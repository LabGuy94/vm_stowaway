/*
 * vm_stowaway controller
 *
 * Spawn or attach to a target that hosts the payload, then talk to it
 * over a Unix domain socket using the protocol in protocol.h.
 */

#define _DARWIN_C_SOURCE

#include "../include/vm_stowaway.h"
#include "protocol.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

struct vm_stowaway {
    int       sock_fd;
    pid_t     pid;
    uint32_t  next_seq;
    char      sock_path[256];
    char      last_error[256];
};

static void set_err(vm_stowaway_t *h, const char *fmt, ...) {
    if (!h) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(h->last_error, sizeof(h->last_error), fmt, ap);
    va_end(ap);
}

static void set_errbuf(char *errbuf, size_t errlen, const char *fmt, ...) {
    if (!errbuf || !errlen) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errbuf, errlen, fmt, ap);
    va_end(ap);
}

static int read_full(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n == 0) return -1;
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

/* -- payload path resolution ---------------------------------------------- */

/* Locate libvm_stowaway_payload.dylib.
 *   1. $VM_STOWAWAY_PAYLOAD if set
 *   2. next to our own image
 *   3. one directory up from our own image (so a binary in build/examples/
 *      finds the payload in build/)
 *   4. /usr/local/lib
 */
static int default_payload_path(char *out, size_t outlen) {
    const char *env = getenv("VM_STOWAWAY_PAYLOAD");
    if (env && *env && access(env, R_OK) == 0) {
        snprintf(out, outlen, "%s", env);
        return 0;
    }
    Dl_info info;
    if (dladdr((void *)default_payload_path, &info) && info.dli_fname) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s", info.dli_fname);
        char *dir = dirname(buf);
        if (dir) {
            snprintf(out, outlen, "%s/libvm_stowaway_payload.dylib", dir);
            if (access(out, R_OK) == 0) return 0;
            snprintf(out, outlen, "%s/../libvm_stowaway_payload.dylib", dir);
            if (access(out, R_OK) == 0) return 0;
        }
    }
    snprintf(out, outlen, "/usr/local/lib/libvm_stowaway_payload.dylib");
    if (access(out, R_OK) == 0) return 0;
    return -1;
}

/* -- socket helpers ------------------------------------------------------- */

static int unique_sock_path(char *out, size_t outlen) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    /* sun_path is 104 bytes on macOS; keep it short. */
    snprintf(out, outlen, "/tmp/vmsw.%d.%lx.sock",
             getpid(), (unsigned long)ts.tv_nsec);
    return 0;
}

static int connect_with_retry(const char *path, int timeout_s) {
    if (timeout_s <= 0) timeout_s = 10;
    struct timespec deadline, now;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout_s;

    while (1) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        struct sockaddr_un addr = {0};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
            return fd;
        close(fd);

        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
            errno = ETIMEDOUT;
            return -1;
        }
        struct timespec sl = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000 };
        nanosleep(&sl, NULL);
    }
}

/* -- request/response RPC ------------------------------------------------- */

static int rpc(vm_stowaway_t *h, uint32_t op,
               const void *body, size_t body_len,
               uint32_t *out_status, uint8_t **out_body, size_t *out_body_len) {
    if (!h || h->sock_fd < 0) return -1;
    uint32_t seq = ++h->next_seq;

    struct vmsw_hdr hdr = {
        .magic = VMSW_MAGIC,
        .op_or_status = op,
        .seq = seq,
        .flags = 0,
        .payload_len = body_len,
    };
    if (write_full(h->sock_fd, &hdr, sizeof(hdr)) < 0) {
        set_err(h, "send hdr: %s", strerror(errno));
        return -1;
    }
    if (body_len && write_full(h->sock_fd, body, body_len) < 0) {
        set_err(h, "send body: %s", strerror(errno));
        return -1;
    }

    struct vmsw_hdr rhdr;
    if (read_full(h->sock_fd, &rhdr, sizeof(rhdr)) < 0) {
        set_err(h, "recv hdr: %s", strerror(errno));
        return -1;
    }
    if (rhdr.magic != VMSW_MAGIC) {
        set_err(h, "bad response magic");
        return -1;
    }
    if (rhdr.payload_len > (1ull << 31)) {
        set_err(h, "response too large");
        return -1;
    }
    uint8_t *buf = NULL;
    if (rhdr.payload_len) {
        buf = malloc((size_t)rhdr.payload_len);
        if (!buf) { set_err(h, "oom"); return -1; }
        if (read_full(h->sock_fd, buf, (size_t)rhdr.payload_len) < 0) {
            free(buf);
            set_err(h, "recv body: %s", strerror(errno));
            return -1;
        }
    }
    *out_status = rhdr.op_or_status;
    *out_body = buf;
    *out_body_len = (size_t)rhdr.payload_len;
    return 0;
}

static int rpc_or_err(vm_stowaway_t *h, uint32_t op,
                      const void *body, size_t body_len,
                      uint8_t **out_body, size_t *out_body_len) {
    uint32_t status = 0;
    if (rpc(h, op, body, body_len, &status, out_body, out_body_len) < 0)
        return -1;
    if (status != VMSW_OK) {
        if (*out_body && *out_body_len)
            set_err(h, "remote: %.*s", (int)*out_body_len, (char *)*out_body);
        else
            set_err(h, "remote status %u", status);
        free(*out_body);
        *out_body = NULL;
        *out_body_len = 0;
        return -1;
    }
    return 0;
}

/* -- launch --------------------------------------------------------------- */

vm_stowaway_t *vm_stowaway_launch(const char *path, char *const argv[],
                                  const vm_stowaway_launch_opts_t *opts,
                                  char *errbuf, size_t errlen) {
    vm_stowaway_launch_opts_t defaults = {0};
    if (!opts) opts = &defaults;

    char payload_path[1024] = {0};
    if (opts->payload_path) {
        snprintf(payload_path, sizeof(payload_path), "%s", opts->payload_path);
    } else if (default_payload_path(payload_path, sizeof(payload_path)) < 0) {
        set_errbuf(errbuf, errlen,
                   "payload dylib not found next to controller; pass opts->payload_path");
        return NULL;
    }

    char sock_path[256];
    if (opts->socket_path)
        snprintf(sock_path, sizeof(sock_path), "%s", opts->socket_path);
    else
        unique_sock_path(sock_path, sizeof(sock_path));

    /* Build env: copy environ + inherit-from-opts + our two vars. */
    size_t base_n = 0;
    if (opts->extra_env) {
        while (opts->extra_env[base_n]) base_n++;
    } else {
        while (environ[base_n]) base_n++;
    }
    char **child_env = calloc(base_n + 3, sizeof(char *));
    if (!child_env) {
        set_errbuf(errbuf, errlen, "oom");
        return NULL;
    }
    char *const *src = opts->extra_env ? opts->extra_env : environ;
    size_t n = 0;
    for (size_t i = 0; i < base_n; i++) {
        if (strncmp(src[i], "DYLD_INSERT_LIBRARIES=", 22) == 0) continue;
        if (strncmp(src[i], "VM_STOWAWAY_SOCK=", 17) == 0) continue;
        child_env[n++] = src[i];
    }
    char dyld_var[1100], sock_var[300];
    snprintf(dyld_var, sizeof(dyld_var), "DYLD_INSERT_LIBRARIES=%s", payload_path);
    snprintf(sock_var, sizeof(sock_var), "VM_STOWAWAY_SOCK=%s", sock_path);
    child_env[n++] = dyld_var;
    child_env[n++] = sock_var;
    child_env[n] = NULL;

    pid_t child = 0;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    int rc = posix_spawn(&child, path, NULL, &attr, argv, child_env);
    posix_spawnattr_destroy(&attr);
    free(child_env);
    if (rc != 0) {
        set_errbuf(errbuf, errlen, "posix_spawn(%s): %s", path, strerror(rc));
        return NULL;
    }

    int cfd = connect_with_retry(sock_path, opts->connect_timeout_s);
    if (cfd < 0) {
        set_errbuf(errbuf, errlen,
                   "payload did not connect within timeout (check that the target is not "
                   "hardened-runtime / library-validated)");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return NULL;
    }

    vm_stowaway_t *h = calloc(1, sizeof(*h));
    if (!h) { close(cfd); set_errbuf(errbuf, errlen, "oom"); return NULL; }
    h->sock_fd = cfd;
    h->pid = child;
    snprintf(h->sock_path, sizeof(h->sock_path), "%s", sock_path);
    return h;
}

/* -- attach --------------------------------------------------------------- */

vm_stowaway_t *vm_stowaway_attach(pid_t pid, const char *socket_path,
                                  int connect_timeout_s,
                                  char *errbuf, size_t errlen) {
    char sock[256];
    if (socket_path)
        snprintf(sock, sizeof(sock), "%s", socket_path);
    else
        snprintf(sock, sizeof(sock), "/tmp/vm_stowaway.%d.sock", pid);

    int cfd = connect_with_retry(sock, connect_timeout_s);
    if (cfd < 0) {
        set_errbuf(errbuf, errlen, "connect %s: %s", sock, strerror(errno));
        return NULL;
    }
    vm_stowaway_t *h = calloc(1, sizeof(*h));
    if (!h) { close(cfd); set_errbuf(errbuf, errlen, "oom"); return NULL; }
    h->sock_fd = cfd;
    h->pid = pid;
    snprintf(h->sock_path, sizeof(h->sock_path), "%s", sock);
    return h;
}

void vm_stowaway_close(vm_stowaway_t *h) {
    if (!h) return;
    /* Just disconnect; do not send OP_QUIT (that's reserved for explicit
     * shutdown of the payload server). The payload's accept loop will
     * happily take the next client. */
    if (h->sock_fd >= 0) close(h->sock_fd);
    free(h);
}

pid_t vm_stowaway_pid(const vm_stowaway_t *h) { return h ? h->pid : -1; }
const char *vm_stowaway_last_error(const vm_stowaway_t *h) {
    return h ? h->last_error : "no handle";
}

/* -- memory ops ----------------------------------------------------------- */

ssize_t vm_stowaway_read(vm_stowaway_t *h, uint64_t addr, void *buf, size_t len) {
    struct vmsw_read_req req = { .addr = addr, .len = len };
    uint8_t *body = NULL; size_t body_len = 0;
    if (rpc_or_err(h, VMSW_OP_READ, &req, sizeof(req), &body, &body_len) < 0)
        return -1;
    size_t copy = body_len < len ? body_len : len;
    memcpy(buf, body, copy);
    free(body);
    return (ssize_t)copy;
}

ssize_t vm_stowaway_write(vm_stowaway_t *h, uint64_t addr, const void *buf, size_t len) {
    size_t total = sizeof(struct vmsw_write_req) + len;
    uint8_t *msg = malloc(total);
    if (!msg) { set_err(h, "oom"); return -1; }
    struct vmsw_write_req req = { .addr = addr, .len = len };
    memcpy(msg, &req, sizeof(req));
    memcpy(msg + sizeof(req), buf, len);

    uint8_t *body = NULL; size_t body_len = 0;
    int rc = rpc_or_err(h, VMSW_OP_WRITE, msg, total, &body, &body_len);
    free(msg);
    if (rc < 0) return -1;
    ssize_t written = (ssize_t)len;
    if (body_len >= sizeof(uint64_t)) {
        uint64_t w;
        memcpy(&w, body, sizeof(w));
        written = (ssize_t)w;
    }
    free(body);
    return written;
}

uint64_t vm_stowaway_resolve(vm_stowaway_t *h, const char *image, const char *symbol) {
    if (!symbol) { set_err(h, "null symbol"); return 0; }
    uint32_t ilen = image ? (uint32_t)strlen(image) : 0;
    uint32_t slen = (uint32_t)strlen(symbol);
    size_t total = sizeof(struct vmsw_resolve_req) + ilen + slen;
    uint8_t *msg = malloc(total);
    if (!msg) { set_err(h, "oom"); return 0; }
    struct vmsw_resolve_req req = { .image_len = ilen, .sym_len = slen };
    memcpy(msg, &req, sizeof(req));
    if (ilen) memcpy(msg + sizeof(req), image, ilen);
    memcpy(msg + sizeof(req) + ilen, symbol, slen);

    uint8_t *body = NULL; size_t body_len = 0;
    int rc = rpc_or_err(h, VMSW_OP_RESOLVE, msg, total, &body, &body_len);
    free(msg);
    if (rc < 0) return 0;
    uint64_t addr = 0;
    if (body_len >= sizeof(struct vmsw_resolve_resp)) {
        struct vmsw_resolve_resp r;
        memcpy(&r, body, sizeof(r));
        addr = r.addr;
    }
    free(body);
    return addr;
}

ssize_t vm_stowaway_images(vm_stowaway_t *h, vm_stowaway_image_t *out, size_t max) {
    uint8_t *body = NULL; size_t body_len = 0;
    if (rpc_or_err(h, VMSW_OP_IMAGES, NULL, 0, &body, &body_len) < 0) return -1;

    size_t off = 0, total = 0;
    while (off + sizeof(struct vmsw_image_entry) <= body_len) {
        struct vmsw_image_entry e;
        memcpy(&e, body + off, sizeof(e));
        off += sizeof(e);
        if (off + e.path_len > body_len) break;
        if (total < max) {
            out[total].base = e.base;
            out[total].slide = e.slide;
            size_t copy = e.path_len < sizeof(out[total].path) - 1
                          ? e.path_len : sizeof(out[total].path) - 1;
            memcpy(out[total].path, body + off, copy);
            out[total].path[copy] = 0;
        }
        off += e.path_len;
        total++;
    }
    free(body);
    return (ssize_t)total;
}

ssize_t vm_stowaway_regions(vm_stowaway_t *h, vm_stowaway_region_t *out, size_t max) {
    uint8_t *body = NULL; size_t body_len = 0;
    if (rpc_or_err(h, VMSW_OP_REGIONS, NULL, 0, &body, &body_len) < 0) return -1;

    size_t n = body_len / sizeof(struct vmsw_region_entry);
    for (size_t i = 0; i < n && i < max; i++) {
        struct vmsw_region_entry e;
        memcpy(&e, body + i * sizeof(e), sizeof(e));
        out[i].base = e.base;
        out[i].size = e.size;
        out[i].prot = e.prot;
    }
    free(body);
    return (ssize_t)n;
}

ssize_t vm_stowaway_scan(vm_stowaway_t *h,
                         uint64_t start, uint64_t end,
                         const uint8_t *pattern, const uint8_t *mask,
                         size_t pat_len,
                         uint64_t *out, size_t max_hits) {
    if (!pattern || pat_len == 0) { set_err(h, "bad pattern"); return -1; }
    size_t total = sizeof(struct vmsw_scan_req) + 2 * pat_len;
    uint8_t *msg = malloc(total);
    if (!msg) { set_err(h, "oom"); return -1; }
    struct vmsw_scan_req req = {
        .start = start, .end = end,
        .plen = pat_len, .max_hits = max_hits,
    };
    memcpy(msg, &req, sizeof(req));
    memcpy(msg + sizeof(req), pattern, pat_len);
    if (mask) memcpy(msg + sizeof(req) + pat_len, mask, pat_len);
    else memset(msg + sizeof(req) + pat_len, 0xFF, pat_len);

    uint8_t *body = NULL; size_t body_len = 0;
    int rc = rpc_or_err(h, VMSW_OP_SCAN, msg, total, &body, &body_len);
    free(msg);
    if (rc < 0) return -1;

    size_t n = body_len / sizeof(uint64_t);
    for (size_t i = 0; i < n && i < max_hits; i++)
        memcpy(&out[i], body + i * sizeof(uint64_t), sizeof(uint64_t));
    free(body);
    return (ssize_t)n;
}
