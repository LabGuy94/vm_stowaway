#define _DARWIN_C_SOURCE

#include "../include/vm_stowaway.h"
#include "protocol.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <libproc.h>
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
    uint32_t  remote_version;
    uint64_t  remote_pid;
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

static void set_errbuf(char *buf, size_t len, const char *fmt, ...) {
    if (!buf || !len) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, len, fmt, ap);
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

/* $VM_STOWAWAY_PAYLOAD, then next to our image, then one dir up (so a
 * binary in build/examples/ finds the payload in build/), then /usr/local/lib. */
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
    if (rhdr.payload_len > (1ull << 26)) {  /* 64 MiB cap */
        set_err(h, "response too large (%llu)", (unsigned long long)rhdr.payload_len);
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

/* exchange version + pid with the payload. fills h->remote_*. */
static int do_handshake(vm_stowaway_t *h, char *errbuf, size_t errlen) {
    uint8_t *body = NULL;
    size_t body_len = 0;
    if (rpc_or_err(h, VMSW_OP_VERSION, NULL, 0, &body, &body_len) < 0) {
        set_errbuf(errbuf, errlen, "version handshake: %s", h->last_error);
        return -1;
    }
    if (body_len < sizeof(struct vmsw_version_resp)) {
        free(body);
        set_errbuf(errbuf, errlen, "short version response");
        return -1;
    }
    struct vmsw_version_resp r;
    memcpy(&r, body, sizeof(r));
    free(body);
    if (r.version != VMSW_VERSION) {
        set_errbuf(errbuf, errlen, "remote payload speaks v%u, we speak v%u",
                   r.version, VMSW_VERSION);
        return -1;
    }
    h->remote_version = r.version;
    h->remote_pid     = r.pid;
    return 0;
}

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

    /* child env = environ + extra_env (extras append) + our two vars. existing
     * DYLD_INSERT_LIBRARIES / VM_STOWAWAY_SOCK in either source are dropped. */
    size_t env_n = 0, extra_n = 0;
    while (environ[env_n]) env_n++;
    if (opts->extra_env) while (opts->extra_env[extra_n]) extra_n++;
    char **child_env = calloc(env_n + extra_n + 3, sizeof(char *));
    if (!child_env) {
        set_errbuf(errbuf, errlen, "oom");
        return NULL;
    }
    size_t n = 0;
    for (size_t i = 0; i < env_n + extra_n; i++) {
        const char *v = i < env_n ? environ[i] : opts->extra_env[i - env_n];
        if (strncmp(v, "DYLD_INSERT_LIBRARIES=", 22) == 0) continue;
        if (strncmp(v, "VM_STOWAWAY_SOCK=", 17) == 0) continue;
        child_env[n++] = (char *)v;
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
    if (do_handshake(h, errbuf, errlen) < 0) {
        close(cfd); free(h); kill(child, SIGKILL); waitpid(child, NULL, 0);
        return NULL;
    }
    return h;
}

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
    if (do_handshake(h, errbuf, errlen) < 0) {
        close(cfd); free(h);
        return NULL;
    }
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

pid_t vm_stowaway_find_pid(const char *name) {
    if (!name || !*name) return -1;
    int n = proc_listallpids(NULL, 0);
    if (n <= 0) return -1;
    pid_t *pids = calloc((size_t)n, sizeof(pid_t));
    if (!pids) return -1;
    int got = proc_listallpids(pids, n * (int)sizeof(pid_t));
    pid_t self = getpid();
    pid_t found = -1;
    for (int i = 0; i < got / (int)sizeof(pid_t); i++) {
        pid_t p = pids[i];
        if (p == self || p <= 0) continue;
        char buf[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(p, buf, sizeof(buf)) <= 0) continue;
        const char *base = strrchr(buf, '/');
        base = base ? base + 1 : buf;
        if (strcmp(base, name) == 0) { found = p; break; }
    }
    free(pids);
    return found;
}
const char *vm_stowaway_last_error(const vm_stowaway_t *h) {
    return h ? h->last_error : "no handle";
}

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

int vm_stowaway_dyld_info(vm_stowaway_t *h, uint64_t *addr, uint64_t *size,
                          uint32_t *format) {
    uint8_t *body = NULL; size_t body_len = 0;
    if (rpc_or_err(h, VMSW_OP_DYLD_INFO, NULL, 0, &body, &body_len) < 0)
        return -1;
    if (body_len < sizeof(struct vmsw_dyld_info_resp)) {
        free(body); set_err(h, "short dyld_info response"); return -1;
    }
    struct vmsw_dyld_info_resp r;
    memcpy(&r, body, sizeof(r));
    if (addr) *addr = r.all_image_info_addr;
    if (size) *size = r.all_image_info_size;
    if (format) *format = r.all_image_info_format;
    free(body);
    return 0;
}

ssize_t vm_stowaway_threads(vm_stowaway_t *h, uint64_t *tids_out, size_t max) {
    uint8_t *body = NULL; size_t body_len = 0;
    if (rpc_or_err(h, VMSW_OP_THREADS, NULL, 0, &body, &body_len) < 0)
        return -1;
    size_t n = body_len / sizeof(struct vmsw_thread_entry);
    for (size_t i = 0; i < n && i < max; i++) {
        struct vmsw_thread_entry e;
        memcpy(&e, body + i * sizeof(e), sizeof(e));
        tids_out[i] = e.tid;
    }
    free(body);
    return (ssize_t)n;
}

int vm_stowaway_thread_get_state(vm_stowaway_t *h, uint64_t tid, uint32_t flavor,
                                 uint32_t *count, void *state_out,
                                 size_t state_capacity) {
    if (!count) { set_err(h, "null count"); return -1; }
    struct vmsw_thread_state_req req = { .tid = tid, .flavor = flavor, .count = *count };
    uint8_t *body = NULL; size_t body_len = 0;
    if (rpc_or_err(h, VMSW_OP_THREAD_GET_STATE, &req, sizeof(req),
                   &body, &body_len) < 0)
        return -1;
    size_t copy = body_len < state_capacity ? body_len : state_capacity;
    if (state_out) memcpy(state_out, body, copy);
    *count = (uint32_t)(body_len / sizeof(uint32_t));
    free(body);
    return 0;
}

int vm_stowaway_thread_set_state(vm_stowaway_t *h, uint64_t tid, uint32_t flavor,
                                 uint32_t count, const void *state) {
    size_t total = sizeof(struct vmsw_thread_state_set_req) + count * sizeof(uint32_t);
    uint8_t *msg = malloc(total);
    if (!msg) { set_err(h, "oom"); return -1; }
    struct vmsw_thread_state_set_req req = { .tid = tid, .flavor = flavor, .count = count };
    memcpy(msg, &req, sizeof(req));
    if (count && state) memcpy(msg + sizeof(req), state, count * sizeof(uint32_t));
    uint8_t *body = NULL; size_t body_len = 0;
    int rc = rpc_or_err(h, VMSW_OP_THREAD_SET_STATE, msg, total, &body, &body_len);
    free(msg); free(body);
    return rc;
}

uint64_t vm_stowaway_allocate(vm_stowaway_t *h, uint64_t size, int flags) {
    struct vmsw_alloc_req req = { .size = size, .flags = flags };
    uint8_t *body = NULL; size_t body_len = 0;
    if (rpc_or_err(h, VMSW_OP_ALLOCATE, &req, sizeof(req), &body, &body_len) < 0)
        return 0;
    uint64_t addr = 0;
    if (body_len >= sizeof(struct vmsw_alloc_resp)) {
        struct vmsw_alloc_resp r;
        memcpy(&r, body, sizeof(r));
        addr = r.addr;
    }
    free(body);
    return addr;
}

int vm_stowaway_deallocate(vm_stowaway_t *h, uint64_t addr, uint64_t size) {
    struct vmsw_dealloc_req req = { .addr = addr, .size = size };
    uint8_t *body = NULL; size_t body_len = 0;
    int rc = rpc_or_err(h, VMSW_OP_DEALLOCATE, &req, sizeof(req), &body, &body_len);
    free(body);
    return rc;
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

int vm_stowaway_call(vm_stowaway_t *h, uint64_t addr,
                     const uint64_t *args, uint32_t nargs,
                     uint64_t *out_ret) {
    if (nargs > 6) { set_err(h, "too many args"); return -1; }
    struct vmsw_call_req req = { .addr = addr, .nargs = nargs };
    for (uint32_t i = 0; i < nargs; i++) req.args[i] = args[i];

    uint8_t *body = NULL; size_t body_len = 0;
    if (rpc_or_err(h, VMSW_OP_CALL, &req, sizeof(req), &body, &body_len) < 0)
        return -1;
    if (body_len < sizeof(struct vmsw_call_resp)) {
        free(body); set_err(h, "short call response"); return -1;
    }
    struct vmsw_call_resp r;
    memcpy(&r, body, sizeof(r));
    free(body);
    if (out_ret) *out_ret = r.ret;
    return 0;
}

int vm_stowaway_break_set(vm_stowaway_t *h, uint64_t addr, uint32_t *out_bp_id) {
    struct vmsw_break_set_req req = { .addr = addr };
    uint8_t *body = NULL; size_t body_len = 0;
    if (rpc_or_err(h, VMSW_OP_BREAK_SET, &req, sizeof(req), &body, &body_len) < 0)
        return -1;
    if (body_len < sizeof(struct vmsw_break_set_resp)) {
        free(body); set_err(h, "short break_set response"); return -1;
    }
    struct vmsw_break_set_resp r;
    memcpy(&r, body, sizeof(r));
    free(body);
    if (out_bp_id) *out_bp_id = r.bp_id;
    return 0;
}

int vm_stowaway_break_clear(vm_stowaway_t *h, uint32_t bp_id) {
    struct vmsw_break_clear_req req = { .bp_id = bp_id };
    uint8_t *body = NULL; size_t body_len = 0;
    int rc = rpc_or_err(h, VMSW_OP_BREAK_CLEAR, &req, sizeof(req), &body, &body_len);
    free(body);
    return rc;
}

int vm_stowaway_break_wait(vm_stowaway_t *h, int timeout_ms,
                           uint32_t *bp_id, uint64_t *tid, uint64_t *pc) {
    struct vmsw_break_wait_req req = { .timeout_ms = timeout_ms };
    uint8_t *body = NULL; size_t body_len = 0;
    if (rpc_or_err(h, VMSW_OP_BREAK_WAIT, &req, sizeof(req), &body, &body_len) < 0)
        return -1;
    if (body_len < sizeof(struct vmsw_break_wait_resp)) {
        free(body); set_err(h, "short break_wait response"); return -1;
    }
    struct vmsw_break_wait_resp r;
    memcpy(&r, body, sizeof(r));
    free(body);
    if (bp_id) *bp_id = r.bp_id;
    if (tid)   *tid   = r.tid;
    if (pc)    *pc    = r.pc;
    return 0;
}

int vm_stowaway_break_cont(vm_stowaway_t *h, uint64_t tid) {
    struct vmsw_break_cont_req req = { .tid = tid };
    uint8_t *body = NULL; size_t body_len = 0;
    int rc = rpc_or_err(h, VMSW_OP_BREAK_CONT, &req, sizeof(req), &body, &body_len);
    free(body);
    return rc;
}

int vm_stowaway_remote_info(vm_stowaway_t *h, uint32_t *version, uint64_t *pid) {
    if (!h) return -1;
    if (version) *version = h->remote_version;
    if (pid)     *pid     = h->remote_pid;
    return 0;
}
