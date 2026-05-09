/*
 * vm_stowaway payload
 *
 * Loaded into the target process either by DYLD_INSERT_LIBRARIES or by an
 * LC_LOAD_DYLIB injected via vm_stowaway_patch. On init it spawns a worker
 * thread that listens on a Unix domain socket and services memory-access
 * requests from the controller.
 */

#define _DARWIN_C_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "../src/protocol.h"

static int  g_listen_fd = -1;
static char g_sock_path[256];

static void log_msg(const char *fmt, ...) {
    if (!getenv("VM_STOWAWAY_DEBUG")) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[vm_stowaway/payload %d] ", getpid());
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* -- safe IO --------------------------------------------------------------- */

static int read_full(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n == 0) return -1;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n; len -= (size_t)n;
    }
    return 0;
}

/* -- response helpers ------------------------------------------------------ */

static int send_response(int fd, uint32_t status, uint32_t seq,
                         const void *payload, uint64_t payload_len) {
    struct vmsw_hdr h = {
        .magic = VMSW_MAGIC,
        .op_or_status = status,
        .seq = seq,
        .flags = 0,
        .payload_len = payload_len,
    };
    if (write_full(fd, &h, sizeof(h)) < 0) return -1;
    if (payload_len && write_full(fd, payload, payload_len) < 0) return -1;
    return 0;
}

static int send_error(int fd, uint32_t status, uint32_t seq, const char *msg) {
    return send_response(fd, status, seq, msg, msg ? strlen(msg) : 0);
}

/* -- ops ------------------------------------------------------------------- */

static int op_ping(int fd, uint32_t seq) {
    return send_response(fd, VMSW_OK, seq, NULL, 0);
}

static int op_read(int fd, uint32_t seq, const uint8_t *body, uint64_t body_len) {
    if (body_len < sizeof(struct vmsw_read_req))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "short read req");

    struct vmsw_read_req req;
    memcpy(&req, body, sizeof(req));
    if (req.len > (1ull << 30))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "len too large");

    uint8_t *buf = malloc((size_t)req.len);
    if (!buf) return send_error(fd, VMSW_ERR_INTERNAL, seq, "oom");

    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(
        mach_task_self(),
        (mach_vm_address_t)req.addr,
        (mach_vm_size_t)req.len,
        (mach_vm_address_t)buf,
        &got);
    if (kr != KERN_SUCCESS) {
        free(buf);
        return send_error(fd, VMSW_ERR_BAD_ADDR, seq, mach_error_string(kr));
    }

    int rc = send_response(fd, VMSW_OK, seq, buf, got);
    free(buf);
    return rc;
}

static int op_write(int fd, uint32_t seq, const uint8_t *body, uint64_t body_len) {
    if (body_len < sizeof(struct vmsw_write_req))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "short write req");

    struct vmsw_write_req req;
    memcpy(&req, body, sizeof(req));
    if (body_len < sizeof(req) + req.len)
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "truncated write");

    const uint8_t *data = body + sizeof(req);
    mach_vm_address_t addr = (mach_vm_address_t)req.addr;
    mach_vm_size_t len = (mach_vm_size_t)req.len;

    /* Snapshot current protection so we can restore. */
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    mach_vm_address_t region_addr = addr;
    mach_vm_size_t region_size = 0;
    kern_return_t kr = mach_vm_region(mach_task_self(), &region_addr, &region_size,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info, &info_count, &object);
    if (kr != KERN_SUCCESS || region_addr > addr || region_addr + region_size < addr + len) {
        /* Unknown region or write spans regions; let mach_vm_protect try anyway. */
        info.protection = VM_PROT_READ;
    }

    kr = mach_vm_protect(mach_task_self(), addr, len, FALSE,
                         VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS)
        return send_error(fd, VMSW_ERR_BAD_ADDR, seq, mach_error_string(kr));

    memcpy((void *)(uintptr_t)addr, data, (size_t)len);

    /* Restore (best effort). */
    mach_vm_protect(mach_task_self(), addr, len, FALSE, info.protection);

    struct { uint64_t written; } resp = { len };
    return send_response(fd, VMSW_OK, seq, &resp, sizeof(resp));
}

static int op_images(int fd, uint32_t seq) {
    uint32_t n = _dyld_image_count();
    size_t cap = 4096;
    uint8_t *out = malloc(cap);
    size_t used = 0;
    if (!out) return send_error(fd, VMSW_ERR_INTERNAL, seq, "oom");

    for (uint32_t i = 0; i < n; i++) {
        const char *path = _dyld_get_image_name(i);
        const struct mach_header *hdr = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        uint32_t plen = (uint32_t)strlen(path);

        size_t entry = sizeof(struct vmsw_image_entry) + plen;
        if (used + entry > cap) {
            cap = (used + entry) * 2;
            uint8_t *nb = realloc(out, cap);
            if (!nb) { free(out); return send_error(fd, VMSW_ERR_INTERNAL, seq, "oom"); }
            out = nb;
        }
        struct vmsw_image_entry e = {
            .base = (uint64_t)(uintptr_t)hdr,
            .slide = (uint64_t)slide,
            .path_len = plen,
            ._pad = 0,
        };
        memcpy(out + used, &e, sizeof(e));
        memcpy(out + used + sizeof(e), path, plen);
        used += entry;
    }
    int rc = send_response(fd, VMSW_OK, seq, out, used);
    free(out);
    return rc;
}

static int op_regions(int fd, uint32_t seq) {
    size_t cap = 4096, used = 0;
    uint8_t *out = malloc(cap);
    if (!out) return send_error(fd, VMSW_ERR_INTERNAL, seq, "oom");

    mach_vm_address_t addr = 0;
    while (1) {
        mach_vm_size_t size = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        natural_t depth = 0;
        kern_return_t kr = mach_vm_region_recurse(
            mach_task_self(), &addr, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;
        if (info.is_submap) { depth++; continue; }

        if (used + sizeof(struct vmsw_region_entry) > cap) {
            cap *= 2;
            uint8_t *nb = realloc(out, cap);
            if (!nb) { free(out); return send_error(fd, VMSW_ERR_INTERNAL, seq, "oom"); }
            out = nb;
        }
        struct vmsw_region_entry e = {
            .base = addr, .size = size, .prot = info.protection, ._pad = 0,
        };
        memcpy(out + used, &e, sizeof(e));
        used += sizeof(e);

        addr += size;
    }
    int rc = send_response(fd, VMSW_OK, seq, out, used);
    free(out);
    return rc;
}

static int op_resolve(int fd, uint32_t seq, const uint8_t *body, uint64_t body_len) {
    if (body_len < sizeof(struct vmsw_resolve_req))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "short resolve req");

    struct vmsw_resolve_req req;
    memcpy(&req, body, sizeof(req));
    if (body_len < sizeof(req) + req.image_len + req.sym_len)
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "truncated resolve");

    char image[512] = {0}, sym[256] = {0};
    if (req.image_len >= sizeof(image) || req.sym_len >= sizeof(sym))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "name too long");
    memcpy(image, body + sizeof(req), req.image_len);
    memcpy(sym, body + sizeof(req) + req.image_len, req.sym_len);

    void *handle = NULL;
    if (req.image_len == 0) {
        handle = dlopen(NULL, RTLD_LAZY);  /* main executable */
    } else {
        /* find image by substring match against loaded paths */
        uint32_t n = _dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            const char *path = _dyld_get_image_name(i);
            if (strstr(path, image)) {
                handle = dlopen(path, RTLD_LAZY | RTLD_NOLOAD);
                if (handle) break;
            }
        }
    }
    if (!handle)
        return send_error(fd, VMSW_ERR_NOT_FOUND, seq, "image not loaded");

    void *p = dlsym(handle, sym);
    dlclose(handle);
    struct vmsw_resolve_resp resp = { .addr = (uint64_t)(uintptr_t)p };
    if (!p)
        return send_error(fd, VMSW_ERR_NOT_FOUND, seq, "symbol not found");
    return send_response(fd, VMSW_OK, seq, &resp, sizeof(resp));
}

static int pattern_match(const uint8_t *data, const uint8_t *pat,
                         const uint8_t *mask, size_t n) {
    if (!mask) return memcmp(data, pat, n) == 0;
    for (size_t i = 0; i < n; i++)
        if ((data[i] & mask[i]) != (pat[i] & mask[i])) return 0;
    return 1;
}

static int op_scan(int fd, uint32_t seq, const uint8_t *body, uint64_t body_len) {
    if (body_len < sizeof(struct vmsw_scan_req))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "short scan req");

    struct vmsw_scan_req req;
    memcpy(&req, body, sizeof(req));
    if (req.plen == 0 || req.plen > 1024)
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "bad pattern length");
    if (body_len < sizeof(req) + 2 * req.plen)
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "truncated scan");

    const uint8_t *pat = body + sizeof(req);
    const uint8_t *mask = pat + req.plen;
    /* mask all-zero means no mask -> exact match */
    int has_mask = 0;
    for (size_t i = 0; i < req.plen; i++) if (mask[i] != 0xFF) { has_mask = 1; break; }

    uint64_t *hits = malloc(req.max_hits * sizeof(uint64_t));
    if (!hits) return send_error(fd, VMSW_ERR_INTERNAL, seq, "oom");
    size_t nhits = 0;

    mach_vm_address_t addr = req.start;
    while (addr < req.end && nhits < req.max_hits) {
        mach_vm_size_t size = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        natural_t depth = 0;
        kern_return_t kr = mach_vm_region_recurse(
            mach_task_self(), &addr, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;
        if (addr >= req.end) break;
        if (info.is_submap) { depth++; continue; }
        if (!(info.protection & VM_PROT_READ)) { addr += size; continue; }

        mach_vm_address_t scan_start = addr;
        mach_vm_size_t scan_size = size;
        if (scan_start + scan_size > req.end) scan_size = req.end - scan_start;

        uint8_t *buf = malloc((size_t)scan_size);
        if (!buf) break;
        mach_vm_size_t got = 0;
        kr = mach_vm_read_overwrite(mach_task_self(), scan_start, scan_size,
                                    (mach_vm_address_t)buf, &got);
        if (kr == KERN_SUCCESS && got >= req.plen) {
            for (size_t i = 0; i + req.plen <= got && nhits < req.max_hits; i++) {
                if (pattern_match(buf + i, pat, has_mask ? mask : NULL, req.plen))
                    hits[nhits++] = scan_start + i;
            }
        }
        free(buf);
        addr += size;
    }

    int rc = send_response(fd, VMSW_OK, seq, hits, nhits * sizeof(uint64_t));
    free(hits);
    return rc;
}

/* -- session loop ---------------------------------------------------------- */

static int serve_one(int cfd) {
    while (1) {
        struct vmsw_hdr h;
        if (read_full(cfd, &h, sizeof(h)) < 0) return 0;
        if (h.magic != VMSW_MAGIC) {
            send_error(cfd, VMSW_ERR_BAD_REQUEST, h.seq, "bad magic");
            return -1;
        }
        if (h.payload_len > (1ull << 31)) {
            send_error(cfd, VMSW_ERR_BAD_REQUEST, h.seq, "payload too large");
            return -1;
        }
        uint8_t *body = NULL;
        if (h.payload_len) {
            body = malloc((size_t)h.payload_len);
            if (!body) { send_error(cfd, VMSW_ERR_INTERNAL, h.seq, "oom"); return -1; }
            if (read_full(cfd, body, (size_t)h.payload_len) < 0) { free(body); return -1; }
        }

        int rc = 0;
        switch (h.op_or_status) {
        case VMSW_OP_PING:    rc = op_ping(cfd, h.seq); break;
        case VMSW_OP_READ:    rc = op_read(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_WRITE:   rc = op_write(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_RESOLVE: rc = op_resolve(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_IMAGES:  rc = op_images(cfd, h.seq); break;
        case VMSW_OP_REGIONS: rc = op_regions(cfd, h.seq); break;
        case VMSW_OP_SCAN:    rc = op_scan(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_QUIT:    free(body); return 1;
        default:
            rc = send_error(cfd, VMSW_ERR_BAD_OP, h.seq, "unknown op");
        }
        free(body);
        if (rc < 0) return -1;
    }
}

static void *server_thread(void *unused) {
    (void)unused;
    while (1) {
        int cfd = accept(g_listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            log_msg("accept failed: %s", strerror(errno));
            return NULL;
        }
        log_msg("client connected");
        int r = serve_one(cfd);
        close(cfd);
        if (r > 0) {
            log_msg("quit requested");
            break;
        }
    }
    close(g_listen_fd);
    unlink(g_sock_path);
    return NULL;
}

/* -- init ------------------------------------------------------------------ */

__attribute__((constructor))
static void vm_stowaway_init(void) {
    const char *sock = getenv("VM_STOWAWAY_SOCK");
    if (sock && *sock) {
        snprintf(g_sock_path, sizeof(g_sock_path), "%s", sock);
    } else {
        snprintf(g_sock_path, sizeof(g_sock_path),
                 "/tmp/vm_stowaway.%d.sock", getpid());
    }
    log_msg("listening on %s", g_sock_path);

    /* Unlink any stale socket from a previous run with the same pid. */
    unlink(g_sock_path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { log_msg("socket: %s", strerror(errno)); return; }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_sock_path, sizeof(addr.sun_path) - 1);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_msg("bind: %s", strerror(errno));
        close(fd);
        return;
    }
    /* Owner-only so other local users can't connect. */
    chmod(g_sock_path, 0600);
    if (listen(fd, 1) < 0) {
        log_msg("listen: %s", strerror(errno));
        close(fd);
        return;
    }
    g_listen_fd = fd;

    pthread_t tid;
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &a, server_thread, NULL);
    pthread_attr_destroy(&a);
}
