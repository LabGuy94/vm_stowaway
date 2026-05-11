/* runs inside the target. listens on a unix socket and services memory ops. */

#define _DARWIN_C_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/exc.h>             /* MIG client: exception_raise (32-bit codes) */
#include <mach/exception_types.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/task_info.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/vm_region.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <sys/un.h>
#include <unistd.h>

#include "../src/protocol.h"

static int  g_listen_fd = -1;
static int  g_debug = 0;
static char g_sock_path[256];

static void log_msg(const char *fmt, ...) {
    if (!g_debug) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[vm_stowaway/payload %d] ", getpid());
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

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
        if (info.is_submap) { addr += size; continue; }

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
    if (req.max_hits == 0 || req.max_hits > (1u << 20))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "bad max_hits");
    if (body_len < sizeof(req) + 2 * req.plen)
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "truncated scan");

    const uint8_t *pat = body + sizeof(req);
    const uint8_t *mask = pat + req.plen;
    /* mask byte: 0xFF = match this byte, 0x00 = wildcard. all-0xFF -> skip the
     * masking branch in the inner loop. */
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
        if (info.is_submap) { addr += size; continue; }
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

static int op_dyld_info(int fd, uint32_t seq) {
    struct task_dyld_info info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(mach_task_self(), TASK_DYLD_INFO,
                                 (task_info_t)&info, &count);
    if (kr != KERN_SUCCESS)
        return send_error(fd, VMSW_ERR_INTERNAL, seq, mach_error_string(kr));
    struct vmsw_dyld_info_resp r = {
        .all_image_info_addr = info.all_image_info_addr,
        .all_image_info_size = info.all_image_info_size,
        .all_image_info_format = (uint32_t)info.all_image_info_format,
        ._pad = 0,
    };
    return send_response(fd, VMSW_OK, seq, &r, sizeof(r));
}

static int op_threads(int fd, uint32_t seq) {
    thread_act_array_t threads;
    mach_msg_type_number_t n = 0;
    kern_return_t kr = task_threads(mach_task_self(), &threads, &n);
    if (kr != KERN_SUCCESS)
        return send_error(fd, VMSW_ERR_INTERNAL, seq, mach_error_string(kr));

    struct vmsw_thread_entry *entries = calloc(n, sizeof(*entries));
    if (!entries) {
        for (uint32_t i = 0; i < n; i++)
            mach_port_deallocate(mach_task_self(), threads[i]);
        vm_deallocate(mach_task_self(), (vm_address_t)threads,
                      n * sizeof(thread_act_t));
        return send_error(fd, VMSW_ERR_INTERNAL, seq, "oom");
    }
    for (uint32_t i = 0; i < n; i++) {
        thread_identifier_info_data_t ti;
        mach_msg_type_number_t tc = THREAD_IDENTIFIER_INFO_COUNT;
        if (thread_info(threads[i], THREAD_IDENTIFIER_INFO,
                        (thread_info_t)&ti, &tc) == KERN_SUCCESS)
            entries[i].tid = ti.thread_id;
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                  n * sizeof(thread_act_t));

    int rc = send_response(fd, VMSW_OK, seq, entries, n * sizeof(*entries));
    free(entries);
    return rc;
}

/* Find the thread by BSD thread id. Returns a send right that the caller
 * must mach_port_deallocate. Returns 0 if not found. */
static thread_act_t thread_by_tid(uint64_t tid) {
    thread_act_array_t threads;
    mach_msg_type_number_t n = 0;
    if (task_threads(mach_task_self(), &threads, &n) != KERN_SUCCESS) return 0;
    thread_act_t found = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (!found) {
            thread_identifier_info_data_t ti;
            mach_msg_type_number_t tc = THREAD_IDENTIFIER_INFO_COUNT;
            if (thread_info(threads[i], THREAD_IDENTIFIER_INFO,
                            (thread_info_t)&ti, &tc) == KERN_SUCCESS &&
                ti.thread_id == tid) {
                found = threads[i];
                continue;
            }
        }
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                  n * sizeof(thread_act_t));
    return found;
}

static int op_thread_get_state(int fd, uint32_t seq,
                               const uint8_t *body, uint64_t body_len) {
    if (body_len < sizeof(struct vmsw_thread_state_req))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "short");
    struct vmsw_thread_state_req req;
    memcpy(&req, body, sizeof(req));
    if (req.count == 0 || req.count > 1024)
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "bad count");

    thread_act_t th = thread_by_tid(req.tid);
    if (!th)
        return send_error(fd, VMSW_ERR_NOT_FOUND, seq, "thread not found");

    natural_t *state = calloc(req.count, sizeof(natural_t));
    if (!state) {
        mach_port_deallocate(mach_task_self(), th);
        return send_error(fd, VMSW_ERR_INTERNAL, seq, "oom");
    }
    mach_msg_type_number_t cnt = req.count;
    kern_return_t kr = thread_get_state(th, req.flavor, state, &cnt);
    mach_port_deallocate(mach_task_self(), th);
    if (kr != KERN_SUCCESS) {
        free(state);
        return send_error(fd, VMSW_ERR_INTERNAL, seq, mach_error_string(kr));
    }
    int rc = send_response(fd, VMSW_OK, seq, state, cnt * sizeof(natural_t));
    free(state);
    return rc;
}

static int op_thread_set_state(int fd, uint32_t seq,
                               const uint8_t *body, uint64_t body_len) {
    if (body_len < sizeof(struct vmsw_thread_state_set_req))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "short");
    struct vmsw_thread_state_set_req req;
    memcpy(&req, body, sizeof(req));
    if (body_len < sizeof(req) + req.count * sizeof(natural_t))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "truncated");

    thread_act_t th = thread_by_tid(req.tid);
    if (!th)
        return send_error(fd, VMSW_ERR_NOT_FOUND, seq, "thread not found");

    kern_return_t kr = thread_set_state(th, req.flavor,
                                        (thread_state_t)(body + sizeof(req)),
                                        req.count);
    mach_port_deallocate(mach_task_self(), th);
    if (kr != KERN_SUCCESS)
        return send_error(fd, VMSW_ERR_INTERNAL, seq, mach_error_string(kr));
    return send_response(fd, VMSW_OK, seq, NULL, 0);
}

static int op_allocate(int fd, uint32_t seq,
                       const uint8_t *body, uint64_t body_len) {
    if (body_len < sizeof(struct vmsw_alloc_req))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "short");
    struct vmsw_alloc_req req;
    memcpy(&req, body, sizeof(req));
    mach_vm_address_t addr = 0;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &addr,
                                        (mach_vm_size_t)req.size, req.flags);
    if (kr != KERN_SUCCESS)
        return send_error(fd, VMSW_ERR_INTERNAL, seq, mach_error_string(kr));
    struct vmsw_alloc_resp r = { .addr = addr };
    return send_response(fd, VMSW_OK, seq, &r, sizeof(r));
}

static int op_deallocate(int fd, uint32_t seq,
                         const uint8_t *body, uint64_t body_len) {
    if (body_len < sizeof(struct vmsw_dealloc_req))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "short");
    struct vmsw_dealloc_req req;
    memcpy(&req, body, sizeof(req));
    kern_return_t kr = mach_vm_deallocate(mach_task_self(),
                                          (mach_vm_address_t)req.addr,
                                          (mach_vm_size_t)req.size);
    if (kr != KERN_SUCCESS)
        return send_error(fd, VMSW_ERR_INTERNAL, seq, mach_error_string(kr));
    return send_response(fd, VMSW_OK, seq, NULL, 0);
}

static int op_version(int fd, uint32_t seq) {
    struct vmsw_version_resp r = {
        .version = VMSW_VERSION,
        .caps = 0,
        .pid = (uint64_t)getpid(),
    };
    return send_response(fd, VMSW_OK, seq, &r, sizeof(r));
}

/* Call addr(args...). Up to 6 u64 args, returns u64. Casts to a 6-arg sig and
 * relies on the macOS ABI passing the first 6/8 ints in registers, so calling
 * with fewer real params still works as long as the callee ignores extras. */
typedef uint64_t (*fn6_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

struct call_ctx {
    uint64_t addr;
    uint64_t args[VMSW_CALL_MAX_ARGS];
    uint32_t nargs;
    uint64_t ret;
};

static void *call_thread(void *arg) {
    struct call_ctx *c = arg;
    fn6_t f = (fn6_t)(uintptr_t)c->addr;
    uint64_t a[VMSW_CALL_MAX_ARGS] = {0};
    for (uint32_t i = 0; i < c->nargs && i < VMSW_CALL_MAX_ARGS; i++) a[i] = c->args[i];
    c->ret = f(a[0], a[1], a[2], a[3], a[4], a[5]);
    return NULL;
}

static int op_call(int fd, uint32_t seq, const uint8_t *body, uint64_t body_len) {
    if (body_len < sizeof(struct vmsw_call_req))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "short call req");
    struct vmsw_call_req req;
    memcpy(&req, body, sizeof(req));
    if (req.nargs > VMSW_CALL_MAX_ARGS)
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "too many args");

    struct call_ctx ctx = { .addr = req.addr, .nargs = req.nargs };
    memcpy(ctx.args, req.args, sizeof(ctx.args));

    pthread_t t;
    if (pthread_create(&t, NULL, call_thread, &ctx) != 0)
        return send_error(fd, VMSW_ERR_INTERNAL, seq, "pthread_create");
    pthread_join(t, NULL);

    struct vmsw_call_resp r = { .ret = ctx.ret };
    return send_response(fd, VMSW_OK, seq, &r, sizeof(r));
}

/* breakpoints. */

#if defined(__arm64__)
static const uint8_t BREAK_INSN[] = { 0x00, 0x00, 0x20, 0xd4 };  /* brk #0 */
#  define BREAK_INSN_LEN 4
#  define BREAK_EXC_TYPE EXC_BREAKPOINT
#elif defined(__x86_64__)
static const uint8_t BREAK_INSN[] = { 0xcc };  /* int3 */
#  define BREAK_INSN_LEN 1
#  define BREAK_EXC_TYPE EXC_BREAKPOINT
#else
#  error unsupported arch
#endif

#define MAX_BREAKPOINTS 64

struct bp {
    int       used;
    uint32_t  id;
    uint64_t  addr;
    uint8_t   orig[8];
    uint64_t  suspended_tid;   /* nonzero while a thread is suspended at this bp */
    thread_act_t suspended_th; /* mach port of suspended thread (send right) */
};

static struct bp        g_bps[MAX_BREAKPOINTS];
static uint32_t         g_next_bp_id = 1;
static pthread_mutex_t  g_bp_mu = PTHREAD_MUTEX_INITIALIZER;

/* hits queue: filled by exception handler, drained by op_break_wait. */
struct bp_hit { uint32_t bp_id; uint64_t tid; uint64_t pc; thread_act_t th; };
#define HIT_QUEUE_CAP 64
static struct bp_hit    g_hits[HIT_QUEUE_CAP];
static size_t           g_hits_head = 0, g_hits_tail = 0;
static pthread_mutex_t  g_hits_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t   g_hits_cv = PTHREAD_COND_INITIALIZER;

static mach_port_t g_exc_port = MACH_PORT_NULL;
static int         g_exc_inited = 0;

/* prior task-level BREAKPOINT handler we displaced; forward misses to it. */
static struct {
    exception_mask_t       masks[EXC_TYPES_COUNT];
    mach_port_t            ports[EXC_TYPES_COUNT];
    exception_behavior_t   behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t  flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count;
} g_prior_exc;

/* range of our own image, so we can refuse to set a bp inside it. */
static uintptr_t g_self_lo, g_self_hi;

static int write_bytes(uint64_t addr, const void *data, size_t len) {
    kern_return_t kr = mach_vm_protect(mach_task_self(), addr, len, FALSE,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) return -1;
    memcpy((void *)(uintptr_t)addr, data, len);
    mach_vm_protect(mach_task_self(), addr, len, FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    return 0;
}

/* find the prior handler covering `exc`. Returns MACH_PORT_NULL if none. */
static mach_port_t prior_handler_for(exception_type_t exc) {
    for (mach_msg_type_number_t i = 0; i < g_prior_exc.count; i++)
        if (g_prior_exc.masks[i] & (1 << exc)) return g_prior_exc.ports[i];
    return MACH_PORT_NULL;
}

static void reply_kr(mach_msg_header_t *req, kern_return_t kr) {
    struct {
        mach_msg_header_t Head;
        NDR_record_t      NDR;
        kern_return_t     RetCode;
    } rep = {0};
    rep.Head.msgh_bits        = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->msgh_bits), 0);
    rep.Head.msgh_remote_port = req->msgh_remote_port;
    rep.Head.msgh_local_port  = MACH_PORT_NULL;
    rep.Head.msgh_id          = req->msgh_id + 100;
    rep.Head.msgh_size        = sizeof(rep);
    rep.NDR                   = NDR_record;
    rep.RetCode               = kr;
    mach_msg(&rep.Head, MACH_SEND_MSG, sizeof(rep), 0,
             MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

static void *exc_thread(void *unused) {
    (void)unused;
    for (;;) {
        struct {
            mach_msg_header_t Head;
            mach_msg_body_t   msgh_body;
            mach_msg_port_descriptor_t thread;
            mach_msg_port_descriptor_t task;
            NDR_record_t      NDR;
            exception_type_t  exception;
            mach_msg_type_number_t codeCnt;
            int32_t           code[2];
            char              trailer[64];
        } req;
        memset(&req, 0, sizeof(req));
        mach_msg_return_t mr = mach_msg(&req.Head, MACH_RCV_MSG, 0, sizeof(req),
                                        g_exc_port, MACH_MSG_TIMEOUT_NONE,
                                        MACH_PORT_NULL);
        if (mr != MACH_MSG_SUCCESS) {
            log_msg("exc mach_msg: 0x%x", mr);
            continue;
        }

        thread_act_t th = req.thread.name;
        task_t       tk = req.task.name;
        exception_type_t exc = req.exception;
        (void)tk;

        /* find pc + check if we own the breakpoint at that pc. */
        uint32_t bp_id = 0;
        uint64_t pc = 0, tid = 0;
        if (exc == BREAK_EXC_TYPE) {
#if defined(__arm64__)
            arm_thread_state64_t s;
            mach_msg_type_number_t n = ARM_THREAD_STATE64_COUNT;
            if (thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&s, &n) == KERN_SUCCESS)
                pc = __darwin_arm_thread_state64_get_pc(s);
#elif defined(__x86_64__)
            x86_thread_state64_t s;
            mach_msg_type_number_t n = x86_THREAD_STATE64_COUNT;
            if (thread_get_state(th, x86_THREAD_STATE64, (thread_state_t)&s, &n) == KERN_SUCCESS)
                pc = s.__rip - 1;
#endif
            thread_identifier_info_data_t ti;
            mach_msg_type_number_t tc = THREAD_IDENTIFIER_INFO_COUNT;
            if (thread_info(th, THREAD_IDENTIFIER_INFO, (thread_info_t)&ti, &tc) == KERN_SUCCESS)
                tid = ti.thread_id;

            pthread_mutex_lock(&g_bp_mu);
            for (size_t i = 0; i < MAX_BREAKPOINTS; i++) {
                if (g_bps[i].used && g_bps[i].addr == pc) { bp_id = g_bps[i].id; break; }
            }
            pthread_mutex_unlock(&g_bp_mu);
        }

        /* Not ours: forward to whoever had this exception class before us
         * (crash reporter, sentry, etc), or fail loud so the kernel falls
         * through to the host port. */
        if (bp_id == 0) {
            mach_port_t prior = prior_handler_for(exc);
            if (prior != MACH_PORT_NULL) {
                exception_data_type_t codes[2] = { req.code[0], req.code[1] };
                kern_return_t fkr = exception_raise(
                    prior, th, tk, exc, codes, req.codeCnt);
                reply_kr(&req.Head, fkr);
            } else {
                reply_kr(&req.Head, KERN_FAILURE);
            }
            mach_port_deallocate(mach_task_self(), th);
            mach_port_deallocate(mach_task_self(), tk);
            continue;
        }

        /* Ours: suspend and queue. */
        thread_suspend(th);
        int queued = 0;
        pthread_mutex_lock(&g_hits_mu);
        if (g_hits_tail - g_hits_head < HIT_QUEUE_CAP) {
            g_hits[g_hits_tail++ % HIT_QUEUE_CAP] = (struct bp_hit){ bp_id, tid, pc, th };
            pthread_cond_signal(&g_hits_cv);
            queued = 1;
        }
        pthread_mutex_unlock(&g_hits_mu);
        if (!queued) {
            thread_resume(th);
            mach_port_deallocate(mach_task_self(), th);
        }
        mach_port_deallocate(mach_task_self(), tk);
        reply_kr(&req.Head, KERN_SUCCESS);
    }
    return NULL;
}

/* Approximate the address range of our own image so break_set can refuse to
 * write a trap inside the payload (deadlock). */
static void compute_self_range(void) {
    Dl_info info;
    if (!dladdr((void *)compute_self_range, &info) || !info.dli_fbase) return;
    g_self_lo = (uintptr_t)info.dli_fbase;
    /* No size from dladdr; scan dyld images for the matching base and use the
     * gap to the next image as an upper bound (good enough; payload is small). */
    uint32_t n = _dyld_image_count();
    uintptr_t next = UINTPTR_MAX;
    for (uint32_t i = 0; i < n; i++) {
        uintptr_t b = (uintptr_t)_dyld_get_image_header(i);
        if (b > g_self_lo && b < next) next = b;
    }
    g_self_hi = next == UINTPTR_MAX ? g_self_lo + 0x100000 : next;
}

static int ensure_exc_thread(void) {
    if (g_exc_inited) return 0;
    kern_return_t kr = mach_port_allocate(mach_task_self(),
                                          MACH_PORT_RIGHT_RECEIVE, &g_exc_port);
    if (kr != KERN_SUCCESS) return -1;
    kr = mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port,
                                MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) return -1;

    /* Remember whoever was handling BREAKPOINT before us so we can forward
     * exceptions we don't own (other people's traps, third-party crash
     * reporters, etc). */
    g_prior_exc.count = EXC_TYPES_COUNT;
    task_get_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT,
                             g_prior_exc.masks, &g_prior_exc.count,
                             g_prior_exc.ports, g_prior_exc.behaviors,
                             g_prior_exc.flavors);

    kr = task_set_exception_ports(mach_task_self(),
                                  EXC_MASK_BREAKPOINT, g_exc_port,
                                  EXCEPTION_DEFAULT,
                                  THREAD_STATE_NONE);
    if (kr != KERN_SUCCESS) return -1;

    compute_self_range();

    pthread_t t;
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &a, exc_thread, NULL) != 0) {
        pthread_attr_destroy(&a);
        return -1;
    }
    pthread_attr_destroy(&a);
    g_exc_inited = 1;
    return 0;
}

static int op_break_set(int fd, uint32_t seq, const uint8_t *body, uint64_t body_len) {
    if (body_len < sizeof(struct vmsw_break_set_req))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "short");
    struct vmsw_break_set_req req;
    memcpy(&req, body, sizeof(req));
    if (ensure_exc_thread() < 0)
        return send_error(fd, VMSW_ERR_INTERNAL, seq, "exception port setup failed");

    if (g_self_lo && req.addr >= g_self_lo && req.addr < g_self_hi)
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq,
                          "refusing to set breakpoint inside payload image");

    pthread_mutex_lock(&g_bp_mu);
    int slot = -1;
    for (int i = 0; i < MAX_BREAKPOINTS; i++) if (!g_bps[i].used) { slot = i; break; }
    if (slot < 0) {
        pthread_mutex_unlock(&g_bp_mu);
        return send_error(fd, VMSW_ERR_INTERNAL, seq, "no breakpoint slots");
    }
    memcpy(g_bps[slot].orig, (void *)(uintptr_t)req.addr, BREAK_INSN_LEN);
    if (write_bytes(req.addr, BREAK_INSN, BREAK_INSN_LEN) < 0) {
        pthread_mutex_unlock(&g_bp_mu);
        return send_error(fd, VMSW_ERR_BAD_ADDR, seq, "write trap failed");
    }
    g_bps[slot].used = 1;
    g_bps[slot].id   = g_next_bp_id++;
    g_bps[slot].addr = req.addr;
    struct vmsw_break_set_resp r = { .bp_id = g_bps[slot].id };
    pthread_mutex_unlock(&g_bp_mu);
    return send_response(fd, VMSW_OK, seq, &r, sizeof(r));
}

static int op_break_clear(int fd, uint32_t seq, const uint8_t *body, uint64_t body_len) {
    if (body_len < sizeof(struct vmsw_break_clear_req))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "short");
    struct vmsw_break_clear_req req;
    memcpy(&req, body, sizeof(req));
    pthread_mutex_lock(&g_bp_mu);
    int found = 0;
    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        if (g_bps[i].used && g_bps[i].id == req.bp_id) {
            write_bytes(g_bps[i].addr, g_bps[i].orig, BREAK_INSN_LEN);
            g_bps[i].used = 0;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_bp_mu);
    if (!found) return send_error(fd, VMSW_ERR_NOT_FOUND, seq, "no such bp");
    return send_response(fd, VMSW_OK, seq, NULL, 0);
}

static int op_break_wait(int fd, uint32_t seq, const uint8_t *body, uint64_t body_len) {
    int32_t timeout_ms = -1;
    if (body_len >= sizeof(struct vmsw_break_wait_req)) {
        struct vmsw_break_wait_req req;
        memcpy(&req, body, sizeof(req));
        timeout_ms = req.timeout_ms;
    }
    pthread_mutex_lock(&g_hits_mu);
    while (g_hits_head == g_hits_tail) {
        if (timeout_ms == 0) { pthread_mutex_unlock(&g_hits_mu); return send_error(fd, VMSW_ERR_NOT_FOUND, seq, "no hit"); }
        if (timeout_ms > 0) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec  += timeout_ms / 1000;
            ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
            if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
            int rc = pthread_cond_timedwait(&g_hits_cv, &g_hits_mu, &ts);
            if (rc == ETIMEDOUT) { pthread_mutex_unlock(&g_hits_mu); return send_error(fd, VMSW_ERR_NOT_FOUND, seq, "timeout"); }
        } else {
            pthread_cond_wait(&g_hits_cv, &g_hits_mu);
        }
    }
    struct bp_hit hit = g_hits[g_hits_head++ % HIT_QUEUE_CAP];
    pthread_mutex_unlock(&g_hits_mu);

    /* Remember the suspended thread port so BREAK_CONT can resume it.
     * Store by tid in the matching bp slot. */
    pthread_mutex_lock(&g_bp_mu);
    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        if (g_bps[i].used && g_bps[i].id == hit.bp_id) {
            g_bps[i].suspended_tid = hit.tid;
            g_bps[i].suspended_th  = hit.th;
            break;
        }
    }
    pthread_mutex_unlock(&g_bp_mu);

    struct vmsw_break_wait_resp r = {
        .bp_id = hit.bp_id, .tid = hit.tid, .pc = hit.pc,
    };
    return send_response(fd, VMSW_OK, seq, &r, sizeof(r));
}

static int op_break_cont(int fd, uint32_t seq, const uint8_t *body, uint64_t body_len) {
    if (body_len < sizeof(struct vmsw_break_cont_req))
        return send_error(fd, VMSW_ERR_BAD_REQUEST, seq, "short");
    struct vmsw_break_cont_req req;
    memcpy(&req, body, sizeof(req));

    thread_act_t th = MACH_PORT_NULL;
    uint64_t bp_addr = 0;
    uint8_t  orig[8];
    int found = 0;
    pthread_mutex_lock(&g_bp_mu);
    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        if (g_bps[i].used && g_bps[i].suspended_tid == req.tid) {
            th = g_bps[i].suspended_th;
            bp_addr = g_bps[i].addr;
            memcpy(orig, g_bps[i].orig, BREAK_INSN_LEN);
            g_bps[i].suspended_tid = 0;
            g_bps[i].suspended_th = MACH_PORT_NULL;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_bp_mu);
    if (!found) return send_error(fd, VMSW_ERR_NOT_FOUND, seq, "no suspended thread for tid");

    /* Restore the original instruction so the resumed thread doesn't immediately
     * re-trap. Caller can re-arm via BREAK_SET. */
    write_bytes(bp_addr, orig, BREAK_INSN_LEN);

#if defined(__x86_64__)
    /* Back rip up by 1 so we execute the restored byte. */
    x86_thread_state64_t s;
    mach_msg_type_number_t n = x86_THREAD_STATE64_COUNT;
    if (thread_get_state(th, x86_THREAD_STATE64, (thread_state_t)&s, &n) == KERN_SUCCESS) {
        s.__rip = bp_addr;
        thread_set_state(th, x86_THREAD_STATE64, (thread_state_t)&s, n);
    }
#endif

    thread_resume(th);
    mach_port_deallocate(mach_task_self(), th);
    return send_response(fd, VMSW_OK, seq, NULL, 0);
}

static int serve_one(int cfd) {
    while (1) {
        struct vmsw_hdr h;
        if (read_full(cfd, &h, sizeof(h)) < 0) return 0;
        if (h.magic != VMSW_MAGIC) {
            send_error(cfd, VMSW_ERR_BAD_REQUEST, h.seq, "bad magic");
            return -1;
        }
        if (h.payload_len > (1ull << 26)) {  /* 64 MiB cap */
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
        case VMSW_OP_PING:             rc = op_ping(cfd, h.seq); break;
        case VMSW_OP_READ:             rc = op_read(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_WRITE:            rc = op_write(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_RESOLVE:          rc = op_resolve(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_IMAGES:           rc = op_images(cfd, h.seq); break;
        case VMSW_OP_REGIONS:          rc = op_regions(cfd, h.seq); break;
        case VMSW_OP_SCAN:             rc = op_scan(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_DYLD_INFO:        rc = op_dyld_info(cfd, h.seq); break;
        case VMSW_OP_THREADS:          rc = op_threads(cfd, h.seq); break;
        case VMSW_OP_THREAD_GET_STATE: rc = op_thread_get_state(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_THREAD_SET_STATE: rc = op_thread_set_state(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_ALLOCATE:         rc = op_allocate(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_DEALLOCATE:       rc = op_deallocate(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_VERSION:          rc = op_version(cfd, h.seq); break;
        case VMSW_OP_CALL:             rc = op_call(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_BREAK_SET:        rc = op_break_set(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_BREAK_CLEAR:      rc = op_break_clear(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_BREAK_WAIT:       rc = op_break_wait(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_BREAK_CONT:       rc = op_break_cont(cfd, h.seq, body, h.payload_len); break;
        case VMSW_OP_QUIT:             free(body); return 1;
        default:
            rc = send_error(cfd, VMSW_ERR_BAD_OP, h.seq, "unknown op");
        }
        free(body);
        if (rc < 0) return -1;
    }
}

/* reject connections from peers running as a different uid. */
static int check_peer(int cfd) {
    struct xucred cr;
    socklen_t len = sizeof(cr);
    if (getsockopt(cfd, 0, LOCAL_PEERCRED, &cr, &len) < 0) return -1;
    if (cr.cr_version != XUCRED_VERSION) return -1;
    if (cr.cr_uid != getuid()) return -1;
    return 0;
}

static void *client_thread(void *arg) {
    int cfd = (int)(intptr_t)arg;
    if (check_peer(cfd) < 0) {
        log_msg("rejected peer (uid mismatch)");
        send_error(cfd, VMSW_ERR_AUTH, 0, "peer uid mismatch");
        close(cfd);
        return NULL;
    }
    log_msg("client connected");
    serve_one(cfd);
    close(cfd);
    return NULL;
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
        pthread_t t;
        pthread_attr_t a;
        pthread_attr_init(&a);
        pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&t, &a, client_thread, (void *)(intptr_t)cfd) != 0) {
            log_msg("pthread_create: %s", strerror(errno));
            close(cfd);
        }
        pthread_attr_destroy(&a);
    }
    close(g_listen_fd);
    unlink(g_sock_path);
    return NULL;
}

__attribute__((constructor))
static void vm_stowaway_init(void) {
    g_debug = getenv("VM_STOWAWAY_DEBUG") != NULL;
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
    if (listen(fd, 8) < 0) {
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
