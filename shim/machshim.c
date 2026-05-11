/*
 * vm_stowaway mach API shim.
 *
 * DYLD_INSERT this dylib into a memory-inspection tool. It interposes
 * task_for_pid and the mach_vm_* functions so that, when the tool tries
 * to operate on the pid set in VM_STOWAWAY_TARGET_PID, the calls route
 * through a vm_stowaway payload already running inside the target instead
 * of into the kernel. The tool works without SIP off / debug entitlements.
 *
 * dyld does not apply our interpose to calls made from within this image,
 * so calls to e.g. task_for_pid below go to the real libSystem function.
 *
 * Env vars (set by `vm_stowaway wrap`):
 *   VM_STOWAWAY_TARGET_PID  the pid we should shim
 *   VM_STOWAWAY_SOCK        socket path; defaults to /tmp/vm_stowaway.<pid>.sock
 */

#define _DARWIN_C_SOURCE

#include "../include/vm_stowaway.h"

#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Magic value handed back from task_for_pid. */
#define VMSW_SENTINEL_PORT 0x76737721u  /* 'vsw!' */

static int             g_target_pid = -1;
static vm_stowaway_t  *g_handle = NULL;
static pthread_once_t  g_init_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_handle_mu = PTHREAD_MUTEX_INITIALIZER;

static vm_stowaway_region_t *g_regions = NULL;
static ssize_t               g_n_regions = 0;
static pthread_mutex_t       g_regions_mu = PTHREAD_MUTEX_INITIALIZER;

static void log_msg(const char *fmt, ...) {
    if (!getenv("VM_STOWAWAY_DEBUG")) return;
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "[vm_stowaway/shim] ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static void shim_init(void) {
    const char *s = getenv("VM_STOWAWAY_TARGET_PID");
    if (s) g_target_pid = atoi(s);
    log_msg("init: target_pid=%d", g_target_pid);
}

static vm_stowaway_t *handle(void) {
    pthread_once(&g_init_once, shim_init);
    if (g_target_pid <= 0) return NULL;
    pthread_mutex_lock(&g_handle_mu);
    if (!g_handle) {
        char err[256] = {0};
        const char *sock = getenv("VM_STOWAWAY_SOCK");
        g_handle = vm_stowaway_attach(g_target_pid, sock, 5, err, sizeof(err));
        if (!g_handle) log_msg("attach failed: %s", err);
        else log_msg("attached to pid %d", g_target_pid);
    }
    vm_stowaway_t *h = g_handle;
    pthread_mutex_unlock(&g_handle_mu);
    return h;
}

static int ensure_regions(void) {
    pthread_mutex_lock(&g_regions_mu);
    if (g_regions) { pthread_mutex_unlock(&g_regions_mu); return 0; }
    vm_stowaway_t *h = handle();
    if (!h) { pthread_mutex_unlock(&g_regions_mu); return -1; }

    size_t cap = 4096;
    vm_stowaway_region_t *buf = malloc(cap * sizeof(*buf));
    if (!buf) { pthread_mutex_unlock(&g_regions_mu); return -1; }
    ssize_t n = vm_stowaway_regions(h, buf, cap);
    while (n > (ssize_t)cap) {
        cap = (size_t)n;
        free(buf);
        buf = malloc(cap * sizeof(*buf));
        if (!buf) { pthread_mutex_unlock(&g_regions_mu); return -1; }
        n = vm_stowaway_regions(h, buf, cap);
    }
    if (n < 0) { free(buf); pthread_mutex_unlock(&g_regions_mu); return -1; }
    g_regions = buf;
    g_n_regions = n;
    log_msg("cached %zd regions", n);
    pthread_mutex_unlock(&g_regions_mu);
    return 0;
}

static const vm_stowaway_region_t *next_region(mach_vm_address_t addr) {
    for (ssize_t i = 0; i < g_n_regions; i++)
        if (g_regions[i].base + g_regions[i].size > addr) return &g_regions[i];
    return NULL;
}

/* -- interposers --------------------------------------------------------- */

static kern_return_t vmsw_task_for_pid(mach_port_name_t target, int pid,
                                       mach_port_name_t *t) {
    pthread_once(&g_init_once, shim_init);
    if (pid == g_target_pid) {
        if (!handle()) return KERN_FAILURE;
        *t = VMSW_SENTINEL_PORT;
        log_msg("task_for_pid(%d) -> sentinel", pid);
        return KERN_SUCCESS;
    }
    return task_for_pid(target, pid, t);
}

static kern_return_t vmsw_mach_vm_read(vm_map_read_t task,
                                       mach_vm_address_t addr,
                                       mach_vm_size_t size,
                                       vm_offset_t *data,
                                       mach_msg_type_number_t *data_count) {
    if (task == VMSW_SENTINEL_PORT) {
        vm_stowaway_t *h = handle();
        if (!h) return KERN_FAILURE;
        mach_vm_address_t buf = 0;
        kern_return_t kr = mach_vm_allocate(mach_task_self(), &buf, size,
                                            VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) return kr;
        ssize_t got = vm_stowaway_read(h, addr, (void *)(uintptr_t)buf, size);
        if (got < 0) {
            mach_vm_deallocate(mach_task_self(), buf, size);
            return KERN_INVALID_ADDRESS;
        }
        *data = (vm_offset_t)buf;
        *data_count = (mach_msg_type_number_t)got;
        return KERN_SUCCESS;
    }
    return mach_vm_read(task, addr, size, data, data_count);
}

static kern_return_t vmsw_mach_vm_read_overwrite(vm_map_read_t task,
                                                 mach_vm_address_t addr,
                                                 mach_vm_size_t size,
                                                 mach_vm_address_t data,
                                                 mach_vm_size_t *out_size) {
    if (task == VMSW_SENTINEL_PORT) {
        vm_stowaway_t *h = handle();
        if (!h) return KERN_FAILURE;
        ssize_t got = vm_stowaway_read(h, addr, (void *)(uintptr_t)data, size);
        if (got < 0) { *out_size = 0; return KERN_INVALID_ADDRESS; }
        *out_size = (mach_vm_size_t)got;
        return KERN_SUCCESS;
    }
    return mach_vm_read_overwrite(task, addr, size, data, out_size);
}

static kern_return_t vmsw_mach_vm_write(vm_map_t task,
                                        mach_vm_address_t addr,
                                        vm_offset_t data,
                                        mach_msg_type_number_t data_count) {
    if (task == VMSW_SENTINEL_PORT) {
        vm_stowaway_t *h = handle();
        if (!h) return KERN_FAILURE;
        ssize_t w = vm_stowaway_write(h, addr, (const void *)(uintptr_t)data,
                                       data_count);
        return (w == (ssize_t)data_count) ? KERN_SUCCESS : KERN_INVALID_ADDRESS;
    }
    return mach_vm_write(task, addr, data, data_count);
}

static kern_return_t vmsw_mach_vm_region(vm_map_read_t task,
                                         mach_vm_address_t *addr,
                                         mach_vm_size_t *size,
                                         vm_region_flavor_t flavor,
                                         vm_region_info_t info,
                                         mach_msg_type_number_t *info_cnt,
                                         mach_port_t *object_name) {
    if (task == VMSW_SENTINEL_PORT) {
        if (ensure_regions() < 0) return KERN_FAILURE;
        const vm_stowaway_region_t *r = next_region(*addr);
        if (!r) return KERN_INVALID_ADDRESS;
        *addr = r->base;
        *size = r->size;
        if (object_name) *object_name = MACH_PORT_NULL;
        if (flavor == VM_REGION_BASIC_INFO_64 &&
            *info_cnt >= VM_REGION_BASIC_INFO_COUNT_64) {
            vm_region_basic_info_data_64_t bi = {0};
            bi.protection = r->prot;
            bi.max_protection = r->prot;
            bi.inheritance = VM_INHERIT_COPY;
            memcpy(info, &bi, sizeof(bi));
            *info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
            return KERN_SUCCESS;
        }
        if (flavor == VM_REGION_EXTENDED_INFO &&
            *info_cnt >= VM_REGION_EXTENDED_INFO_COUNT) {
            vm_region_extended_info_data_t ei = {0};
            ei.protection = r->prot;
            memcpy(info, &ei, sizeof(ei));
            *info_cnt = VM_REGION_EXTENDED_INFO_COUNT;
            return KERN_SUCCESS;
        }
        return KERN_INVALID_ARGUMENT;
    }
    return mach_vm_region(task, addr, size, flavor, info, info_cnt, object_name);
}

static kern_return_t vmsw_mach_vm_region_recurse(vm_map_read_t task,
                                                 mach_vm_address_t *addr,
                                                 mach_vm_size_t *size,
                                                 natural_t *depth,
                                                 vm_region_recurse_info_t info,
                                                 mach_msg_type_number_t *info_cnt) {
    if (task == VMSW_SENTINEL_PORT) {
        if (ensure_regions() < 0) return KERN_FAILURE;
        const vm_stowaway_region_t *r = next_region(*addr);
        if (!r) return KERN_INVALID_ADDRESS;
        *addr = r->base;
        *size = r->size;
        if (*info_cnt >= VM_REGION_SUBMAP_INFO_COUNT_64) {
            vm_region_submap_info_data_64_t si = {0};
            si.protection = r->prot;
            si.max_protection = r->prot;
            si.inheritance = VM_INHERIT_COPY;
            si.is_submap = 0;
            memcpy(info, &si, sizeof(si));
            *info_cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
            return KERN_SUCCESS;
        }
        return KERN_INVALID_ARGUMENT;
    }
    return mach_vm_region_recurse(task, addr, size, depth, info, info_cnt);
}

static kern_return_t vmsw_mach_port_deallocate(ipc_space_t task,
                                               mach_port_name_t name) {
    if (name == VMSW_SENTINEL_PORT) return KERN_SUCCESS;
    return mach_port_deallocate(task, name);
}

static kern_return_t vmsw_mach_port_mod_refs(ipc_space_t task,
                                             mach_port_name_t name,
                                             mach_port_right_t right,
                                             mach_port_delta_t delta) {
    if (name == VMSW_SENTINEL_PORT) return KERN_SUCCESS;
    return mach_port_mod_refs(task, name, right, delta);
}

/* --- task control APIs (no-op for our sentinel) --- */

static kern_return_t vmsw_task_suspend(task_t task) {
    if (task == VMSW_SENTINEL_PORT) {
        log_msg("task_suspend(sentinel) -> ok (no-op)");
        return KERN_SUCCESS;
    }
    return task_suspend(task);
}

static kern_return_t vmsw_task_resume(task_t task) {
    if (task == VMSW_SENTINEL_PORT) {
        log_msg("task_resume(sentinel) -> ok (no-op)");
        return KERN_SUCCESS;
    }
    return task_resume(task);
}

/* task_info: zero-fill the requested struct and return success. Tools use
 * a variety of flavors (TASK_BASIC_INFO_64 for cpu/mem, TASK_DYLD_INFO for
 * the dyld_all_image_infos pointer, ...). Returning all-zeros is enough to
 * get past tools that only check kern_return; tools that depend on the
 * specific fields will need a richer impl (planned). */
static kern_return_t vmsw_task_info(task_name_t task,
                                    task_flavor_t flavor,
                                    task_info_t info,
                                    mach_msg_type_number_t *count) {
    if (task == VMSW_SENTINEL_PORT) {
        log_msg("task_info(sentinel, flavor=%u, count=%u) -> zero-filled",
                flavor, count ? *count : 0);
        if (info && count && *count > 0)
            memset(info, 0, (size_t)(*count) * sizeof(integer_t));
        return KERN_SUCCESS;
    }
    return task_info(task, flavor, info, count);
}

static kern_return_t vmsw_task_threads(task_inspect_t task,
                                       thread_act_array_t *threads,
                                       mach_msg_type_number_t *count) {
    if (task == VMSW_SENTINEL_PORT) {
        log_msg("task_threads(sentinel) -> empty list");
        if (threads) *threads = NULL;
        if (count) *count = 0;
        return KERN_SUCCESS;
    }
    return task_threads(task, threads, count);
}

/* --- VM allocation / protection (sentinel path) --- */

static kern_return_t vmsw_mach_vm_allocate(vm_map_t task,
                                           mach_vm_address_t *addr,
                                           mach_vm_size_t size,
                                           int flags) {
    if (task == VMSW_SENTINEL_PORT) {
        log_msg("mach_vm_allocate(sentinel, size=%llu) -> KERN_FAILURE "
                "(allocation in target not supported by v1 shim)", size);
        return KERN_FAILURE;
    }
    return mach_vm_allocate(task, addr, size, flags);
}

static kern_return_t vmsw_mach_vm_deallocate(vm_map_t task,
                                             mach_vm_address_t addr,
                                             mach_vm_size_t size) {
    if (task == VMSW_SENTINEL_PORT) {
        log_msg("mach_vm_deallocate(sentinel) -> ok (no-op)");
        return KERN_SUCCESS;
    }
    return mach_vm_deallocate(task, addr, size);
}

static kern_return_t vmsw_mach_vm_protect(vm_map_t task,
                                          mach_vm_address_t addr,
                                          mach_vm_size_t size,
                                          boolean_t set_max,
                                          vm_prot_t new_prot) {
    if (task == VMSW_SENTINEL_PORT) {
        /* Page perm changes inside the target are best-effort: the payload
         * already toggles RW for writes via mach_vm_protect in the target.
         * Pretend success for the tool. */
        log_msg("mach_vm_protect(sentinel, addr=0x%llx size=%llu prot=%d) "
                "-> ok (no-op)", addr, size, new_prot);
        return KERN_SUCCESS;
    }
    return mach_vm_protect(task, addr, size, set_max, new_prot);
}

/* -- DYLD_INTERPOSE table ------------------------------------------------- */

#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { \
        const void *replacement; \
        const void *replacee; \
    } _interpose_##_replacee \
    __attribute__ ((section ("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)&_replacement, \
        (const void *)(uintptr_t)&_replacee \
    }

DYLD_INTERPOSE(vmsw_task_for_pid,            task_for_pid);
DYLD_INTERPOSE(vmsw_mach_vm_read,            mach_vm_read);
DYLD_INTERPOSE(vmsw_mach_vm_read_overwrite,  mach_vm_read_overwrite);
DYLD_INTERPOSE(vmsw_mach_vm_write,           mach_vm_write);
DYLD_INTERPOSE(vmsw_mach_vm_region,          mach_vm_region);
DYLD_INTERPOSE(vmsw_mach_vm_region_recurse,  mach_vm_region_recurse);
DYLD_INTERPOSE(vmsw_mach_port_deallocate,    mach_port_deallocate);
DYLD_INTERPOSE(vmsw_mach_port_mod_refs,      mach_port_mod_refs);
DYLD_INTERPOSE(vmsw_task_suspend,            task_suspend);
DYLD_INTERPOSE(vmsw_task_resume,             task_resume);
DYLD_INTERPOSE(vmsw_task_info,               task_info);
DYLD_INTERPOSE(vmsw_task_threads,            task_threads);
DYLD_INTERPOSE(vmsw_mach_vm_allocate,        mach_vm_allocate);
DYLD_INTERPOSE(vmsw_mach_vm_deallocate,      mach_vm_deallocate);
DYLD_INTERPOSE(vmsw_mach_vm_protect,         mach_vm_protect);
