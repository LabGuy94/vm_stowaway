/* DYLD_INSERT into a mem-inspection tool. Interposes task_for_pid / mach_vm_*
 * etc for VM_STOWAWAY_TARGET_PID; calls route through the payload.
 *
 * Note: dyld doesn't apply interposes to calls from inside this image, so the
 * real-libSystem fallbacks below work as-is. */

#define _DARWIN_C_SOURCE

#include "../include/vm_stowaway.h"

#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/task_info.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/vm_region.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>

/* Magic value handed back from task_for_pid. */
#define VMSW_SENTINEL_PORT 0x76737721u  /* 'vsw!' */
/* Base for fake per-thread sentinel ports. Each thread the tool sees is
 * VMSW_THREAD_PORT_BASE + index_in_g_thread_tids. */
#define VMSW_THREAD_PORT_BASE 0x76737800u
#define VMSW_THREAD_PORT_MAX  256

static int is_thread_sentinel(mach_port_t p) {
    return p >= VMSW_THREAD_PORT_BASE &&
           p <  VMSW_THREAD_PORT_BASE + VMSW_THREAD_PORT_MAX;
}

static int             g_target_pid = -1;
static int             g_debug = 0;
static vm_stowaway_t  *g_handle = NULL;
static pthread_once_t  g_init_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_handle_mu = PTHREAD_MUTEX_INITIALIZER;

static vm_stowaway_region_t *g_regions = NULL;
static ssize_t               g_n_regions = 0;
static pthread_mutex_t       g_regions_mu = PTHREAD_MUTEX_INITIALIZER;

/* Most recent thread enumeration: maps the fake port (BASE+i) back to the
 * tid the payload reported. Mutated under g_threads_mu. */
static uint64_t        g_thread_tids[VMSW_THREAD_PORT_MAX];
static uint32_t        g_thread_count = 0;
static pthread_mutex_t g_threads_mu = PTHREAD_MUTEX_INITIALIZER;

static void log_msg(const char *fmt, ...) {
    if (!g_debug) return;
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "[vm_stowaway/shim] ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static void shim_init(void) {
    g_debug = getenv("VM_STOWAWAY_DEBUG") != NULL;
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

static int cmp_region(const void *a, const void *b) {
    uint64_t ba = ((const vm_stowaway_region_t *)a)->base;
    uint64_t bb = ((const vm_stowaway_region_t *)b)->base;
    return (ba > bb) - (ba < bb);
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
    if (n > (ssize_t)cap) {
        cap = (size_t)n;
        free(buf);
        buf = malloc(cap * sizeof(*buf));
        if (!buf) { pthread_mutex_unlock(&g_regions_mu); return -1; }
        n = vm_stowaway_regions(h, buf, cap);
        if (n > (ssize_t)cap) n = (ssize_t)cap;  /* accept truncation on race */
    }
    if (n < 0) { free(buf); pthread_mutex_unlock(&g_regions_mu); return -1; }
    qsort(buf, (size_t)n, sizeof(*buf), cmp_region);
    g_regions = buf;
    g_n_regions = n;
    log_msg("cached %zd regions", n);
    pthread_mutex_unlock(&g_regions_mu);
    return 0;
}

static void invalidate_regions(void) {
    pthread_mutex_lock(&g_regions_mu);
    free(g_regions);
    g_regions = NULL;
    g_n_regions = 0;
    pthread_mutex_unlock(&g_regions_mu);
}

/* lowest region r with r.base + r.size > addr, via bisect on sorted bases. */
static const vm_stowaway_region_t *next_region(mach_vm_address_t addr) {
    ssize_t lo = 0, hi = g_n_regions;
    while (lo < hi) {
        ssize_t m = lo + (hi - lo) / 2;
        if (g_regions[m].base + g_regions[m].size > addr) hi = m;
        else lo = m + 1;
    }
    return lo < g_n_regions ? &g_regions[lo] : NULL;
}

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
    if (name == VMSW_SENTINEL_PORT || is_thread_sentinel(name))
        return KERN_SUCCESS;
    return mach_port_deallocate(task, name);
}

static kern_return_t vmsw_mach_port_mod_refs(ipc_space_t task,
                                             mach_port_name_t name,
                                             mach_port_right_t right,
                                             mach_port_delta_t delta) {
    if (name == VMSW_SENTINEL_PORT || is_thread_sentinel(name))
        return KERN_SUCCESS;
    return mach_port_mod_refs(task, name, right, delta);
}

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

/* task_info: real implementations for TASK_DYLD_INFO (routed to payload)
 * and TASK_BASIC_INFO_64 (filled from proc_pidinfo locally, no entitlement
 * needed). Other flavors get zero-fill + success. */
static kern_return_t vmsw_task_info(task_name_t task,
                                    task_flavor_t flavor,
                                    task_info_t info,
                                    mach_msg_type_number_t *count) {
    if (task == VMSW_SENTINEL_PORT) {
        if (flavor == TASK_DYLD_INFO && info && count &&
            *count >= TASK_DYLD_INFO_COUNT) {
            vm_stowaway_t *h = handle();
            if (!h) return KERN_FAILURE;
            struct task_dyld_info di = {0};
            uint32_t fmt = 0;
            if (vm_stowaway_dyld_info(h, &di.all_image_info_addr,
                                       &di.all_image_info_size, &fmt) < 0)
                return KERN_FAILURE;
            di.all_image_info_format = fmt;
            memcpy(info, &di, sizeof(di));
            *count = TASK_DYLD_INFO_COUNT;
            log_msg("task_info(sentinel, TASK_DYLD_INFO) -> addr=0x%llx",
                    (unsigned long long)di.all_image_info_addr);
            return KERN_SUCCESS;
        }
        if (flavor == TASK_BASIC_INFO_64 && info && count &&
            *count >= TASK_BASIC_INFO_64_COUNT) {
            struct proc_taskinfo pti = {0};
            int n = proc_pidinfo(g_target_pid, PROC_PIDTASKINFO, 0,
                                 &pti, sizeof(pti));
            task_basic_info_64_data_t bi = {0};
            if (n == (int)sizeof(pti)) {
                bi.virtual_size  = pti.pti_virtual_size;
                bi.resident_size = pti.pti_resident_size;
                bi.user_time.seconds      = (int)(pti.pti_total_user / 1000000000ULL);
                bi.user_time.microseconds = (int)((pti.pti_total_user / 1000ULL) % 1000000ULL);
                bi.system_time.seconds      = (int)(pti.pti_total_system / 1000000000ULL);
                bi.system_time.microseconds = (int)((pti.pti_total_system / 1000ULL) % 1000000ULL);
            }
            memcpy(info, &bi, sizeof(bi));
            *count = TASK_BASIC_INFO_64_COUNT;
            log_msg("task_info(sentinel, TASK_BASIC_INFO_64) -> vsz=%llu rsz=%llu",
                    (unsigned long long)bi.virtual_size,
                    (unsigned long long)bi.resident_size);
            return KERN_SUCCESS;
        }
        log_msg("task_info(sentinel, flavor=%u) -> zero-filled fallback", flavor);
        if (info && count && *count > 0)
            memset(info, 0, (size_t)(*count) * sizeof(integer_t));
        return KERN_SUCCESS;
    }
    return task_info(task, flavor, info, count);
}

/* task_threads: ask the payload for tids, store them in g_thread_tids, hand
 * back fake per-thread sentinel ports indexed off VMSW_THREAD_PORT_BASE. */
static kern_return_t vmsw_task_threads(task_inspect_t task,
                                       thread_act_array_t *threads_out,
                                       mach_msg_type_number_t *count_out) {
    if (task == VMSW_SENTINEL_PORT) {
        vm_stowaway_t *h = handle();
        if (!h) return KERN_FAILURE;
        uint64_t tids[VMSW_THREAD_PORT_MAX];
        ssize_t n = vm_stowaway_threads(h, tids, VMSW_THREAD_PORT_MAX);
        if (n < 0) return KERN_FAILURE;
        if (n > VMSW_THREAD_PORT_MAX) n = VMSW_THREAD_PORT_MAX;

        pthread_mutex_lock(&g_threads_mu);
        g_thread_count = (uint32_t)n;
        for (ssize_t i = 0; i < n; i++) g_thread_tids[i] = tids[i];
        pthread_mutex_unlock(&g_threads_mu);

        /* The caller will mach_vm_deallocate this array (with self_task,
         * which falls through to the real call), so back it with real
         * mach-allocated memory. */
        mach_vm_address_t addr = 0;
        mach_vm_size_t bytes = (mach_vm_size_t)n * sizeof(thread_act_t);
        kern_return_t kr = mach_vm_allocate(mach_task_self(), &addr, bytes,
                                            VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) return kr;
        thread_act_t *arr = (thread_act_t *)(uintptr_t)addr;
        for (ssize_t i = 0; i < n; i++)
            arr[i] = VMSW_THREAD_PORT_BASE + (uint32_t)i;
        *threads_out = arr;
        *count_out = (mach_msg_type_number_t)n;
        log_msg("task_threads(sentinel) -> %zd threads", n);
        return KERN_SUCCESS;
    }
    return task_threads(task, threads_out, count_out);
}

static kern_return_t vmsw_thread_get_state(thread_act_t thread,
                                           thread_state_flavor_t flavor,
                                           thread_state_t state,
                                           mach_msg_type_number_t *count) {
    if (is_thread_sentinel(thread)) {
        uint32_t idx = thread - VMSW_THREAD_PORT_BASE;
        pthread_mutex_lock(&g_threads_mu);
        uint64_t tid = (idx < g_thread_count) ? g_thread_tids[idx] : 0;
        pthread_mutex_unlock(&g_threads_mu);
        if (!tid) return KERN_INVALID_ARGUMENT;
        vm_stowaway_t *h = handle();
        if (!h) return KERN_FAILURE;
        uint32_t c = *count;
        if (vm_stowaway_thread_get_state(h, tid, (uint32_t)flavor, &c,
                                         state, (*count) * sizeof(uint32_t)) < 0)
            return KERN_FAILURE;
        *count = c;
        log_msg("thread_get_state(tid=%llu, flavor=%u) -> %u natural_t",
                (unsigned long long)tid, flavor, c);
        return KERN_SUCCESS;
    }
    return thread_get_state(thread, flavor, state, count);
}

static kern_return_t vmsw_thread_set_state(thread_act_t thread,
                                           thread_state_flavor_t flavor,
                                           thread_state_t state,
                                           mach_msg_type_number_t count) {
    if (is_thread_sentinel(thread)) {
        uint32_t idx = thread - VMSW_THREAD_PORT_BASE;
        pthread_mutex_lock(&g_threads_mu);
        uint64_t tid = (idx < g_thread_count) ? g_thread_tids[idx] : 0;
        pthread_mutex_unlock(&g_threads_mu);
        if (!tid) return KERN_INVALID_ARGUMENT;
        vm_stowaway_t *h = handle();
        if (!h) return KERN_FAILURE;
        if (vm_stowaway_thread_set_state(h, tid, (uint32_t)flavor, count, state) < 0)
            return KERN_FAILURE;
        log_msg("thread_set_state(tid=%llu, flavor=%u)", (unsigned long long)tid, flavor);
        return KERN_SUCCESS;
    }
    return thread_set_state(thread, flavor, state, count);
}

static kern_return_t vmsw_mach_vm_allocate(vm_map_t task,
                                           mach_vm_address_t *addr,
                                           mach_vm_size_t size,
                                           int flags) {
    if (task == VMSW_SENTINEL_PORT) {
        vm_stowaway_t *h = handle();
        if (!h) return KERN_FAILURE;
        uint64_t a = vm_stowaway_allocate(h, size, flags);
        if (!a) return KERN_FAILURE;
        *addr = (mach_vm_address_t)a;
        invalidate_regions();
        log_msg("mach_vm_allocate(sentinel, size=%llu) -> 0x%llx", size, a);
        return KERN_SUCCESS;
    }
    return mach_vm_allocate(task, addr, size, flags);
}

static kern_return_t vmsw_mach_vm_deallocate(vm_map_t task,
                                             mach_vm_address_t addr,
                                             mach_vm_size_t size) {
    if (task == VMSW_SENTINEL_PORT) {
        vm_stowaway_t *h = handle();
        if (h) vm_stowaway_deallocate(h, addr, size);
        invalidate_regions();
        log_msg("mach_vm_deallocate(sentinel, 0x%llx, %llu)", addr, size);
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

static kern_return_t vmsw_pid_for_task(mach_port_name_t task, int *pid) {
    if (task == VMSW_SENTINEL_PORT) {
        if (pid) *pid = g_target_pid;
        log_msg("pid_for_task(sentinel) -> %d", g_target_pid);
        return KERN_SUCCESS;
    }
    return pid_for_task(task, pid);
}

static kern_return_t vmsw_task_set_info(task_t task, task_flavor_t flavor,
                                        task_info_t info,
                                        mach_msg_type_number_t cnt) {
    if (task == VMSW_SENTINEL_PORT) {
        log_msg("task_set_info(sentinel, flavor=%u) -> ok (no-op)", flavor);
        return KERN_SUCCESS;
    }
    return task_set_info(task, flavor, info, cnt);
}

static kern_return_t vmsw_task_terminate(task_t task) {
    if (task == VMSW_SENTINEL_PORT) {
        /* Refuse to kill the target by accident. */
        log_msg("task_terminate(sentinel) -> ok (refused)");
        return KERN_SUCCESS;
    }
    return task_terminate(task);
}

static kern_return_t vmsw_task_set_exception_ports(task_t task,
                                                   exception_mask_t mask,
                                                   mach_port_t handler,
                                                   exception_behavior_t behavior,
                                                   thread_state_flavor_t flavor) {
    if (task == VMSW_SENTINEL_PORT) {
        log_msg("task_set_exception_ports(sentinel) -> ok (no-op)");
        return KERN_SUCCESS;
    }
    return task_set_exception_ports(task, mask, handler, behavior, flavor);
}

static kern_return_t vmsw_task_get_exception_ports(task_t task,
                                                   exception_mask_t mask,
                                                   exception_mask_array_t masks,
                                                   mach_msg_type_number_t *cnt,
                                                   exception_handler_array_t ports,
                                                   exception_behavior_array_t behaviors,
                                                   exception_flavor_array_t flavors) {
    if (task == VMSW_SENTINEL_PORT) {
        if (cnt) *cnt = 0;
        log_msg("task_get_exception_ports(sentinel) -> 0 ports");
        return KERN_SUCCESS;
    }
    return task_get_exception_ports(task, mask, masks, cnt, ports, behaviors, flavors);
}

static kern_return_t vmsw_thread_info(thread_inspect_t thread,
                                      thread_flavor_t flavor,
                                      thread_info_t info,
                                      mach_msg_type_number_t *count) {
    if (is_thread_sentinel(thread)) {
        if (info && count && *count > 0)
            memset(info, 0, (size_t)(*count) * sizeof(natural_t));
        log_msg("thread_info(sentinel_thread, flavor=%u) -> zero-filled", flavor);
        return KERN_SUCCESS;
    }
    return thread_info(thread, flavor, info, count);
}

static kern_return_t vmsw_thread_suspend(thread_act_t thread) {
    if (is_thread_sentinel(thread)) return KERN_SUCCESS;
    return thread_suspend(thread);
}

static kern_return_t vmsw_thread_resume(thread_act_t thread) {
    if (is_thread_sentinel(thread)) return KERN_SUCCESS;
    return thread_resume(thread);
}

static kern_return_t vmsw_thread_terminate(thread_act_t thread) {
    if (is_thread_sentinel(thread)) {
        log_msg("thread_terminate(sentinel_thread) -> ok (refused)");
        return KERN_SUCCESS;
    }
    return thread_terminate(thread);
}

static kern_return_t vmsw_mach_port_destroy(ipc_space_t task,
                                            mach_port_name_t name) {
    if (name == VMSW_SENTINEL_PORT || is_thread_sentinel(name))
        return KERN_SUCCESS;
    return mach_port_destroy(task, name);
}

/* legacy vm_* family. */

static kern_return_t vmsw_vm_read(vm_map_t task, vm_address_t addr,
                                  vm_size_t size, vm_offset_t *data,
                                  mach_msg_type_number_t *cnt) {
    if (task == VMSW_SENTINEL_PORT)
        return vmsw_mach_vm_read(task, addr, size, data, cnt);
    return vm_read(task, addr, size, data, cnt);
}

static kern_return_t vmsw_vm_read_overwrite(vm_map_t task, vm_address_t addr,
                                            vm_size_t size, vm_address_t data,
                                            vm_size_t *out_size) {
    if (task == VMSW_SENTINEL_PORT) {
        mach_vm_size_t got = 0;
        kern_return_t kr = vmsw_mach_vm_read_overwrite(task, addr, size, data, &got);
        if (out_size) *out_size = (vm_size_t)got;
        return kr;
    }
    return vm_read_overwrite(task, addr, size, data, out_size);
}

static kern_return_t vmsw_vm_write(vm_map_t task, vm_address_t addr,
                                   vm_offset_t data,
                                   mach_msg_type_number_t cnt) {
    if (task == VMSW_SENTINEL_PORT)
        return vmsw_mach_vm_write(task, addr, data, cnt);
    return vm_write(task, addr, data, cnt);
}

static kern_return_t vmsw_vm_protect(vm_map_t task, vm_address_t addr,
                                     vm_size_t size, boolean_t set_max,
                                     vm_prot_t new_prot) {
    if (task == VMSW_SENTINEL_PORT)
        return vmsw_mach_vm_protect(task, addr, size, set_max, new_prot);
    return vm_protect(task, addr, size, set_max, new_prot);
}

static kern_return_t vmsw_vm_allocate(vm_map_t task, vm_address_t *addr,
                                      vm_size_t size, int flags) {
    if (task == VMSW_SENTINEL_PORT) {
        mach_vm_address_t a = 0;
        kern_return_t kr = vmsw_mach_vm_allocate(task, &a, size, flags);
        if (kr == KERN_SUCCESS && addr) *addr = (vm_address_t)a;
        return kr;
    }
    return vm_allocate(task, addr, size, flags);
}

static kern_return_t vmsw_vm_deallocate(vm_map_t task, vm_address_t addr,
                                        vm_size_t size) {
    if (task == VMSW_SENTINEL_PORT)
        return vmsw_mach_vm_deallocate(task, addr, size);
    return vm_deallocate(task, addr, size);
}

/* vm_region / vm_region_recurse aren't exported on macOS 12+; modern tools
 * call the mach_vm_* variants which we already interpose. */

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
DYLD_INTERPOSE(vmsw_thread_get_state,        thread_get_state);
DYLD_INTERPOSE(vmsw_thread_set_state,        thread_set_state);
DYLD_INTERPOSE(vmsw_mach_vm_allocate,        mach_vm_allocate);
DYLD_INTERPOSE(vmsw_mach_vm_deallocate,      mach_vm_deallocate);
DYLD_INTERPOSE(vmsw_mach_vm_protect,         mach_vm_protect);
DYLD_INTERPOSE(vmsw_pid_for_task,            pid_for_task);
DYLD_INTERPOSE(vmsw_task_set_info,           task_set_info);
DYLD_INTERPOSE(vmsw_task_terminate,          task_terminate);
DYLD_INTERPOSE(vmsw_task_set_exception_ports, task_set_exception_ports);
DYLD_INTERPOSE(vmsw_task_get_exception_ports, task_get_exception_ports);
DYLD_INTERPOSE(vmsw_thread_info,             thread_info);
DYLD_INTERPOSE(vmsw_thread_suspend,          thread_suspend);
DYLD_INTERPOSE(vmsw_thread_resume,           thread_resume);
DYLD_INTERPOSE(vmsw_thread_terminate,        thread_terminate);
DYLD_INTERPOSE(vmsw_mach_port_destroy,       mach_port_destroy);
DYLD_INTERPOSE(vmsw_vm_read,                 vm_read);
DYLD_INTERPOSE(vmsw_vm_read_overwrite,       vm_read_overwrite);
DYLD_INTERPOSE(vmsw_vm_write,                vm_write);
DYLD_INTERPOSE(vmsw_vm_protect,              vm_protect);
DYLD_INTERPOSE(vmsw_vm_allocate,             vm_allocate);
DYLD_INTERPOSE(vmsw_vm_deallocate,           vm_deallocate);
