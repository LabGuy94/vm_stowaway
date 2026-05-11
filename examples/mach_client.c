/*
 * Tiny stand-in for a memory-inspection tool that exercises every mach
 * API the vm_stowaway shim interposes. Run it under the shim and it
 * should read + write the target's memory and walk threads / allocate /
 * inspect task info, all without holding a task_for_pid entitlement.
 *
 * usage: mach_client <pid> <addr> <len> [hex-to-write]
 */

#include <ctype.h>
#include <inttypes.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__arm64__)
#  include <mach/arm/thread_state.h>
#  define TS_FLAVOR ARM_THREAD_STATE64
#  define TS_COUNT  ARM_THREAD_STATE64_COUNT
typedef arm_thread_state64_t ts_t;
static uint64_t ts_pc(const ts_t *s) { return __darwin_arm_thread_state64_get_pc(*s); }
#elif defined(__x86_64__)
#  include <mach/i386/thread_state.h>
#  define TS_FLAVOR x86_THREAD_STATE64
#  define TS_COUNT  x86_THREAD_STATE64_COUNT
typedef x86_thread_state64_t ts_t;
static uint64_t ts_pc(const ts_t *s) { return s->__rip; }
#endif

static int parse_hex(const char *s, uint8_t *out, size_t cap, size_t *out_len) {
    int hi = -1;
    *out_len = 0;
    for (const char *p = s; *p; p++) {
        if (isspace((unsigned char)*p)) continue;
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else return -1;
        if (hi < 0) hi = v;
        else {
            if (*out_len >= cap) return -1;
            out[(*out_len)++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    return hi >= 0 ? -1 : 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <pid> <addr> <len> [hex-to-write]\n", argv[0]);
        return 1;
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    mach_vm_address_t addr = (mach_vm_address_t)strtoull(argv[2], NULL, 0);
    mach_vm_size_t    len  = (mach_vm_size_t)   strtoull(argv[3], NULL, 0);

    task_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid: %s\n", mach_error_string(kr));
        return 1;
    }
    printf("task_for_pid(%d) -> 0x%x\n", pid, task);

    /* --- read + (optionally) write the requested address --- */
    uint8_t *buf = malloc((size_t)len);
    mach_vm_size_t got = 0;
    kr = mach_vm_read_overwrite(task, addr, len, (mach_vm_address_t)(uintptr_t)buf, &got);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "mach_vm_read_overwrite: %s\n", mach_error_string(kr));
        return 1;
    }
    printf("read %llu bytes from 0x%llx:\n", got, addr);
    for (mach_vm_size_t i = 0; i < got; i++)
        printf("%02x%s", buf[i], (i + 1) % 16 == 0 ? "\n" : " ");
    if (got % 16) putchar('\n');
    free(buf);

    if (argc > 4) {
        uint8_t wbuf[256];
        size_t wlen = 0;
        if (parse_hex(argv[4], wbuf, sizeof(wbuf), &wlen) < 0) {
            fprintf(stderr, "bad hex\n"); return 1;
        }
        kr = mach_vm_write(task, addr, (vm_offset_t)(uintptr_t)wbuf, (mach_msg_type_number_t)wlen);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "mach_vm_write: %s\n", mach_error_string(kr)); return 1;
        }
        printf("wrote %zu bytes to 0x%llx\n", wlen, addr);
    }

    /* --- region walk (exercises mach_vm_region_recurse) --- */
    mach_vm_address_t walk = 0;
    for (int n = 0; n < 3; n++) {
        mach_vm_size_t sz = 0;
        natural_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        kr = mach_vm_region_recurse(task, &walk, &sz, &depth,
                                    (vm_region_recurse_info_t)&info, &cnt);
        if (kr != KERN_SUCCESS) break;
        printf("region: 0x%016llx-0x%016llx prot=%d\n",
               walk, walk + sz, info.protection);
        walk += sz;
    }

    /* --- task_info(TASK_DYLD_INFO) --- */
    struct task_dyld_info di;
    mach_msg_type_number_t dcnt = TASK_DYLD_INFO_COUNT;
    kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&di, &dcnt);
    if (kr == KERN_SUCCESS)
        printf("dyld_all_image_infos @ 0x%llx (size=%llu format=%d)\n",
               (unsigned long long)di.all_image_info_addr,
               (unsigned long long)di.all_image_info_size,
               di.all_image_info_format);
    else
        printf("task_info(TASK_DYLD_INFO) failed: %s\n", mach_error_string(kr));

    /* --- task_info(TASK_BASIC_INFO_64) --- */
    task_basic_info_64_data_t bi;
    mach_msg_type_number_t bcnt = TASK_BASIC_INFO_64_COUNT;
    kr = task_info(task, TASK_BASIC_INFO_64, (task_info_t)&bi, &bcnt);
    if (kr == KERN_SUCCESS)
        printf("task_basic_info: vsz=%llu rsz=%llu\n",
               (unsigned long long)bi.virtual_size,
               (unsigned long long)bi.resident_size);

    /* --- task_threads + thread_get_state --- */
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t tcount = 0;
    kr = task_threads(task, &threads, &tcount);
    if (kr == KERN_SUCCESS) {
        printf("task_threads: %u thread%s\n", tcount, tcount == 1 ? "" : "s");
        for (mach_msg_type_number_t i = 0; i < tcount && i < 3; i++) {
            ts_t state = {0};
            mach_msg_type_number_t scnt = TS_COUNT;
            kern_return_t skr = thread_get_state(threads[i], TS_FLAVOR,
                                                 (thread_state_t)&state, &scnt);
            if (skr == KERN_SUCCESS)
                printf("  thread %u port=0x%x pc=0x%llx\n",
                       i, threads[i], (unsigned long long)ts_pc(&state));
            else
                printf("  thread %u thread_get_state failed: %s\n",
                       i, mach_error_string(skr));
            mach_port_deallocate(mach_task_self(), threads[i]);
        }
        if (threads)
            mach_vm_deallocate(mach_task_self(),
                               (mach_vm_address_t)(uintptr_t)threads,
                               tcount * sizeof(thread_act_t));
    } else {
        printf("task_threads failed: %s\n", mach_error_string(kr));
    }

    /* --- allocate / write / read / deallocate cycle in target --- */
    mach_vm_address_t mine = 0;
    kr = mach_vm_allocate(task, &mine, 64, VM_FLAGS_ANYWHERE);
    if (kr == KERN_SUCCESS) {
        const uint8_t payload[] = "vm_stowaway round-trip";
        mach_vm_write(task, mine, (vm_offset_t)(uintptr_t)payload, sizeof(payload));
        char back[64] = {0};
        mach_vm_size_t bgot = 0;
        mach_vm_read_overwrite(task, mine, sizeof(payload),
                               (mach_vm_address_t)(uintptr_t)back, &bgot);
        printf("alloc/rt: addr=0x%llx read=\"%s\"\n",
               (unsigned long long)mine, back);
        mach_vm_deallocate(task, mine, 64);
    } else {
        printf("mach_vm_allocate failed: %s\n", mach_error_string(kr));
    }

    mach_port_deallocate(mach_task_self(), task);
    return 0;
}
