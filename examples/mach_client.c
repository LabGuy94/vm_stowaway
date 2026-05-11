/*
 * Tiny stand-in for a memory-inspection tool that exercises exactly the
 * mach APIs vm_stowaway's shim interposes. Run it under the shim and it
 * should read + write the target's memory without ever holding a
 * task_for_pid entitlement.
 *
 * usage: mach_client <pid> <addr> <len> [hex-to-write]
 */

#include <inttypes.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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

    uint8_t *buf = malloc((size_t)len);
    mach_vm_size_t got = 0;
    kr = mach_vm_read_overwrite(task, addr, len, (mach_vm_address_t)(uintptr_t)buf, &got);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "mach_vm_read_overwrite: %s\n", mach_error_string(kr));
        return 1;
    }
    printf("read %llu bytes from 0x%llx:\n", got, addr);
    for (mach_vm_size_t i = 0; i < got; i++) {
        printf("%02x%s", buf[i], (i + 1) % 16 == 0 ? "\n" : " ");
    }
    if (got % 16) putchar('\n');
    free(buf);

    if (argc > 4) {
        uint8_t wbuf[256];
        size_t wlen = 0;
        if (parse_hex(argv[4], wbuf, sizeof(wbuf), &wlen) < 0) {
            fprintf(stderr, "bad hex\n");
            return 1;
        }
        kr = mach_vm_write(task, addr, (vm_offset_t)(uintptr_t)wbuf, (mach_msg_type_number_t)wlen);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "mach_vm_write: %s\n", mach_error_string(kr));
            return 1;
        }
        printf("wrote %zu bytes to 0x%llx\n", wlen, addr);
    }

    /* Walk a few regions to exercise mach_vm_region_recurse. */
    mach_vm_address_t walk = 0;
    int n = 0;
    while (n < 5) {
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
        n++;
    }

    mach_port_deallocate(mach_task_self(), task);
    return 0;
}
