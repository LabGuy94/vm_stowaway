/* attach to a running, payload-loaded process and invoke a function inside it.
 * the target must already have the payload loaded (e.g. via `vm_stowaway patch`
 * or LC_LOAD_DYLIB on disk). */

#include "../include/vm_stowaway.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <pid|name>\n", argv[0]);
        return 1;
    }

    pid_t pid = (pid_t)atoi(argv[1]);
    if (pid <= 0) {
        pid = vm_stowaway_find_pid(argv[1]);
        if (pid <= 0) { fprintf(stderr, "no process matching %s\n", argv[1]); return 1; }
    }

    char err[256] = {0};
    vm_stowaway_t *h = vm_stowaway_attach(pid, NULL, 5, err, sizeof err);
    if (!h) { fprintf(stderr, "attach: %s\n", err); return 1; }

    uint32_t proto = 0; uint64_t remote_pid = 0;
    vm_stowaway_remote_info(h, &proto, &remote_pid);
    fprintf(stderr, "attached pid=%llu (payload proto v%u)\n",
            (unsigned long long)remote_pid, proto);

    uint64_t getpid_addr = vm_stowaway_resolve(h, "libsystem_c", "getpid");
    if (!getpid_addr) {
        fprintf(stderr, "resolve getpid: %s\n", vm_stowaway_last_error(h));
        vm_stowaway_close(h);
        return 1;
    }

    uint64_t ret = 0;
    if (vm_stowaway_call(h, getpid_addr, NULL, 0, &ret) < 0) {
        fprintf(stderr, "call getpid: %s\n", vm_stowaway_last_error(h));
        vm_stowaway_close(h);
        return 1;
    }
    printf("target's getpid() -> %llu (expected %d)\n",
           (unsigned long long)ret, pid);

    vm_stowaway_close(h);
    return ret == (uint64_t)pid ? 0 : 1;
}
