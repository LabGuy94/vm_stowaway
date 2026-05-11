/* smoke-test controller: launch target, read/write its globals, verify. */

#include "../include/vm_stowaway.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <target-path> [target args...]\n", argv[0]); return 1; }

    char err[256] = {0};
    vm_stowaway_launch_opts_t opts = { .connect_timeout_s = 5 };
    vm_stowaway_t *h = vm_stowaway_launch(argv[1], argv + 1, &opts, err, sizeof(err));
    if (!h) { fprintf(stderr, "launch failed: %s\n", err); return 1; }
    fprintf(stderr, "[ctrl] launched pid %d\n", vm_stowaway_pid(h));

    uint64_t addr_secret  = vm_stowaway_resolve(h, NULL, "secret");
    uint64_t addr_message = vm_stowaway_resolve(h, NULL, "message");
    if (!addr_secret || !addr_message) {
        fprintf(stderr, "resolve: %s\n", vm_stowaway_last_error(h));
        vm_stowaway_close(h);
        return 1;
    }
    fprintf(stderr, "[ctrl] secret @ %#llx, message @ %#llx\n",
            (unsigned long long)addr_secret, (unsigned long long)addr_message);

    int  before_secret = 0;
    char before_msg[64] = {0};
    vm_stowaway_read(h, addr_secret,  &before_secret, sizeof(before_secret));
    vm_stowaway_read(h, addr_message, before_msg,    sizeof(before_msg));
    fprintf(stderr, "[ctrl] before: secret=%d message=%s\n", before_secret, before_msg);

    int  new_secret = 1337;
    const char new_msg[] = "rewritten from outside";
    vm_stowaway_write(h, addr_secret,  &new_secret, sizeof(new_secret));
    vm_stowaway_write(h, addr_message, new_msg,     sizeof(new_msg));

    int  after_secret = 0;
    char after_msg[64] = {0};
    vm_stowaway_read(h, addr_secret,  &after_secret, sizeof(after_secret));
    vm_stowaway_read(h, addr_message, after_msg,     sizeof(after_msg));
    fprintf(stderr, "[ctrl] after:  secret=%d message=%s\n", after_secret, after_msg);

    int rc = (after_secret == new_secret && strcmp(after_msg, new_msg) == 0) ? 0 : 1;
    vm_stowaway_close(h);
    return rc;
}
