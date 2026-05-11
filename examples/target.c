/* smoke-test target: print a couple of globals each second. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int  secret  = 42;
char message[64] = "hello from the target";

__attribute__((visibility("default"))) int  *get_secret(void)  { return &secret; }
__attribute__((visibility("default"))) char *get_message(void) { return message; }

int main(int argc, char **argv) {
    int loops = argc > 1 ? atoi(argv[1]) : 30;
    setvbuf(stdout, NULL, _IOLBF, 0);
    for (int i = 0; i < loops; i++) {
        printf("[target %d] secret=%d message=%s\n", getpid(), secret, message);
        sleep(1);
    }
    return 0;
}
