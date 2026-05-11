/* System-wide AMFI / library-validation toggles. These poke NVRAM and
 * /Library/Preferences, both of which are SIP-protected -- callers need
 * SIP off and root. The actual mechanics are stable across macOS 11..15. */

#define _DARWIN_C_SOURCE

#include "../include/vm_stowaway.h"

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void sc_seterr(char *errbuf, size_t errlen, const char *fmt, ...) {
    if (!errbuf || !errlen) return;
    va_list ap; va_start(ap, fmt);
    vsnprintf(errbuf, errlen, fmt, ap);
    va_end(ap);
}

/* Run `prog argv...`, captured stdout into `out` (truncated to outlen-1).
 * Returns the exit code, or -1 on spawn failure. */
static int run_capture(const char *prog, char *const argv[],
                       char *out, size_t outlen) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, pipefd[1], 1);
    posix_spawn_file_actions_addclose(&fa, pipefd[0]);
    posix_spawn_file_actions_addclose(&fa, pipefd[1]);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);

    pid_t pid;
    int rc = posix_spawnp(&pid, prog, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(pipefd[1]);
    if (rc != 0) { close(pipefd[0]); return -1; }

    size_t got = 0;
    if (out && outlen > 1) {
        ssize_t r;
        while (got + 1 < outlen &&
               (r = read(pipefd[0], out + got, outlen - 1 - got)) > 0)
            got += (size_t)r;
        out[got] = 0;
        /* drain anything that didn't fit */
        char drop[256];
        while (read(pipefd[0], drop, sizeof(drop)) > 0) {}
    }
    close(pipefd[0]);

    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int run_quiet(const char *prog, char *const argv[]) {
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    pid_t pid;
    int rc = posix_spawnp(&pid, prog, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) return -1;
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* Parse `nvram boot-args` output: "boot-args\t<value>\n". Writes the value
 * portion into `out`. Returns 0 if the key exists, 1 if not, -1 on error. */
static int read_bootargs(char *out, size_t outlen) {
    char buf[2048];
    char *argv[] = { "nvram", "boot-args", NULL };
    int rc = run_capture("nvram", argv, buf, sizeof(buf));
    if (rc != 0) {
        out[0] = 0;
        return 1;  /* not present (or nvram failed) */
    }
    /* buf looks like "boot-args\tval\n" */
    char *tab = strchr(buf, '\t');
    if (!tab) { out[0] = 0; return 1; }
    char *nl = strchr(tab + 1, '\n');
    if (nl) *nl = 0;
    snprintf(out, outlen, "%s", tab + 1);
    return 0;
}

static int bootargs_has_token(const char *bootargs, const char *token) {
    /* token bounded by start/space/= or end. */
    size_t tlen = strlen(token);
    const char *p = bootargs;
    while ((p = strstr(p, token))) {
        int left_ok  = (p == bootargs) || p[-1] == ' ';
        char rc = p[tlen];
        int right_ok = (rc == 0) || rc == ' ' || rc == '=';
        if (left_ok && right_ok) return 1;
        p += tlen;
    }
    return 0;
}

/* Remove every occurrence of `token` (and an optional =<value> tail) from
 * `bootargs`, in place. Collapses runs of spaces. */
static void bootargs_remove_token(char *bootargs, const char *token) {
    size_t tlen = strlen(token);
    char *p = bootargs;
    while ((p = strstr(p, token))) {
        int left_ok  = (p == bootargs) || p[-1] == ' ';
        char rc = p[tlen];
        int right_ok = (rc == 0) || rc == ' ' || rc == '=';
        if (!left_ok || !right_ok) { p += tlen; continue; }
        char *end = p + tlen;
        /* eat =<value> if present */
        if (*end == '=') {
            while (*end && *end != ' ') end++;
        }
        /* eat the separating space too, if present */
        if (*end == ' ') end++;
        else if (p > bootargs && p[-1] == ' ') p--;
        memmove(p, end, strlen(end) + 1);
    }
    /* trim trailing/leading whitespace */
    size_t L = strlen(bootargs);
    while (L > 0 && bootargs[L - 1] == ' ') bootargs[--L] = 0;
    size_t i = 0;
    while (bootargs[i] == ' ') i++;
    if (i) memmove(bootargs, bootargs + i, strlen(bootargs + i) + 1);
}

int vm_stowaway_amfi_bypass_get(char *errbuf, size_t errlen) {
    (void)errbuf; (void)errlen;
    char ba[2048];
    int rc = read_bootargs(ba, sizeof(ba));
    if (rc < 0) return -1;
    return bootargs_has_token(ba, "amfi_get_out_of_my_way") ? 1 : 0;
}

int vm_stowaway_amfi_bypass_set(int enable, char *errbuf, size_t errlen) {
    char ba[2048];
    read_bootargs(ba, sizeof(ba));  /* "" if absent */
    bootargs_remove_token(ba, "amfi_get_out_of_my_way");

    char new_args[2200];
    if (enable) {
        if (ba[0])
            snprintf(new_args, sizeof(new_args), "%s amfi_get_out_of_my_way=1", ba);
        else
            snprintf(new_args, sizeof(new_args), "amfi_get_out_of_my_way=1");
    } else {
        snprintf(new_args, sizeof(new_args), "%s", ba);
    }

    if (!new_args[0]) {
        char *argv[] = { "nvram", "-d", "boot-args", NULL };
        if (run_quiet("nvram", argv) != 0) {
            sc_seterr(errbuf, errlen, "nvram -d boot-args failed (need root + SIP off)");
            return -1;
        }
        return 0;
    }

    char kv[2400];
    snprintf(kv, sizeof(kv), "boot-args=%s", new_args);
    char *argv[] = { "nvram", kv, NULL };
    if (run_quiet("nvram", argv) != 0) {
        sc_seterr(errbuf, errlen,
                  "nvram boot-args=... failed (need root + SIP off; on Apple "
                  "Silicon also Reduced Security policy)");
        return -1;
    }
    return 0;
}

#define LIBVAL_PLIST \
    "/Library/Preferences/com.apple.security.libraryvalidation"
#define LIBVAL_KEY "DisableLibraryValidation"

int vm_stowaway_libval_disable_get(char *errbuf, size_t errlen) {
    (void)errbuf; (void)errlen;
    char *argv[] = { "defaults", "read", LIBVAL_PLIST, LIBVAL_KEY, NULL };
    char out[64] = {0};
    int rc = run_capture("defaults", argv, out, sizeof(out));
    if (rc != 0) return 0;
    /* trim */
    size_t L = strlen(out);
    while (L > 0 && (out[L-1] == '\n' || out[L-1] == ' ')) out[--L] = 0;
    return (strcmp(out, "1") == 0 || strcasecmp(out, "true") == 0) ? 1 : 0;
}

int vm_stowaway_libval_disable_set(int disable, char *errbuf, size_t errlen) {
    if (disable) {
        char *argv[] = { "defaults", "write", LIBVAL_PLIST,
                         LIBVAL_KEY, "-bool", "true", NULL };
        if (run_quiet("defaults", argv) != 0) {
            sc_seterr(errbuf, errlen,
                      "defaults write %s.plist %s failed (need root + SIP off)",
                      LIBVAL_PLIST, LIBVAL_KEY);
            return -1;
        }
    } else {
        char *argv[] = { "defaults", "delete", LIBVAL_PLIST, LIBVAL_KEY, NULL };
        run_quiet("defaults", argv);
    }
    return 0;
}
