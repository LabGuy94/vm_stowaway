#include "../include/vm_stowaway.h"

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <libgen.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf,1,2)));
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fputs("err: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

static void info(const char *fmt, ...) __attribute__((format(printf,1,2)));
static void info(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

#define ok(...) info(__VA_ARGS__)

/* parse 0x... or decimal */
static int parse_u64(const char *s, uint64_t *out) {
    char *end = NULL;
    errno = 0;
    *out = strtoull(s, &end, 0);
    if (errno || end == s || *end) return -1;
    return 0;
}

/* parse hex like "deadbeef" or "de ad be ef" into bytes */
static int parse_hex(const char *s, uint8_t **out, size_t *out_len) {
    size_t cap = strlen(s) / 2 + 1, used = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return -1;
    int hi = -1;
    for (const char *p = s; *p; p++) {
        if (isspace((unsigned char)*p)) continue;
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else { free(buf); return -1; }
        if (hi < 0) hi = v;
        else { buf[used++] = (hi << 4) | v; hi = -1; }
    }
    if (hi >= 0) { free(buf); return -1; }
    *out = buf; *out_len = used;
    return 0;
}

static void print_hex(const uint8_t *buf, size_t len, uint64_t base) {
    for (size_t i = 0; i < len; i += 16) {
        printf("%016llx  ", (unsigned long long)(base + i));
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", buf[i + j]);
            else             printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t b = buf[i + j];
            putchar((b >= 32 && b < 127) ? b : '.');
        }
        printf("|\n");
    }
}

static int cmd_patch(int argc, char **argv) {
    if (argc < 2) die("usage: vm_stowaway patch <bin> <install-name> [--weak] [--out PATH] [--no-sign]");
    const char *binary = argv[0];
    const char *payload = argv[1];
    vm_stowaway_patch_opts_t opts = { .resign = 1, .strip_existing_sig = 1 };
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--weak")) opts.weak = 1;
        else if (!strcmp(argv[i], "--no-sign")) opts.resign = 0;
        else if (!strcmp(argv[i], "--out") && i + 1 < argc) opts.out_path = argv[++i];
        else die("unknown flag: %s", argv[i]);
    }
    char err[512] = {0};
    info("patching %s -> add LC_LOAD_%sDYLIB %s",
         binary, opts.weak ? "WEAK_" : "", payload);
    if (vm_stowaway_patch(binary, payload, &opts, err, sizeof(err)) < 0)
        die("patch failed: %s", err);
    ok("patched%s", opts.resign ? " and re-signed ad-hoc" : "");
    return 0;
}

/* Connect to a target by pid. */
static vm_stowaway_t *attach_pid(pid_t pid, const char *sock) {
    char err[256];
    vm_stowaway_t *h = vm_stowaway_attach(pid, sock, 5, err, sizeof(err));
    if (!h) die("attach pid %d: %s", pid, err);
    return h;
}

static int cmd_read(int argc, char **argv) {
    if (argc < 3) die("usage: vm_stowaway read <pid> <addr> <len>");
    pid_t pid = (pid_t)atoi(argv[0]);
    uint64_t addr, len;
    if (parse_u64(argv[1], &addr) < 0) die("bad addr");
    if (parse_u64(argv[2], &len) < 0) die("bad len");
    vm_stowaway_t *h = attach_pid(pid, NULL);
    uint8_t *buf = malloc((size_t)len);
    if (!buf) die("oom");
    ssize_t got = vm_stowaway_read(h, addr, buf, (size_t)len);
    if (got < 0) die("read: %s", vm_stowaway_last_error(h));
    print_hex(buf, (size_t)got, addr);
    free(buf);
    vm_stowaway_close(h);
    return 0;
}

static int cmd_write(int argc, char **argv) {
    if (argc < 3) die("usage: vm_stowaway write <pid> <addr> <hex>");
    pid_t pid = (pid_t)atoi(argv[0]);
    uint64_t addr;
    if (parse_u64(argv[1], &addr) < 0) die("bad addr");
    uint8_t *bytes; size_t blen;
    if (parse_hex(argv[2], &bytes, &blen) < 0) die("bad hex bytes");
    vm_stowaway_t *h = attach_pid(pid, NULL);
    ssize_t w = vm_stowaway_write(h, addr, bytes, blen);
    if (w < 0) die("write: %s", vm_stowaway_last_error(h));
    ok("wrote %zd bytes to 0x%llx", w, (unsigned long long)addr);
    free(bytes);
    vm_stowaway_close(h);
    return 0;
}

static int cmd_regions(int argc, char **argv) {
    if (argc < 1) die("usage: vm_stowaway regions <pid>");
    pid_t pid = (pid_t)atoi(argv[0]);
    vm_stowaway_t *h = attach_pid(pid, NULL);

    size_t cap = 4096;
    vm_stowaway_region_t *buf = malloc(cap * sizeof(*buf));
    if (!buf) die("oom");
    ssize_t n = vm_stowaway_regions(h, buf, cap);
    if (n > (ssize_t)cap) {
        cap = (size_t)n;
        free(buf);
        buf = malloc(cap * sizeof(*buf));
        if (!buf) die("oom");
        n = vm_stowaway_regions(h, buf, cap);
    }
    if (n < 0) die("regions: %s", vm_stowaway_last_error(h));
    for (ssize_t i = 0; i < n; i++) {
        char p[4] = "---";
        if (buf[i].prot & 1) p[0] = 'r';
        if (buf[i].prot & 2) p[1] = 'w';
        if (buf[i].prot & 4) p[2] = 'x';
        printf("%016llx-%016llx %s  %llu\n",
               (unsigned long long)buf[i].base,
               (unsigned long long)(buf[i].base + buf[i].size),
               p,
               (unsigned long long)buf[i].size);
    }
    free(buf);
    vm_stowaway_close(h);
    return 0;
}

static int cmd_images(int argc, char **argv) {
    if (argc < 1) die("usage: vm_stowaway images <pid>");
    pid_t pid = (pid_t)atoi(argv[0]);
    vm_stowaway_t *h = attach_pid(pid, NULL);

    size_t cap = 1024;
    vm_stowaway_image_t *buf = malloc(cap * sizeof(*buf));
    if (!buf) die("oom");
    ssize_t n = vm_stowaway_images(h, buf, cap);
    if (n > (ssize_t)cap) {
        cap = (size_t)n;
        free(buf);
        buf = malloc(cap * sizeof(*buf));
        if (!buf) die("oom");
        n = vm_stowaway_images(h, buf, cap);
    }
    if (n < 0) die("images: %s", vm_stowaway_last_error(h));
    for (ssize_t i = 0; i < n; i++)
        printf("%016llx  slide=%016llx  %s\n",
               (unsigned long long)buf[i].base,
               (unsigned long long)buf[i].slide,
               buf[i].path);
    free(buf);
    vm_stowaway_close(h);
    return 0;
}

static int cmd_resolve(int argc, char **argv) {
    if (argc < 2) die("usage: vm_stowaway resolve <pid> [image] <symbol>");
    pid_t pid = (pid_t)atoi(argv[0]);
    const char *image = argc == 2 ? NULL : argv[1];
    const char *sym = argc == 2 ? argv[1] : argv[2];
    vm_stowaway_t *h = attach_pid(pid, NULL);
    uint64_t addr = vm_stowaway_resolve(h, image, sym);
    if (!addr) die("resolve: %s", vm_stowaway_last_error(h));
    printf("0x%016llx\n", (unsigned long long)addr);
    vm_stowaway_close(h);
    return 0;
}

static int cmd_scan(int argc, char **argv) {
    if (argc < 4) die("usage: vm_stowaway scan <pid> <start> <end> <hex-pat> [--mask HEX]");
    pid_t pid = (pid_t)atoi(argv[0]);
    uint64_t start, end;
    if (parse_u64(argv[1], &start) < 0) die("bad start");
    if (parse_u64(argv[2], &end) < 0) die("bad end");
    uint8_t *pat; size_t plen;
    if (parse_hex(argv[3], &pat, &plen) < 0) die("bad pattern");
    uint8_t *mask = NULL; size_t mlen = 0;
    for (int i = 4; i < argc; i++) {
        if (!strcmp(argv[i], "--mask") && i + 1 < argc) {
            if (parse_hex(argv[++i], &mask, &mlen) < 0) die("bad mask");
            if (mlen != plen) die("mask length must match pattern");
        } else die("unknown flag: %s", argv[i]);
    }
    vm_stowaway_t *h = attach_pid(pid, NULL);
    uint64_t hits[256];
    ssize_t n = vm_stowaway_scan(h, start, end, pat, mask, plen, hits, 256);
    if (n < 0) die("scan: %s", vm_stowaway_last_error(h));
    for (ssize_t i = 0; i < n && i < 256; i++)
        printf("0x%016llx\n", (unsigned long long)hits[i]);
    info("%zd hit(s)", n);
    free(pat);
    free(mask);
    vm_stowaway_close(h);
    return 0;
}

static void repl(vm_stowaway_t *h) {
    info("commands: r <addr> <len> | w <addr> <hex> | i | g <sym> | q");
    char line[1024];
    while (fputs("> ", stdout), fflush(stdout),
           fgets(line, sizeof(line), stdin)) {
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) continue;
        if (*p == 'q') break;
        if (*p == 'i') {
            vm_stowaway_image_t buf[8];
            ssize_t n = vm_stowaway_images(h, buf, 8);
            for (ssize_t i = 0; i < n && i < 8; i++) printf("  %s\n", buf[i].path);
            printf("  ... (%zd total)\n", n);
            continue;
        }
        if (*p == 'g') {
            char s[256];
            if (sscanf(p + 1, " %255s", s) != 1) { printf("usage: g <symbol>\n"); continue; }
            printf("%016llx\n", (unsigned long long)vm_stowaway_resolve(h, NULL, s));
            continue;
        }
        if (*p == 'r') {
            char as[64], ns[64];
            if (sscanf(p + 1, " %63s %63s", as, ns) != 2) {
                printf("usage: r <addr> <len>\n"); continue;
            }
            uint64_t a, n;
            if (parse_u64(as, &a) < 0 || parse_u64(ns, &n) < 0) {
                printf("bad number\n"); continue;
            }
            uint8_t *buf = malloc((size_t)n);
            ssize_t got = vm_stowaway_read(h, a, buf, (size_t)n);
            if (got < 0) printf("read failed: %s\n", vm_stowaway_last_error(h));
            else print_hex(buf, (size_t)got, a);
            free(buf);
            continue;
        }
        if (*p == 'w') {
            char as[64], hex[2048];
            if (sscanf(p + 1, " %63s %2047s", as, hex) != 2) {
                printf("usage: w <addr> <hex>\n"); continue;
            }
            uint64_t a;
            if (parse_u64(as, &a) < 0) { printf("bad addr\n"); continue; }
            uint8_t *b; size_t bl;
            if (parse_hex(hex, &b, &bl) < 0) { printf("bad hex\n"); continue; }
            ssize_t w = vm_stowaway_write(h, a, b, bl);
            if (w < 0) printf("write failed: %s\n", vm_stowaway_last_error(h));
            else printf("wrote %zd bytes\n", w);
            free(b);
            continue;
        }
        printf("unknown command\n");
    }
}

static int cmd_launch(int argc, char **argv) {
    if (argc < 1) die("usage: vm_stowaway launch <target> [args...]");
    char err[512] = {0};
    vm_stowaway_launch_opts_t opts = {0};
    vm_stowaway_t *h = vm_stowaway_launch(argv[0], argv, &opts, err, sizeof(err));
    if (!h) die("launch: %s", err);
    ok("launched pid %d, payload connected", vm_stowaway_pid(h));
    repl(h);
    vm_stowaway_close(h);
    return 0;
}

/* Try to find libvm_stowaway_machshim.dylib next to the CLI binary, then
 * one directory up, then in /usr/local/lib. */
static int default_shim_path(char *out, size_t outlen) {
    Dl_info info;
    if (dladdr((void *)default_shim_path, &info) && info.dli_fname) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s", info.dli_fname);
        char *dir = dirname(buf);
        if (dir) {
            snprintf(out, outlen, "%s/libvm_stowaway_machshim.dylib", dir);
            if (access(out, R_OK) == 0) return 0;
            snprintf(out, outlen, "%s/../libvm_stowaway_machshim.dylib", dir);
            if (access(out, R_OK) == 0) return 0;
        }
    }
    snprintf(out, outlen, "/usr/local/lib/libvm_stowaway_machshim.dylib");
    return access(out, R_OK) == 0 ? 0 : -1;
}

/* Run an external command via posix_spawnp. Returns 0 on success. */
static int run(const char *prog, char *const argv[]) {
    pid_t pid;
    int rc = posix_spawnp(&pid, prog, NULL, NULL, argv, environ);
    if (rc != 0) return rc;
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* Walk up from a path until we find a parent directory whose name ends in
 * ".app". Returns 0 and writes the bundle path into `out` (without trailing
 * slash), or -1 if no .app ancestor was found. */
static int find_app_bundle(const char *path, char *out, size_t outlen) {
    char buf[2048];
    snprintf(buf, sizeof(buf), "%s", path);
    while (1) {
        char *slash = strrchr(buf, '/');
        if (!slash) return -1;
        *slash = 0;
        size_t n = strlen(buf);
        if (n >= 4 && strcmp(buf + n - 4, ".app") == 0) {
            snprintf(out, outlen, "%s", buf);
            return 0;
        }
    }
}

/* Copy `src_app` to `dst_app`, clear xattrs, strip the existing signature,
 * re-sign ad-hoc without hardened runtime. Returns 0 on success. */
static int copy_and_unharden(const char *src_app, const char *dst_app,
                             char *errbuf, size_t errlen) {
    /* rm -rf dst (in case it exists from a prior run) */
    char *rm_argv[] = { "rm", "-rf", (char *)dst_app, NULL };
    if (run("rm", rm_argv) != 0)
        { snprintf(errbuf, errlen, "rm -rf %s failed", dst_app); return -1; }

    /* cp -R src dst */
    char *cp_argv[] = { "cp", "-R", (char *)src_app, (char *)dst_app, NULL };
    if (run("cp", cp_argv) != 0)
        { snprintf(errbuf, errlen, "cp -R failed"); return -1; }

    /* xattr -cr dst (clear quarantine + other extended attrs) */
    char *xattr_argv[] = { "xattr", "-cr", (char *)dst_app, NULL };
    run("xattr", xattr_argv);  /* ignore failure */

    /* codesign --remove-signature dst (may fail if no sig; that's ok) */
    char *cs_rm_argv[] = { "codesign", "--remove-signature", (char *)dst_app, NULL };
    run("codesign", cs_rm_argv);

    /* codesign --force --deep --sign - dst (no --options flag; ad-hoc with
     * --deep gives every nested framework the same empty team id, which
     * library validation accepts since they match). */
    char *cs_re_argv[] = { "codesign", "--force", "--deep", "--sign", "-",
                           (char *)dst_app, NULL };
    if (run("codesign", cs_re_argv) != 0)
        { snprintf(errbuf, errlen, "codesign re-sign failed"); return -1; }

    return 0;
}

static int cmd_wrap(int argc, char **argv) {
    pid_t target_pid = 0;
    const char *sock = NULL;
    const char *copy_dest = NULL;
    char shim[1024] = {0};
    int i = 0;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc) target_pid = (pid_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--sock") && i + 1 < argc) sock = argv[++i];
        else if (!strcmp(argv[i], "--shim") && i + 1 < argc) snprintf(shim, sizeof(shim), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--copy") && i + 1 < argc) copy_dest = argv[++i];
        else if (!strcmp(argv[i], "--")) { i++; break; }
        else break;
    }
    if (target_pid <= 0 || i >= argc)
        die("usage: vm_stowaway wrap --pid PID [--sock PATH] [--shim PATH] [--copy DEST.app] -- <tool> [args...]");

    if (!shim[0] && default_shim_path(shim, sizeof(shim)) < 0)
        die("can't find libvm_stowaway_machshim.dylib; pass --shim PATH");

    /* If --copy is set: find the .app bundle the tool lives inside, copy it
     * to the destination, ad-hoc resign without hardened runtime, then exec
     * the equivalent path inside the copy. This is the one-shot fix for
     * "App Management blocked codesign on the original" and for hardened
     * runtime stripping DYLD_INSERT_LIBRARIES at load time. */
    char exec_path[2048];
    snprintf(exec_path, sizeof(exec_path), "%s", argv[i]);

    if (copy_dest) {
        char src_app[2048];
        if (find_app_bundle(argv[i], src_app, sizeof(src_app)) < 0)
            die("--copy: %s isn't inside a .app bundle", argv[i]);

        info("copying %s -> %s and re-signing without hardened runtime",
             src_app, copy_dest);
        char err[256] = {0};
        if (copy_and_unharden(src_app, copy_dest, err, sizeof(err)) < 0)
            die("copy/sign: %s", err);

        /* Re-base the exec path inside the copy. */
        size_t slen = strlen(src_app);
        if (strncmp(argv[i], src_app, slen) != 0)
            die("internal: tool path doesn't start with bundle path");
        snprintf(exec_path, sizeof(exec_path), "%s%s",
                 copy_dest, argv[i] + slen);
        ok("ready: %s", exec_path);
    }

    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", target_pid);
    setenv("VM_STOWAWAY_TARGET_PID", pid_str, 1);
    if (sock) setenv("VM_STOWAWAY_SOCK", sock, 1);

    const char *existing = getenv("DYLD_INSERT_LIBRARIES");
    if (existing && *existing) {
        size_t n = strlen(existing) + 1 + strlen(shim) + 1;
        char *combined = malloc(n);
        snprintf(combined, n, "%s:%s", existing, shim);
        setenv("DYLD_INSERT_LIBRARIES", combined, 1);
        free(combined);
    } else {
        setenv("DYLD_INSERT_LIBRARIES", shim, 1);
    }

    info("wrap pid=%d shim=%s -> exec %s", target_pid, shim, exec_path);
    argv[i] = exec_path;
    execvp(exec_path, &argv[i]);
    die("exec %s: %s", exec_path, strerror(errno));
}

static int cmd_attach(int argc, char **argv) {
    if (argc < 1) die("usage: vm_stowaway attach <pid> [--sock PATH]");
    pid_t pid = (pid_t)atoi(argv[0]);
    const char *sock = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--sock") && i + 1 < argc) sock = argv[++i];
        else die("unknown flag: %s", argv[i]);
    }
    vm_stowaway_t *h = attach_pid(pid, sock);
    ok("attached to pid %d", pid);
    repl(h);
    vm_stowaway_close(h);
    return 0;
}

static void usage(void) {
    fputs(
        "usage: vm_stowaway <command> [args...]\n"
        "\n"
        "  launch  <target> [args...]              spawn target with payload via DYLD_INSERT_LIBRARIES\n"
        "  patch   <bin> <install-name>            add LC_LOAD_DYLIB to bin so payload loads on its own\n"
        "            [--weak] [--out PATH] [--no-sign]\n"
        "  wrap    --pid PID [--sock PATH] [--shim PATH] [--copy DEST.app] -- <tool> [args...]\n"
        "                                          launch <tool> with the mach shim DYLD_INSERTed\n"
        "  attach  <pid> [--sock PATH]             connect to a process that already has payload\n"
        "  read    <pid> <addr> <len>\n"
        "  write   <pid> <addr> <hex>\n"
        "  regions <pid>\n"
        "  images  <pid>\n"
        "  resolve <pid> [image] <symbol>\n"
        "  scan    <pid> <start> <end> <hex-pat> [--mask HEX]\n",
        stdout);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];
    int sub_argc = argc - 2;
    char **sub_argv = argv + 2;

    if (!strcmp(cmd, "launch"))   return cmd_launch(sub_argc, sub_argv);
    if (!strcmp(cmd, "patch"))    return cmd_patch(sub_argc, sub_argv);
    if (!strcmp(cmd, "wrap"))     return cmd_wrap(sub_argc, sub_argv);
    if (!strcmp(cmd, "attach"))   return cmd_attach(sub_argc, sub_argv);
    if (!strcmp(cmd, "read"))     return cmd_read(sub_argc, sub_argv);
    if (!strcmp(cmd, "write"))    return cmd_write(sub_argc, sub_argv);
    if (!strcmp(cmd, "regions"))  return cmd_regions(sub_argc, sub_argv);
    if (!strcmp(cmd, "images"))   return cmd_images(sub_argc, sub_argv);
    if (!strcmp(cmd, "resolve"))  return cmd_resolve(sub_argc, sub_argv);
    if (!strcmp(cmd, "scan"))     return cmd_scan(sub_argc, sub_argv);
    if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help")) { usage(); return 0; }
    fprintf(stderr, "unknown command: %s\n", cmd);
    usage();
    return 1;
}
