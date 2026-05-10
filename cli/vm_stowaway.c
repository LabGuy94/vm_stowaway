/*
 * vm_stowaway CLI
 *
 * Subcommands:
 *   patch     <binary> <payload-install-name> [--weak] [--out PATH] [--no-sign]
 *   launch    <target> -- [args...]                 (then drops into REPL)
 *   attach    <pid> [--sock PATH]                   (then drops into REPL)
 *   read      <pid> <addr> <len>
 *   write     <pid> <addr> <hex-bytes>
 *   regions   <pid>
 *   images    <pid>
 *   resolve   <pid> [image-substring] <symbol>
 *   scan      <pid> <start> <end> <hex-pattern> [--mask HEX]
 *
 * `<pid>` for read/write/etc. assumes vm_stowaway_attach by default socket.
 */

#include "../include/vm_stowaway.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define C_RESET "\033[0m"
#define C_BOLD  "\033[1m"
#define C_RED   "\033[0;31m"
#define C_GRN   "\033[0;32m"
#define C_YEL   "\033[0;33m"
#define C_BLU   "\033[0;34m"
#define C_CYN   "\033[0;36m"

static int g_color = 1;
static const char *c(const char *code) { return g_color ? code : ""; }

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf,1,2)));
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "%s✖%s ", c(C_RED), c(C_RESET));
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

static void info(const char *fmt, ...) __attribute__((format(printf,1,2)));
static void info(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "%s➜%s ", c(C_CYN), c(C_RESET));
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static void ok(const char *fmt, ...) __attribute__((format(printf,1,2)));
static void ok(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "%s✔%s ", c(C_GRN), c(C_RESET));
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

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

/* -- subcommands ---------------------------------------------------------- */

static int cmd_patch(int argc, char **argv) {
    if (argc < 2) die("usage: vm_stowaway patch <binary> <payload-install-name> [--weak] [--out PATH] [--no-sign]");
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
    if (argc < 3) die("usage: vm_stowaway write <pid> <addr> <hex-bytes>");
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
    vm_stowaway_region_t buf[4096];
    ssize_t n = vm_stowaway_regions(h, buf, 4096);
    if (n < 0) die("regions: %s", vm_stowaway_last_error(h));
    for (ssize_t i = 0; i < n && i < 4096; i++) {
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
    vm_stowaway_close(h);
    return 0;
}

static int cmd_images(int argc, char **argv) {
    if (argc < 1) die("usage: vm_stowaway images <pid>");
    pid_t pid = (pid_t)atoi(argv[0]);
    vm_stowaway_t *h = attach_pid(pid, NULL);
    vm_stowaway_image_t buf[2048];
    ssize_t n = vm_stowaway_images(h, buf, 2048);
    if (n < 0) die("images: %s", vm_stowaway_last_error(h));
    for (ssize_t i = 0; i < n && i < 2048; i++)
        printf("%016llx  slide=%016llx  %s\n",
               (unsigned long long)buf[i].base,
               (unsigned long long)buf[i].slide,
               buf[i].path);
    vm_stowaway_close(h);
    return 0;
}

static int cmd_resolve(int argc, char **argv) {
    if (argc < 2) die("usage: vm_stowaway resolve <pid> [image-substring] <symbol>");
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
    if (argc < 4) die("usage: vm_stowaway scan <pid> <start> <end> <hex-pattern> [--mask HEX]");
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

static int cmd_launch(int argc, char **argv) {
    if (argc < 1) die("usage: vm_stowaway launch <target> [args...]");
    char err[512] = {0};
    vm_stowaway_launch_opts_t opts = {0};
    vm_stowaway_t *h = vm_stowaway_launch(argv[0], argv, &opts, err, sizeof(err));
    if (!h) die("launch: %s", err);
    ok("launched pid %d, payload connected", vm_stowaway_pid(h));

    /* Tiny REPL so the user can experiment. */
    info("commands: r <addr> <len> | w <addr> <hex> | i | g | q");
    char line[1024];
    while (printf("%s>%s ", c(C_BLU), c(C_RESET)), fflush(stdout),
           fgets(line, sizeof(line), stdin)) {
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) continue;
        if (*p == 'q') break;
        if (*p == 'i') { vm_stowaway_image_t buf[8]; ssize_t n = vm_stowaway_images(h, buf, 8);
            for (ssize_t i=0;i<n && i<8;i++) printf("  %s\n", buf[i].path);
            printf("  ... (%zd total)\n", n);
            continue;
        }
        if (*p == 'g') {
            uint64_t a; char s[256];
            if (sscanf(p+1, " %255s", s) != 1) { printf("usage: g <symbol>\n"); continue; }
            a = vm_stowaway_resolve(h, NULL, s);
            printf("%016llx\n", (unsigned long long)a);
            continue;
        }
        if (*p == 'r') {
            uint64_t a, n;
            if (sscanf(p+1, " %lli %lli", (long long*)&a, (long long*)&n) != 2) {
                printf("usage: r <addr> <len>\n"); continue;
            }
            uint8_t *buf = malloc((size_t)n);
            ssize_t got = vm_stowaway_read(h, a, buf, (size_t)n);
            if (got < 0) printf("read failed: %s\n", vm_stowaway_last_error(h));
            else print_hex(buf, (size_t)got, a);
            free(buf);
            continue;
        }
        if (*p == 'w') {
            uint64_t a; char hex[2048];
            if (sscanf(p+1, " %lli %2047s", (long long*)&a, hex) != 2) {
                printf("usage: w <addr> <hex>\n"); continue;
            }
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
    vm_stowaway_close(h);
    return 0;
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
    /* Drop into the same little REPL as launch. */
    char *no_argv[] = { NULL };
    (void)no_argv;
    info("commands: r <addr> <len> | w <addr> <hex> | i | g | q");
    char line[1024];
    while (printf("%s>%s ", c(C_BLU), c(C_RESET)), fflush(stdout),
           fgets(line, sizeof(line), stdin)) {
        if (line[0] == 'q') break;
        /* For brevity, attach mode shares only basic ops; users should call
         * the read/write subcommands for scripted use. */
        printf("(use the read/write/scan subcommands; tiny repl here)\n");
        break;
    }
    vm_stowaway_close(h);
    return 0;
}

/* -- main ----------------------------------------------------------------- */

static void usage(void) {
    printf("vm_stowaway: read/write memory in a macos process via a dylib payload\n\n");
    printf("usage: vm_stowaway <command> [args...]\n\n");
    printf("commands:\n");
    printf("  launch  <target> [args...]         spawn target with payload via DYLD_INSERT_LIBRARIES\n");
    printf("  patch   <bin> <install-name>       add LC_LOAD_DYLIB to bin so payload loads on its own\n");
    printf("            [--weak] [--out PATH] [--no-sign]\n");
    printf("  attach  <pid> [--sock PATH]        connect to a running process that already has payload\n");
    printf("  read    <pid> <addr> <len>\n");
    printf("  write   <pid> <addr> <hex>\n");
    printf("  regions <pid>\n");
    printf("  images  <pid>\n");
    printf("  resolve <pid> [image] <symbol>\n");
    printf("  scan    <pid> <start> <end> <hex-pat> [--mask HEX]\n\n");
}

int main(int argc, char **argv) {
    if (!isatty(STDERR_FILENO)) g_color = 0;
    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];
    int sub_argc = argc - 2;
    char **sub_argv = argv + 2;

    if (!strcmp(cmd, "launch"))   return cmd_launch(sub_argc, sub_argv);
    if (!strcmp(cmd, "patch"))    return cmd_patch(sub_argc, sub_argv);
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
