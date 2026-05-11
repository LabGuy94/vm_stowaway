#include "../include/vm_stowaway.h"

#include <ctype.h>
#include <dirent.h>
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
#include <sys/stat.h>
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

/* Connect helpers. A "target" is either a numeric pid or a process name. */
static vm_stowaway_t *attach_pid(pid_t pid, const char *sock);

static vm_stowaway_t *attach_target(const char *target, const char *sock) {
    char *end = NULL;
    errno = 0;
    long v = strtol(target, &end, 10);
    if (!errno && end != target && *end == 0) return attach_pid((pid_t)v, sock);
    pid_t pid = vm_stowaway_find_pid(target);
    if (pid <= 0) {
        fprintf(stderr, "err: no process named %s\n", target);
        exit(1);
    }
    return attach_pid(pid, sock);
}

/* Parse an address spec: "0x..." / decimal, or "ImageSubstr+0xN" / "Image+N".
 * For image-relative parses, queries `h` for images to resolve the base. */
static int parse_addr(vm_stowaway_t *h, const char *s, uint64_t *out) {
    const char *plus = strchr(s, '+');
    if (!plus) return parse_u64(s, out);

    size_t namelen = (size_t)(plus - s);
    char name[256];
    if (namelen >= sizeof(name)) return -1;
    memcpy(name, s, namelen);
    name[namelen] = 0;

    uint64_t off;
    if (parse_u64(plus + 1, &off) < 0) return -1;

    vm_stowaway_image_t buf[1024];
    ssize_t n = vm_stowaway_images(h, buf, 1024);
    if (n < 0) return -1;
    if (n > 1024) n = 1024;
    for (ssize_t i = 0; i < n; i++) {
        if (strstr(buf[i].path, name)) { *out = buf[i].base + off; return 0; }
    }
    return -1;
}

/* Cache loaded images for --syms annotation. */
struct image_cache {
    vm_stowaway_image_t *v;
    ssize_t n;
};

static int load_images(vm_stowaway_t *h, struct image_cache *out) {
    size_t cap = 1024;
    vm_stowaway_image_t *buf = malloc(cap * sizeof(*buf));
    if (!buf) return -1;
    ssize_t n = vm_stowaway_images(h, buf, cap);
    if (n > (ssize_t)cap) {
        cap = (size_t)n;
        free(buf);
        buf = malloc(cap * sizeof(*buf));
        if (!buf) return -1;
        n = vm_stowaway_images(h, buf, cap);
    }
    if (n < 0) { free(buf); return -1; }
    out->v = buf;
    out->n = n;
    return 0;
}

/* Best-effort: return image whose base <= addr < base+0x10000000.
 * (We don't know image sizes; cap the lookback to something plausible.) */
static const vm_stowaway_image_t *image_for(const struct image_cache *ic,
                                            uint64_t addr) {
    const vm_stowaway_image_t *best = NULL;
    uint64_t best_off = UINT64_MAX;
    for (ssize_t i = 0; i < ic->n; i++) {
        if (addr < ic->v[i].base) continue;
        uint64_t off = addr - ic->v[i].base;
        if (off < best_off && off < 0x10000000ull) {
            best = &ic->v[i];
            best_off = off;
        }
    }
    return best;
}

static void json_string(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p == '\n') fputs("\\n", stdout);
        else if (*p == '\r') fputs("\\r", stdout);
        else if (*p == '\t') fputs("\\t", stdout);
        else if (*p < 0x20)  printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
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

/* Hex dump with pointer-sized words annotated when they point inside an image. */
static void print_hex_syms(const uint8_t *buf, size_t len, uint64_t base,
                           const struct image_cache *ic) {
    print_hex(buf, len, base);
    for (size_t i = 0; i + 8 <= len; i += 8) {
        uint64_t w;
        memcpy(&w, buf + i, sizeof(w));
        const vm_stowaway_image_t *im = image_for(ic, w);
        if (!im) continue;
        const char *bname = strrchr(im->path, '/');
        bname = bname ? bname + 1 : im->path;
        printf("  +%04zx -> %s+0x%llx\n", i, bname,
               (unsigned long long)(w - im->base));
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
    if (argc < 3) die("usage: vm_stowaway read <target> <addr> <len> [--syms]");
    int want_syms = 0;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--syms")) want_syms = 1;
        else die("unknown flag: %s", argv[i]);
    }
    vm_stowaway_t *h = attach_target(argv[0], NULL);
    uint64_t addr, len;
    if (parse_addr(h, argv[1], &addr) < 0) die("bad addr");
    if (parse_u64(argv[2], &len) < 0) die("bad len");
    uint8_t *buf = malloc((size_t)len);
    if (!buf) die("oom");
    ssize_t got = vm_stowaway_read(h, addr, buf, (size_t)len);
    if (got < 0) die("read: %s", vm_stowaway_last_error(h));
    if (want_syms) {
        struct image_cache ic = {0};
        if (load_images(h, &ic) < 0) die("images: %s", vm_stowaway_last_error(h));
        print_hex_syms(buf, (size_t)got, addr, &ic);
        free(ic.v);
    } else {
        print_hex(buf, (size_t)got, addr);
    }
    free(buf);
    vm_stowaway_close(h);
    return 0;
}

static int cmd_write(int argc, char **argv) {
    if (argc < 3) die("usage: vm_stowaway write <target> <addr> <hex>");
    vm_stowaway_t *h = attach_target(argv[0], NULL);
    uint64_t addr;
    if (parse_addr(h, argv[1], &addr) < 0) die("bad addr");
    uint8_t *bytes; size_t blen;
    if (parse_hex(argv[2], &bytes, &blen) < 0) die("bad hex bytes");
    ssize_t w = vm_stowaway_write(h, addr, bytes, blen);
    if (w < 0) die("write: %s", vm_stowaway_last_error(h));
    ok("wrote %zd bytes to 0x%llx", w, (unsigned long long)addr);
    free(bytes);
    vm_stowaway_close(h);
    return 0;
}

static int cmd_regions(int argc, char **argv) {
    if (argc < 1) die("usage: vm_stowaway regions <target> [--json]");
    int json = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) json = 1;
        else die("unknown flag: %s", argv[i]);
    }
    vm_stowaway_t *h = attach_target(argv[0], NULL);

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

    if (json) {
        printf("[");
        for (ssize_t i = 0; i < n; i++) {
            if (i) putchar(',');
            printf("{\"base\":\"0x%llx\",\"size\":%llu,\"prot\":%u}",
                   (unsigned long long)buf[i].base,
                   (unsigned long long)buf[i].size, buf[i].prot);
        }
        printf("]\n");
    } else {
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
    }
    free(buf);
    vm_stowaway_close(h);
    return 0;
}

static int cmd_images(int argc, char **argv) {
    if (argc < 1) die("usage: vm_stowaway images <target> [--json]");
    int json = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) json = 1;
        else die("unknown flag: %s", argv[i]);
    }
    vm_stowaway_t *h = attach_target(argv[0], NULL);

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

    if (json) {
        printf("[");
        for (ssize_t i = 0; i < n; i++) {
            if (i) putchar(',');
            printf("{\"base\":\"0x%llx\",\"slide\":\"0x%llx\",\"path\":",
                   (unsigned long long)buf[i].base,
                   (unsigned long long)buf[i].slide);
            json_string(buf[i].path);
            putchar('}');
        }
        printf("]\n");
    } else {
        for (ssize_t i = 0; i < n; i++)
            printf("%016llx  slide=%016llx  %s\n",
                   (unsigned long long)buf[i].base,
                   (unsigned long long)buf[i].slide,
                   buf[i].path);
    }
    free(buf);
    vm_stowaway_close(h);
    return 0;
}

static int cmd_resolve(int argc, char **argv) {
    if (argc < 2) die("usage: vm_stowaway resolve <target> [image] <symbol>");
    const char *image = argc == 2 ? NULL : argv[1];
    const char *sym = argc == 2 ? argv[1] : argv[2];
    vm_stowaway_t *h = attach_target(argv[0], NULL);
    uint64_t addr = vm_stowaway_resolve(h, image, sym);
    if (!addr) die("resolve: %s", vm_stowaway_last_error(h));
    printf("0x%016llx\n", (unsigned long long)addr);
    vm_stowaway_close(h);
    return 0;
}

/* Build a hex pattern (and matching all-0xFF mask) from typed value args. */
static int value_to_pattern(const char *kind, const char *val,
                            uint8_t **out, size_t *out_len) {
    if (!strcmp(kind, "--i32") || !strcmp(kind, "--u32")) {
        uint64_t v;
        if (parse_u64(val, &v) < 0) return -1;
        uint32_t w = (uint32_t)v;
        *out = malloc(4); if (!*out) return -1;
        memcpy(*out, &w, 4); *out_len = 4;
        return 0;
    }
    if (!strcmp(kind, "--i64") || !strcmp(kind, "--u64")) {
        uint64_t v;
        if (parse_u64(val, &v) < 0) return -1;
        *out = malloc(8); if (!*out) return -1;
        memcpy(*out, &v, 8); *out_len = 8;
        return 0;
    }
    if (!strcmp(kind, "--f32")) {
        float f = strtof(val, NULL);
        *out = malloc(4); if (!*out) return -1;
        memcpy(*out, &f, 4); *out_len = 4;
        return 0;
    }
    if (!strcmp(kind, "--f64")) {
        double f = strtod(val, NULL);
        *out = malloc(8); if (!*out) return -1;
        memcpy(*out, &f, 8); *out_len = 8;
        return 0;
    }
    if (!strcmp(kind, "--str")) {
        size_t n = strlen(val);
        *out = malloc(n); if (!*out) return -1;
        memcpy(*out, val, n); *out_len = n;
        return 0;
    }
    return -1;
}

static int cmd_scan(int argc, char **argv) {
    if (argc < 4)
        die("usage: vm_stowaway scan <target> <start> <end> <hex-pat | --i32 N | --u32 N | --i64 N | --u64 N | --f32 N | --f64 N | --str S> [--mask HEX] [--json]");
    vm_stowaway_t *h = attach_target(argv[0], NULL);
    uint64_t start, end;
    if (parse_addr(h, argv[1], &start) < 0) die("bad start");
    if (parse_addr(h, argv[2], &end) < 0) die("bad end");

    uint8_t *pat = NULL, *mask = NULL;
    size_t plen = 0, mlen = 0;
    int json = 0;
    int i = 3;

    if (argv[i][0] == '-' && argv[i][1] == '-' &&
        strcmp(argv[i], "--mask") != 0 && strcmp(argv[i], "--json") != 0) {
        if (i + 1 >= argc) die("missing value after %s", argv[i]);
        if (value_to_pattern(argv[i], argv[i + 1], &pat, &plen) < 0)
            die("bad value or kind: %s %s", argv[i], argv[i + 1]);
        i += 2;
    } else {
        if (parse_hex(argv[i], &pat, &plen) < 0) die("bad pattern");
        i++;
    }
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--mask") && i + 1 < argc) {
            if (parse_hex(argv[++i], &mask, &mlen) < 0) die("bad mask");
            if (mlen != plen) die("mask length must match pattern");
        } else if (!strcmp(argv[i], "--json")) json = 1;
        else die("unknown flag: %s", argv[i]);
    }

    uint64_t hits[1024];
    ssize_t n = vm_stowaway_scan(h, start, end, pat, mask, plen, hits, 1024);
    if (n < 0) die("scan: %s", vm_stowaway_last_error(h));
    if (json) {
        printf("[");
        for (ssize_t k = 0; k < n && k < 1024; k++) {
            if (k) putchar(',');
            printf("\"0x%llx\"", (unsigned long long)hits[k]);
        }
        printf("]\n");
    } else {
        for (ssize_t k = 0; k < n && k < 1024; k++)
            printf("0x%016llx\n", (unsigned long long)hits[k]);
        info("%zd hit(s)", n);
    }
    free(pat); free(mask);
    vm_stowaway_close(h);
    return 0;
}

/* snapshot scan: maintain a session file with a list of candidate addresses
 * and their last-seen values. On each call we re-read each, filter by the
 * comparator, and rewrite the session. */
struct snap_entry { uint64_t addr; int64_t last; };

static const char *snap_path(const char *name, char *buf, size_t buflen) {
    snprintf(buf, buflen, "/tmp/vm_stowaway.snap.%s", name ? name : "default");
    return buf;
}

static int cmd_diff(int argc, char **argv) {
    if (argc < 2)
        die("usage:\n"
            "  vm_stowaway diff start <target> <start> <end> <kind> <val>    initial snapshot via scan\n"
            "  vm_stowaway diff filter <target> <op> [val]                   op = eq|neq|gt|lt|changed|unchanged\n"
            "  vm_stowaway diff list                                         dump current snapshot\n"
            "  vm_stowaway diff drop                                         remove snapshot\n"
            "(use --name N to keep multiple snapshots side by side; default name = 'default')");

    /* extract --name N if present */
    const char *name = NULL;
    int sub_argc = 0;
    char *sub_argv[16];
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--name") && i + 1 < argc) { name = argv[++i]; continue; }
        if (sub_argc < 16) sub_argv[sub_argc++] = argv[i];
    }
    char pb[256]; const char *path = snap_path(name, pb, sizeof(pb));

    const char *mode = sub_argv[0];
    if (!strcmp(mode, "drop")) {
        unlink(path);
        ok("dropped %s", path);
        return 0;
    }
    if (!strcmp(mode, "list")) {
        FILE *f = fopen(path, "rb");
        if (!f) die("no snapshot at %s", path);
        struct snap_entry e;
        size_t n = 0;
        while (fread(&e, sizeof(e), 1, f) == 1) {
            printf("0x%016llx  %lld\n", (unsigned long long)e.addr, (long long)e.last);
            n++;
        }
        fclose(f);
        info("%zu entries", n);
        return 0;
    }
    if (!strcmp(mode, "start")) {
        if (sub_argc < 6) die("diff start needs <target> <start> <end> <kind> <val>");
        vm_stowaway_t *h = attach_target(sub_argv[1], NULL);
        uint64_t start, end;
        if (parse_addr(h, sub_argv[2], &start) < 0) die("bad start");
        if (parse_addr(h, sub_argv[3], &end)   < 0) die("bad end");
        uint8_t *pat = NULL; size_t plen = 0;
        if (value_to_pattern(sub_argv[4], sub_argv[5], &pat, &plen) < 0)
            die("bad value");

        size_t cap = 1024;
        uint64_t *hits = malloc(cap * sizeof(uint64_t));
        if (!hits) die("oom");
        ssize_t n = vm_stowaway_scan(h, start, end, pat, NULL, plen, hits, cap);
        if (n < 0) die("scan: %s", vm_stowaway_last_error(h));
        if (n > (ssize_t)cap) n = (ssize_t)cap;

        /* re-read each as i64 to populate `last` (use 4 or 8 bytes depending on
         * pattern length; here just pack first 8 bytes). */
        FILE *f = fopen(path, "wb");
        if (!f) die("open %s: %s", path, strerror(errno));
        for (ssize_t i = 0; i < n; i++) {
            uint8_t b[8] = {0};
            ssize_t got = vm_stowaway_read(h, hits[i], b,
                                           plen > 8 ? 8 : plen);
            int64_t v = 0;
            if (got > 0) memcpy(&v, b, (size_t)got);
            struct snap_entry e = { hits[i], v };
            fwrite(&e, sizeof(e), 1, f);
        }
        fclose(f);
        ok("snapshot %s: %zd entries", path, n);
        free(pat); free(hits);
        vm_stowaway_close(h);
        return 0;
    }
    if (!strcmp(mode, "filter")) {
        if (sub_argc < 3) die("diff filter needs <target> <op> [val]");
        const char *op = sub_argv[2];
        int64_t val = 0;
        int has_val = sub_argc > 3;
        if (has_val) val = (int64_t)strtoll(sub_argv[3], NULL, 0);

        FILE *f = fopen(path, "rb");
        if (!f) die("no snapshot at %s", path);
        size_t cap = 0;
        struct snap_entry *e = NULL, tmp;
        while (fread(&tmp, sizeof(tmp), 1, f) == 1) {
            cap++;
            e = realloc(e, cap * sizeof(*e));
            if (!e) die("oom");
            e[cap - 1] = tmp;
        }
        fclose(f);

        vm_stowaway_t *h = attach_target(sub_argv[1], NULL);
        FILE *out = fopen(path, "wb");
        if (!out) die("rewrite: %s", strerror(errno));
        size_t kept = 0;
        for (size_t i = 0; i < cap; i++) {
            uint8_t b[8] = {0};
            ssize_t got = vm_stowaway_read(h, e[i].addr, b, 8);
            if (got <= 0) continue;
            int64_t cur = 0;
            memcpy(&cur, b, (size_t)got);
            int pass = 0;
            if      (!strcmp(op, "eq"))        pass = has_val && cur == val;
            else if (!strcmp(op, "neq"))       pass = has_val && cur != val;
            else if (!strcmp(op, "gt"))        pass = has_val && cur >  val;
            else if (!strcmp(op, "lt"))        pass = has_val && cur <  val;
            else if (!strcmp(op, "changed"))   pass = cur != e[i].last;
            else if (!strcmp(op, "unchanged")) pass = cur == e[i].last;
            else die("unknown op: %s", op);
            if (pass) {
                struct snap_entry ne = { e[i].addr, cur };
                fwrite(&ne, sizeof(ne), 1, out);
                kept++;
                if (kept <= 64)
                    printf("0x%016llx  %lld -> %lld\n",
                           (unsigned long long)e[i].addr,
                           (long long)e[i].last, (long long)cur);
            }
        }
        fclose(out);
        free(e);
        info("%zu of %zu kept", kept, cap);
        vm_stowaway_close(h);
        return 0;
    }
    die("unknown diff mode: %s", mode);
}

static int cmd_call(int argc, char **argv) {
    if (argc < 2)
        die("usage: vm_stowaway call <target> <addr> [arg0..arg5]   (args parsed as 0x... or decimal)");
    vm_stowaway_t *h = attach_target(argv[0], NULL);
    uint64_t addr;
    if (parse_addr(h, argv[1], &addr) < 0) die("bad addr");
    uint64_t args[6] = {0};
    uint32_t nargs = 0;
    for (int i = 2; i < argc && nargs < 6; i++) {
        if (parse_addr(h, argv[i], &args[nargs]) < 0) die("bad arg %d: %s", i - 1, argv[i]);
        nargs++;
    }
    uint64_t ret = 0;
    if (vm_stowaway_call(h, addr, args, nargs, &ret) < 0)
        die("call: %s", vm_stowaway_last_error(h));
    printf("0x%llx\n", (unsigned long long)ret);
    vm_stowaway_close(h);
    return 0;
}

static int cmd_break(int argc, char **argv) {
    if (argc < 2)
        die("usage:\n"
            "  vm_stowaway break set    <target> <addr>\n"
            "  vm_stowaway break clear  <target> <id>\n"
            "  vm_stowaway break wait   <target> [--ms N]\n"
            "  vm_stowaway break cont   <target> <tid>");
    const char *mode = argv[0];
    vm_stowaway_t *h = attach_target(argv[1], NULL);

    if (!strcmp(mode, "set")) {
        if (argc < 3) die("break set needs <addr>");
        uint64_t a;
        if (parse_addr(h, argv[2], &a) < 0) die("bad addr");
        uint32_t id = 0;
        if (vm_stowaway_break_set(h, a, &id) < 0)
            die("break set: %s", vm_stowaway_last_error(h));
        printf("bp_id %u at 0x%llx\n", id, (unsigned long long)a);
    } else if (!strcmp(mode, "clear")) {
        if (argc < 3) die("break clear needs <id>");
        uint64_t id;
        if (parse_u64(argv[2], &id) < 0) die("bad id");
        if (vm_stowaway_break_clear(h, (uint32_t)id) < 0)
            die("break clear: %s", vm_stowaway_last_error(h));
        ok("cleared");
    } else if (!strcmp(mode, "wait")) {
        int ms = -1;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--ms") && i + 1 < argc) ms = atoi(argv[++i]);
            else die("unknown flag: %s", argv[i]);
        }
        uint32_t id; uint64_t tid, pc;
        if (vm_stowaway_break_wait(h, ms, &id, &tid, &pc) < 0)
            die("break wait: %s", vm_stowaway_last_error(h));
        printf("hit bp_id=%u tid=%llu pc=0x%llx\n",
               id, (unsigned long long)tid, (unsigned long long)pc);
    } else if (!strcmp(mode, "cont")) {
        if (argc < 3) die("break cont needs <tid>");
        uint64_t tid;
        if (parse_u64(argv[2], &tid) < 0) die("bad tid");
        if (vm_stowaway_break_cont(h, tid) < 0)
            die("break cont: %s", vm_stowaway_last_error(h));
        ok("resumed");
    } else {
        die("unknown break mode: %s", mode);
    }
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
    if (argc < 1)
        die("usage: vm_stowaway launch [--name N | --sock PATH] <target> [args...]");
    char sock_buf[256];
    char err[512] = {0};
    vm_stowaway_launch_opts_t opts = {0};
    int i = 0;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--name") && i + 1 < argc) {
            snprintf(sock_buf, sizeof(sock_buf), "/tmp/vm_stowaway.%s.sock", argv[++i]);
            opts.socket_path = sock_buf;
        } else if (!strcmp(argv[i], "--sock") && i + 1 < argc) {
            opts.socket_path = argv[++i];
        } else break;
    }
    if (i >= argc) die("launch: missing target");
    vm_stowaway_t *h = vm_stowaway_launch(argv[i], argv + i, &opts, err, sizeof(err));
    if (!h) die("launch: %s", err);
    ok("launched pid %d, payload connected (sock=%s)",
       vm_stowaway_pid(h), opts.socket_path ? opts.socket_path : "auto");
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

/* find_app_bundle + unharden are now vm_stowaway_find_app_bundle() /
 * vm_stowaway_unharden() in src/scanner.c. */

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
        if (vm_stowaway_find_app_bundle(argv[i], src_app, sizeof(src_app)) < 0)
            die("--copy: %s isn't inside a .app bundle", argv[i]);

        info("copying %s -> %s and re-signing without hardened runtime",
             src_app, copy_dest);
        char err[256] = {0};
        if (vm_stowaway_unharden(src_app, copy_dest, err, sizeof(err)) < 0)
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
    if (argc < 1)
        die("usage: vm_stowaway attach <target> [--sock PATH | --name N]");
    char sock_buf[256];
    const char *sock = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--sock") && i + 1 < argc) sock = argv[++i];
        else if (!strcmp(argv[i], "--name") && i + 1 < argc) {
            snprintf(sock_buf, sizeof(sock_buf), "/tmp/vm_stowaway.%s.sock", argv[++i]);
            sock = sock_buf;
        } else die("unknown flag: %s", argv[i]);
    }
    vm_stowaway_t *h = attach_target(argv[0], sock);
    ok("attached to pid %d", (int)vm_stowaway_pid(h));
    repl(h);
    vm_stowaway_close(h);
    return 0;
}

static int cmd_scan_electron(int argc, char **argv) {
    const char *root = argc >= 1 ? argv[0] : "/Applications";
    char err[256] = {0};
    vm_stowaway_electron_t buf[256];
    ssize_t n = vm_stowaway_scan_electron(root, buf, 256, err, sizeof(err));
    if (n < 0) die("scan-electron: %s", err);
    for (ssize_t i = 0; i < n && i < 256; i++) {
        printf("%s  electron  RUN_AS_NODE=%s\n",
               buf[i].path,
               buf[i].run_as_node == 1 ? "enabled" :
               buf[i].run_as_node == 0 ? "disabled" : "unknown");
    }
    if (n > 256) info("... (%zd total, showing 256)", n);
    return 0;
}

static int cmd_scan_targets(int argc, char **argv) {
    const char *root = argc >= 1 ? argv[0] : "/Applications";
    info("scanning %s for hardened-but-permissive apps...", root);
    char err[256] = {0};
    vm_stowaway_app_t buf[256];
    ssize_t n = vm_stowaway_scan_apps(root, 1, buf, 256, err, sizeof(err));
    if (n < 0) die("scan-targets: %s", err);
    for (ssize_t i = 0; i < n && i < 256; i++)
        printf("%s  (dyld-env + no-libval)\n", buf[i].path);
    if (n > 256) info("... (%zd total, showing 256)", n);
    return 0;
}

static int cmd_scan_hijacks(int argc, char **argv) {
    if (argc < 1) die("usage: vm_stowaway scan-hijacks <bin>");
    char err[512] = {0};
    vm_stowaway_hijack_t buf[64];
    ssize_t n = vm_stowaway_scan_hijacks(argv[0], buf, 64, err, sizeof(err));
    if (n < 0) die("scan-hijacks: %s", err);
    if (n == 0) { info("no candidates"); return 0; }
    for (ssize_t i = 0; i < n && i < 64; i++) {
        printf("%s  (%s) %s\n",
               buf[i].path,
               buf[i].weak ? "weak-missing" : "rpath-missing",
               buf[i].dep_name);
    }
    if (n > 64) info("... (%zd total, showing 64)", n);
    return 0;
}

/* Locate libvm_stowaway_payload.dylib next to us / build/ / /usr/local/lib. */
static int default_payload_path(char *out, size_t outlen) {
    Dl_info info;
    if (dladdr((void *)default_payload_path, &info) && info.dli_fname) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s", info.dli_fname);
        char *dir = dirname(buf);
        if (dir) {
            snprintf(out, outlen, "%s/libvm_stowaway_payload.dylib", dir);
            if (access(out, R_OK) == 0) return 0;
            snprintf(out, outlen, "%s/../libvm_stowaway_payload.dylib", dir);
            if (access(out, R_OK) == 0) return 0;
        }
    }
    snprintf(out, outlen, "/usr/local/lib/libvm_stowaway_payload.dylib");
    return access(out, R_OK) == 0 ? 0 : -1;
}

static int cmd_hijack(int argc, char **argv) {
    if (argc < 1)
        die("usage: vm_stowaway hijack <bin> [--pick N] [--payload PATH] [--dry-run]");
    const char *bin = argv[0];
    int pick = 0, dry = 0;
    const char *payload = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pick") && i + 1 < argc) pick = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--payload") && i + 1 < argc) payload = argv[++i];
        else if (!strcmp(argv[i], "--dry-run")) dry = 1;
        else die("unknown flag: %s", argv[i]);
    }
    char err[512] = {0};
    vm_stowaway_hijack_t buf[64];
    ssize_t n = vm_stowaway_scan_hijacks(bin, buf, 64, err, sizeof(err));
    if (n < 0) die("scan-hijacks: %s", err);
    if (n == 0) die("no hijack candidates");
    if (pick < 0 || pick >= n || pick >= 64) die("pick out of range (0..%zd)", n - 1);

    info("target: %s (%s) %s", buf[pick].path,
         buf[pick].weak ? "weak-missing" : "rpath-missing", buf[pick].dep_name);
    if (dry) return 0;

    char pp[1024];
    if (payload) snprintf(pp, sizeof(pp), "%s", payload);
    else if (default_payload_path(pp, sizeof(pp)) < 0)
        die("couldn't find payload; pass --payload PATH");

    if (vm_stowaway_hijack_drop(pp, buf[pick].path, err, sizeof(err)) < 0)
        die("drop: %s", err);
    ok("dropped %s -> %s", pp, buf[pick].path);
    return 0;
}

static int cmd_unharden(int argc, char **argv) {
    if (argc < 2)
        die("usage: vm_stowaway unharden <src.app> <dst.app>\n"
            "       (copy + ad-hoc resign without hardened runtime / library validation)");
    char err[256] = {0};
    if (vm_stowaway_unharden(argv[0], argv[1], err, sizeof(err)) < 0)
        die("unharden: %s", err);
    ok("%s ready (hardened runtime stripped)", argv[1]);
    return 0;
}

static int cmd_grant_task_allow(int argc, char **argv) {
    if (argc < 1)
        die("usage: vm_stowaway grant-task-allow <src.app> [dst.app]\n"
            "       (re-sign with get-task-allow so any same-uid process can task_for_pid)\n"
            "       (no dst -> re-sign in place)");
    const char *src = argv[0];
    const char *dst = argc >= 2 ? argv[1] : NULL;
    char err[256] = {0};
    if (vm_stowaway_grant_task_allow(src, dst, err, sizeof(err)) < 0)
        die("grant-task-allow: %s", err);
    ok("%s carries get-task-allow", dst ? dst : src);
    return 0;
}

static int cmd_amfi_bypass(int argc, char **argv) {
    if (argc < 1)
        die("usage: vm_stowaway amfi-bypass on|off|status\n"
            "       (sets amfi_get_out_of_my_way=1 boot-arg; reboot required;\n"
            "        needs root + SIP off, on Apple Silicon also Reduced Security)");
    char err[256] = {0};
    if (!strcmp(argv[0], "status")) {
        int s = vm_stowaway_amfi_bypass_get(err, sizeof(err));
        if (s < 0) die("amfi-bypass status: %s", err);
        info("amfi_get_out_of_my_way is %s in current NVRAM boot-args",
             s ? "SET" : "not set");
        return 0;
    }
    int enable;
    if      (!strcmp(argv[0], "on"))  enable = 1;
    else if (!strcmp(argv[0], "off")) enable = 0;
    else die("expected on|off|status, got: %s", argv[0]);
    if (vm_stowaway_amfi_bypass_set(enable, err, sizeof(err)) < 0)
        die("amfi-bypass %s: %s", argv[0], err);
    ok("boot-args updated; reboot for the change to take effect");
    return 0;
}

static int cmd_disable_libval(int argc, char **argv) {
    if (argc < 1)
        die("usage: vm_stowaway disable-libval on|off|status\n"
            "       (toggles DisableLibraryValidation in /Library/Preferences;\n"
            "        needs root + SIP off; no reboot required)");
    char err[256] = {0};
    if (!strcmp(argv[0], "status")) {
        int s = vm_stowaway_libval_disable_get(err, sizeof(err));
        if (s < 0) die("disable-libval status: %s", err);
        info("DisableLibraryValidation is %s", s ? "SET" : "not set");
        return 0;
    }
    int disable;
    if      (!strcmp(argv[0], "on"))  disable = 1;
    else if (!strcmp(argv[0], "off")) disable = 0;
    else die("expected on|off|status, got: %s", argv[0]);
    if (vm_stowaway_libval_disable_set(disable, err, sizeof(err)) < 0)
        die("disable-libval %s: %s", argv[0], err);
    ok("DisableLibraryValidation %s", disable ? "set" : "cleared");
    return 0;
}

static int cmd_unpatch(int argc, char **argv) {
    if (argc < 2)
        die("usage: vm_stowaway unpatch <bin> <name-substr> [--out PATH] [--no-sign]");
    const char *binary = argv[0];
    const char *substr = argv[1];
    vm_stowaway_patch_opts_t opts = { .resign = 1 };
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--no-sign")) opts.resign = 0;
        else if (!strcmp(argv[i], "--out") && i + 1 < argc) opts.out_path = argv[++i];
        else die("unknown flag: %s", argv[i]);
    }
    char err[512] = {0};
    int n = vm_stowaway_unpatch(binary, substr, &opts, err, sizeof(err));
    if (n < 0) die("unpatch: %s", err);
    ok("removed %d LC_LOAD_DYLIB entr%s%s",
       n, n == 1 ? "y" : "ies",
       opts.resign ? " and re-signed ad-hoc" : "");
    return 0;
}

static void usage(void) {
    fputs(
        "usage: vm_stowaway <command> [args...]\n"
        "\n"
        "target := <pid> | <process-name>     (attach commands resolve a name to the first matching pid)\n"
        "addr   := 0x... | <decimal> | Image+0xN\n"
        "\n"
        "  launch  [--name N | --sock PATH] <target> [args...]\n"
        "            spawn target with payload via DYLD_INSERT_LIBRARIES\n"
        "  patch   <bin> <install-name> [--weak] [--out PATH] [--no-sign]\n"
        "            add LC_LOAD_DYLIB to bin\n"
        "  unpatch <bin> <name-substr> [--out PATH] [--no-sign]\n"
        "            strip LC_LOAD_DYLIBs whose name contains substr\n"
        "  unharden <src.app> <dst.app>\n"
        "            copy the bundle and ad-hoc resign without hardened runtime/library validation\n"
        "            (afterwards plain `launch` works against it)\n"
        "  grant-task-allow <src.app> [dst.app]\n"
        "            re-sign with get-task-allow so any same-uid process can task_for_pid\n"
        "            it (no root needed afterwards). Omit dst to re-sign in place.\n"
        "  amfi-bypass on|off|status\n"
        "            toggle amfi_get_out_of_my_way=1 boot-arg; reboot required.\n"
        "            With this on, DYLD_INSERT_LIBRARIES is no longer stripped from any\n"
        "            hardened binary system-wide. Needs root + SIP off.\n"
        "  disable-libval on|off|status\n"
        "            toggle /Library/Preferences/.../DisableLibraryValidation. Lets dylibs\n"
        "            signed by a different team-id load into hardened binaries.\n"
        "            Needs root + SIP off. No reboot required.\n"
        "  scan-hijacks <bin>\n"
        "            list paths where dropping a dylib would be loaded as a missing dep\n"
        "  hijack  <bin> [--pick N] [--payload PATH] [--dry-run]\n"
        "            drop the payload at the first (or Nth) hijack candidate\n"
        "  scan-targets [dir]\n"
        "            walk /Applications (or dir) for hardened apps shipping with\n"
        "            disable-library-validation + allow-dyld-environment-variables\n"
        "            (i.e. ones where plain `launch` works against hardened runtime)\n"
        "  scan-electron [dir]\n"
        "            list Electron apps and their ELECTRON_RUN_AS_NODE fuse state\n"
        "  wrap    --pid PID [--sock PATH] [--shim PATH] [--copy DEST.app] -- <tool> [args...]\n"
        "            launch <tool> with the mach shim DYLD_INSERTed\n"
        "  attach  <target> [--sock PATH | --name N]\n"
        "  read    <target> <addr> <len> [--syms]\n"
        "  write   <target> <addr> <hex>\n"
        "  regions <target> [--json]\n"
        "  images  <target> [--json]\n"
        "  resolve <target> [image] <symbol>\n"
        "  scan    <target> <start> <end> <hex-pat | --i32 N | --u32 N | --i64 N | --u64 N | --f32 N | --f64 N | --str S>\n"
        "          [--mask HEX] [--json]\n"
        "  diff    start  <target> <start> <end> <kind> <val> [--name N]\n"
        "          filter <target> <eq|neq|gt|lt|changed|unchanged> [val] [--name N]\n"
        "          list | drop [--name N]\n"
        "  call    <target> <addr> [arg0..arg5]\n"
        "  break   set <target> <addr> | clear <target> <id> | wait <target> [--ms N] | cont <target> <tid>\n",
        stdout);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];
    int sub_argc = argc - 2;
    char **sub_argv = argv + 2;

    if (!strcmp(cmd, "launch"))   return cmd_launch(sub_argc, sub_argv);
    if (!strcmp(cmd, "patch"))    return cmd_patch(sub_argc, sub_argv);
    if (!strcmp(cmd, "unpatch"))  return cmd_unpatch(sub_argc, sub_argv);
    if (!strcmp(cmd, "unharden")) return cmd_unharden(sub_argc, sub_argv);
    if (!strcmp(cmd, "grant-task-allow")) return cmd_grant_task_allow(sub_argc, sub_argv);
    if (!strcmp(cmd, "amfi-bypass"))    return cmd_amfi_bypass(sub_argc, sub_argv);
    if (!strcmp(cmd, "disable-libval")) return cmd_disable_libval(sub_argc, sub_argv);
    if (!strcmp(cmd, "scan-hijacks")) return cmd_scan_hijacks(sub_argc, sub_argv);
    if (!strcmp(cmd, "scan-targets")) return cmd_scan_targets(sub_argc, sub_argv);
    if (!strcmp(cmd, "scan-electron")) return cmd_scan_electron(sub_argc, sub_argv);
    if (!strcmp(cmd, "hijack"))   return cmd_hijack(sub_argc, sub_argv);
    if (!strcmp(cmd, "wrap"))     return cmd_wrap(sub_argc, sub_argv);
    if (!strcmp(cmd, "attach"))   return cmd_attach(sub_argc, sub_argv);
    if (!strcmp(cmd, "read"))     return cmd_read(sub_argc, sub_argv);
    if (!strcmp(cmd, "write"))    return cmd_write(sub_argc, sub_argv);
    if (!strcmp(cmd, "regions"))  return cmd_regions(sub_argc, sub_argv);
    if (!strcmp(cmd, "images"))   return cmd_images(sub_argc, sub_argv);
    if (!strcmp(cmd, "resolve"))  return cmd_resolve(sub_argc, sub_argv);
    if (!strcmp(cmd, "scan"))     return cmd_scan(sub_argc, sub_argv);
    if (!strcmp(cmd, "diff"))     return cmd_diff(sub_argc, sub_argv);
    if (!strcmp(cmd, "call"))     return cmd_call(sub_argc, sub_argv);
    if (!strcmp(cmd, "break"))    return cmd_break(sub_argc, sub_argv);
    if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help")) { usage(); return 0; }
    fprintf(stderr, "unknown command: %s\n", cmd);
    usage();
    return 1;
}
