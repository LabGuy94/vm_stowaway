/* filesystem-only scanners: walk app bundles, check entitlements, detect
 * Electron fuses, ad-hoc resign without hardened runtime. no payload, no
 * attach, just disk + codesign/xattr/cp. */

#define _DARWIN_C_SOURCE

#include "../include/vm_stowaway.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void scan_seterr(char *errbuf, size_t errlen, const char *fmt, ...) {
    if (!errbuf || !errlen) return;
    va_list ap; va_start(ap, fmt);
    vsnprintf(errbuf, errlen, fmt, ap);
    va_end(ap);
}

static int run_silent(const char *prog, char *const argv[]) {
    pid_t pid;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    int rc = posix_spawnp(&pid, prog, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) return rc;
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* `codesign -d --entitlements - <bin>` -> sniff for flags. */
static int read_entitlements(const char *bin, int *allow_dyld, int *no_libval) {
    *allow_dyld = *no_libval = 0;
    char q[2048];
    size_t qn = 0;
    q[qn++] = '\'';
    for (const char *p = bin; *p && qn + 5 < sizeof(q); p++) {
        if (*p == '\'') { q[qn++]='\''; q[qn++]='\\'; q[qn++]='\''; q[qn++]='\''; }
        else q[qn++] = *p;
    }
    q[qn++] = '\''; q[qn] = 0;
    char cmd[2200];
    snprintf(cmd, sizeof(cmd),
             "codesign -d --entitlements - %s 2>/dev/null", q);
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    char buf[8192];
    size_t got = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[got] = 0;
    pclose(fp);
    if (strstr(buf, "com.apple.security.cs.allow-dyld-environment-variables"))
        *allow_dyld = 1;
    if (strstr(buf, "com.apple.security.cs.disable-library-validation"))
        *no_libval = 1;
    return 0;
}

struct scan_ctx {
    vm_stowaway_app_t *out;
    size_t max;
    size_t written;
    size_t total;
    int permissive_only;
};

static void scan_apps_recurse(const char *dir, int depth, struct scan_ctx *c) {
    if (depth > 4) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        size_t nlen = strlen(e->d_name);
        if (nlen > 4 && strcmp(e->d_name + nlen - 4, ".app") == 0) {
            char macos[1280];
            snprintf(macos, sizeof(macos), "%s/Contents/MacOS", path);
            DIR *m = opendir(macos);
            if (!m) continue;
            struct dirent *me;
            while ((me = readdir(m))) {
                if (me->d_name[0] == '.') continue;
                char exe[2048];
                snprintf(exe, sizeof(exe), "%s/%s", macos, me->d_name);
                int ad = 0, nv = 0;
                if (read_entitlements(exe, &ad, &nv) == 0) {
                    if (!c->permissive_only || (ad && nv)) {
                        c->total++;
                        if (c->written < c->max && c->out) {
                            vm_stowaway_app_t *a = &c->out[c->written++];
                            snprintf(a->path, sizeof(a->path), "%s", path);
                            a->allow_dyld_env = ad;
                            a->disable_lib_val = nv;
                        }
                    }
                }
                break;
            }
            closedir(m);
        } else {
            struct stat st;
            if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
                scan_apps_recurse(path, depth + 1, c);
        }
    }
    closedir(d);
}

ssize_t vm_stowaway_scan_apps(const char *dir, int permissive_only,
                              vm_stowaway_app_t *out, size_t max,
                              char *errbuf, size_t errlen) {
    const char *root = dir ? dir : "/Applications";
    struct scan_ctx c = { out, max, 0, 0, permissive_only };
    DIR *d = opendir(root);
    if (!d) {
        scan_seterr(errbuf, errlen, "opendir(%s): %s", root, strerror(errno));
        return -1;
    }
    closedir(d);
    scan_apps_recurse(root, 0, &c);
    return (ssize_t)c.total;
}

/* @electron/fuses v1 sentinel: 32 ASCII bytes, then version u8, then fuse
 * bytes (0=removed, 1=disabled, 2=enabled). Index 0 = RunAsNode. */
static int electron_run_as_node_fuse(const char *fw_bin) {
    static const char SENT[] = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";
    const size_t slen = sizeof(SENT) - 1;
    FILE *f = fopen(fw_bin, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz <= 0 || sz > (long)(500 * 1024 * 1024)) { fclose(f); return -1; }
    rewind(f);
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    long got = (long)fread(buf, 1, (size_t)sz, f);
    fclose(f);
    int result = -1;
    for (long i = 0; i + (long)slen + 8 <= got; i++) {
        if (memcmp(buf + i, SENT, slen) == 0) {
            uint8_t run_as_node = buf[i + slen + 1];
            result = (run_as_node == 2) ? 1 : 0;
            break;
        }
    }
    free(buf);
    return result;
}

ssize_t vm_stowaway_scan_electron(const char *dir,
                                  vm_stowaway_electron_t *out, size_t max,
                                  char *errbuf, size_t errlen) {
    const char *root = dir ? dir : "/Applications";
    DIR *d = opendir(root);
    if (!d) {
        scan_seterr(errbuf, errlen, "opendir(%s): %s", root, strerror(errno));
        return -1;
    }
    size_t written = 0, total = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        size_t nlen = strlen(e->d_name);
        if (nlen < 4 || strcmp(e->d_name + nlen - 4, ".app") != 0) continue;
        char app[1024];
        snprintf(app, sizeof(app), "%s/%s", root, e->d_name);
        char fw[1280];
        snprintf(fw, sizeof(fw),
                 "%s/Contents/Frameworks/Electron Framework.framework/Electron Framework",
                 app);
        if (access(fw, F_OK) != 0) continue;
        total++;
        if (out && written < max) {
            vm_stowaway_electron_t *o = &out[written++];
            snprintf(o->path, sizeof(o->path), "%s", app);
            o->run_as_node = electron_run_as_node_fuse(fw);
        }
    }
    closedir(d);
    return (ssize_t)total;
}

int vm_stowaway_find_app_bundle(const char *path, char *out, size_t outlen) {
    if (!path || !out || outlen == 0) return -1;
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

/* Common path for unharden and grant_task_allow. If `entitlements_plist` is
 * non-NULL, it's passed as `--entitlements` to the resigner. If dst_app is
 * NULL or equal to src_app, re-sign in place (no copy). */
static int resign_bundle(const char *src_app, const char *dst_app,
                         const char *entitlements_plist,
                         char *errbuf, size_t errlen) {
    const char *target = dst_app && dst_app[0] ? dst_app : src_app;
    int in_place = (target == src_app) || strcmp(target, src_app) == 0;
    if (!in_place) {
        char *rm_argv[] = { "rm", "-rf", (char *)target, NULL };
        if (run_silent("rm", rm_argv) != 0) {
            scan_seterr(errbuf, errlen, "rm -rf %s failed", target);
            return -1;
        }
        char *cp_argv[] = { "cp", "-R", (char *)src_app, (char *)target, NULL };
        if (run_silent("cp", cp_argv) != 0) {
            scan_seterr(errbuf, errlen, "cp -R %s %s failed", src_app, target);
            return -1;
        }
    }
    char *xattr_argv[] = { "xattr", "-cr", (char *)target, NULL };
    run_silent("xattr", xattr_argv);
    char *cs_rm_argv[] = { "codesign", "--remove-signature", (char *)target, NULL };
    run_silent("codesign", cs_rm_argv);
    char *re_with_ent[] = {
        "codesign", "--force", "--deep", "--sign", "-",
        "--entitlements", (char *)entitlements_plist,
        (char *)target, NULL,
    };
    char *re_without_ent[] = {
        "codesign", "--force", "--deep", "--sign", "-",
        (char *)target, NULL,
    };
    char *const *argv = entitlements_plist ? re_with_ent : re_without_ent;
    if (run_silent("codesign", argv) != 0) {
        scan_seterr(errbuf, errlen, "codesign --force --deep --sign - %s failed", target);
        return -1;
    }
    return 0;
}

int vm_stowaway_unharden(const char *src_app, const char *dst_app,
                         char *errbuf, size_t errlen) {
    return resign_bundle(src_app, dst_app, NULL, errbuf, errlen);
}

int vm_stowaway_grant_task_allow(const char *src_app, const char *dst_app,
                                 char *errbuf, size_t errlen) {
    char tmpl[] = "/tmp/vmsw-ent.XXXXXX.plist";
    int fd = mkstemps(tmpl, 6);
    if (fd < 0) {
        scan_seterr(errbuf, errlen, "mkstemps: %s", strerror(errno));
        return -1;
    }
    const char *plist =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict>\n"
        "  <key>com.apple.security.get-task-allow</key><true/>\n"
        "</dict></plist>\n";
    size_t n = strlen(plist);
    if ((size_t)write(fd, plist, n) != n) {
        close(fd); unlink(tmpl);
        scan_seterr(errbuf, errlen, "write entitlements: %s", strerror(errno));
        return -1;
    }
    close(fd);
    int rc = resign_bundle(src_app, dst_app, tmpl, errbuf, errlen);
    unlink(tmpl);
    return rc;
}
