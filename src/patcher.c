/* in-place LC_LOAD_DYLIB insertion using header padding, then ad-hoc resign.
 * fat binaries: patch each slice. */

#define _DARWIN_C_SOURCE

#include "../include/vm_stowaway.h"

#include <errno.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void seterr(char *errbuf, size_t errlen, const char *fmt, ...) {
    if (!errbuf || !errlen) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errbuf, errlen, fmt, ap);
    va_end(ap);
}

static int copy_file(const char *src, const char *dst, char *err, size_t elen) {
    int in = open(src, O_RDONLY);
    if (in < 0) { seterr(err, elen, "open(%s): %s", src, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(in, &st) < 0) { seterr(err, elen, "stat: %s", strerror(errno)); close(in); return -1; }
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 0777);
    if (out < 0) { seterr(err, elen, "open(%s): %s", dst, strerror(errno)); close(in); return -1; }
    uint8_t buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        ssize_t w = 0;
        while (w < n) {
            ssize_t k = write(out, buf + w, n - w);
            if (k <= 0) {
                seterr(err, elen, "write: %s", strerror(errno));
                close(in); close(out); unlink(dst);
                return -1;
            }
            w += k;
        }
    }
    close(in); close(out);
    return 0;
}

/* 64-bit Mach-O only; 32-bit returns -1. */
static int patch_slice(uint8_t *data, uint64_t slice_size,
                       const char *install_name, int weak,
                       int strip_sig,
                       char *err, size_t elen) {
    if (slice_size < sizeof(struct mach_header_64)) {
        seterr(err, elen, "slice too small"); return -1;
    }

    uint32_t magic;
    memcpy(&magic, data, 4);
    int swap;
    if      (magic == MH_MAGIC_64)  swap = 0;
    else if (magic == MH_CIGAM_64)  swap = 1;
    else if (magic == MH_MAGIC || magic == MH_CIGAM) {
        seterr(err, elen, "32-bit Mach-O not supported"); return -1;
    } else {
        seterr(err, elen, "unknown magic 0x%08x", magic); return -1;
    }

    struct mach_header_64 hdr;
    memcpy(&hdr, data, sizeof(hdr));
    if (swap) {
        hdr.cputype     = OSSwapInt32(hdr.cputype);
        hdr.cpusubtype  = OSSwapInt32(hdr.cpusubtype);
        hdr.filetype    = OSSwapInt32(hdr.filetype);
        hdr.ncmds       = OSSwapInt32(hdr.ncmds);
        hdr.sizeofcmds  = OSSwapInt32(hdr.sizeofcmds);
        hdr.flags       = OSSwapInt32(hdr.flags);
    }

    /* Verify the load commands fit. */
    uint64_t hdr_end = sizeof(struct mach_header_64) + hdr.sizeofcmds;
    if (hdr_end > slice_size) { seterr(err, elen, "corrupt load commands"); return -1; }

    /* Find the ceiling: minimum non-zero file offset of any segment data /
     * section data that lives after the header. This is how much slack we
     * have to write a new load command into without shifting any data. */
    uint64_t ceiling = slice_size;
    uint8_t *lc_cur = data + sizeof(struct mach_header_64);
    uint8_t *lc_end = lc_cur + hdr.sizeofcmds;

    uint8_t *existing_sig_lc = NULL;

    for (uint32_t i = 0; i < hdr.ncmds && lc_cur + sizeof(struct load_command) <= lc_end; i++) {
        struct load_command lc;
        memcpy(&lc, lc_cur, sizeof(lc));
        uint32_t cmd = swap ? OSSwapInt32(lc.cmd) : lc.cmd;
        uint32_t cmdsize = swap ? OSSwapInt32(lc.cmdsize) : lc.cmdsize;
        if (cmdsize < sizeof(struct load_command) || lc_cur + cmdsize > lc_end) {
            seterr(err, elen, "malformed lc at %u", i); return -1;
        }

        if (cmd == LC_SEGMENT_64) {
            struct segment_command_64 seg;
            memcpy(&seg, lc_cur, sizeof(seg));
            if (swap) {
                seg.fileoff = OSSwapInt64(seg.fileoff);
                seg.filesize = OSSwapInt64(seg.filesize);
                seg.nsects = OSSwapInt32(seg.nsects);
            }
            if (seg.filesize > 0 && seg.fileoff > 0 && seg.fileoff < ceiling)
                ceiling = seg.fileoff;
            for (uint32_t s = 0; s < seg.nsects; s++) {
                struct section_64 sec;
                memcpy(&sec, lc_cur + sizeof(seg) + s * sizeof(sec), sizeof(sec));
                uint32_t size_lo = swap ? OSSwapInt32(sec.size) : sec.size; /* offset is 32-bit */
                uint32_t off = swap ? OSSwapInt32(sec.offset) : sec.offset;
                if (size_lo > 0 && off > 0 && off < ceiling) ceiling = off;
            }
        } else if (cmd == LC_CODE_SIGNATURE) {
            existing_sig_lc = lc_cur;
        }
        lc_cur += cmdsize;
    }

    /* Compute new load command size. */
    size_t name_len = strlen(install_name) + 1;
    size_t new_size = sizeof(struct dylib_command) + name_len;
    new_size = (new_size + 7) & ~7ULL;  /* 8-byte align */

    uint64_t available = ceiling - hdr_end;

    /* drop the LC_CODE_SIGNATURE load command if present; the signature blob
     * in __LINKEDIT becomes unreferenced and codesign will overwrite it. */
    if (strip_sig && existing_sig_lc) {
        struct load_command lc;
        memcpy(&lc, existing_sig_lc, sizeof(lc));
        uint32_t sig_cmdsize = swap ? OSSwapInt32(lc.cmdsize) : lc.cmdsize;
        size_t tail = lc_end - (existing_sig_lc + sig_cmdsize);
        memmove(existing_sig_lc, existing_sig_lc + sig_cmdsize, tail);
        memset(data + sizeof(struct mach_header_64) + hdr.sizeofcmds - sig_cmdsize,
               0, sig_cmdsize);
        hdr.ncmds      -= 1;
        hdr.sizeofcmds -= sig_cmdsize;
        hdr_end -= sig_cmdsize;
        available = ceiling - hdr_end;
    }

    if (available < new_size) {
        seterr(err, elen,
               "not enough header padding (%llu available, %zu needed). "
               "Rebuild the host with `-Wl,-headerpad,0x4000` (or "
               "`-headerpad_max_install_names`), or use a shorter install "
               "name (e.g. @rpath/lib.dylib instead of an absolute path)",
               (unsigned long long)available, new_size);
        return -1;
    }

    /* Build the new load command. */
    uint8_t *new_lc = data + hdr_end;
    memset(new_lc, 0, new_size);
    struct dylib_command dc = {0};
    dc.cmd = weak ? LC_LOAD_WEAK_DYLIB : LC_LOAD_DYLIB;
    dc.cmdsize = (uint32_t)new_size;
    dc.dylib.name.offset = sizeof(struct dylib_command);
    dc.dylib.timestamp = 2;
    dc.dylib.current_version = 0x00010000;
    dc.dylib.compatibility_version = 0x00010000;
    if (swap) {
        dc.cmd = OSSwapInt32(dc.cmd);
        dc.cmdsize = OSSwapInt32(dc.cmdsize);
        dc.dylib.name.offset = OSSwapInt32(dc.dylib.name.offset);
        dc.dylib.timestamp = OSSwapInt32(dc.dylib.timestamp);
        dc.dylib.current_version = OSSwapInt32(dc.dylib.current_version);
        dc.dylib.compatibility_version = OSSwapInt32(dc.dylib.compatibility_version);
    }
    memcpy(new_lc, &dc, sizeof(dc));
    memcpy(new_lc + sizeof(struct dylib_command), install_name, name_len - 1);
    /* trailing null + alignment padding already zeroed by memset */

    /* Update header. */
    hdr.ncmds      += 1;
    hdr.sizeofcmds += (uint32_t)new_size;
    struct mach_header_64 wh = hdr;
    if (swap) {
        wh.cputype     = OSSwapInt32(wh.cputype);
        wh.cpusubtype  = OSSwapInt32(wh.cpusubtype);
        wh.filetype    = OSSwapInt32(wh.filetype);
        wh.ncmds       = OSSwapInt32(wh.ncmds);
        wh.sizeofcmds  = OSSwapInt32(wh.sizeofcmds);
        wh.flags       = OSSwapInt32(wh.flags);
    }
    memcpy(data, &wh, sizeof(wh));

    return 0;
}

/* Strip every LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB whose name contains
 * `name_substr`. Zeroes the freed bytes at the tail and updates the header. */
static int unpatch_slice(uint8_t *data, uint64_t slice_size,
                         const char *name_substr,
                         char *err, size_t elen) {
    if (slice_size < sizeof(struct mach_header_64)) {
        seterr(err, elen, "slice too small"); return -1;
    }

    uint32_t magic;
    memcpy(&magic, data, 4);
    int swap;
    if      (magic == MH_MAGIC_64)  swap = 0;
    else if (magic == MH_CIGAM_64)  swap = 1;
    else { seterr(err, elen, "32-bit / unknown magic 0x%08x", magic); return -1; }

    struct mach_header_64 hdr;
    memcpy(&hdr, data, sizeof(hdr));
    if (swap) {
        hdr.cputype     = OSSwapInt32(hdr.cputype);
        hdr.cpusubtype  = OSSwapInt32(hdr.cpusubtype);
        hdr.filetype    = OSSwapInt32(hdr.filetype);
        hdr.ncmds       = OSSwapInt32(hdr.ncmds);
        hdr.sizeofcmds  = OSSwapInt32(hdr.sizeofcmds);
        hdr.flags       = OSSwapInt32(hdr.flags);
    }

    uint8_t *lc_cur = data + sizeof(struct mach_header_64);
    uint8_t *lc_end = lc_cur + hdr.sizeofcmds;
    if (lc_end > data + slice_size) {
        seterr(err, elen, "corrupt load commands"); return -1;
    }
    uint32_t removed = 0;

    uint32_t i = 0;
    while (i < hdr.ncmds && lc_cur + sizeof(struct load_command) <= lc_end) {
        struct load_command lc;
        memcpy(&lc, lc_cur, sizeof(lc));
        uint32_t cmd = swap ? OSSwapInt32(lc.cmd) : lc.cmd;
        uint32_t cmdsize = swap ? OSSwapInt32(lc.cmdsize) : lc.cmdsize;
        if (cmdsize < sizeof(struct load_command) || lc_cur + cmdsize > lc_end) {
            seterr(err, elen, "malformed lc at %u", i); return -1;
        }

        int is_dylib = (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB);
        int match = 0;
        if (is_dylib && cmdsize > sizeof(struct dylib_command)) {
            struct dylib_command dc;
            memcpy(&dc, lc_cur, sizeof(dc));
            uint32_t name_off = swap ? OSSwapInt32(dc.dylib.name.offset)
                                     : dc.dylib.name.offset;
            if (name_off < cmdsize) {
                const char *name = (const char *)(lc_cur + name_off);
                size_t maxlen = cmdsize - name_off;
                /* strnstr is BSD; do a manual contains check. */
                size_t nl = strnlen(name, maxlen);
                size_t sl = strlen(name_substr);
                for (size_t k = 0; sl <= nl && k + sl <= nl; k++) {
                    if (memcmp(name + k, name_substr, sl) == 0) { match = 1; break; }
                }
            }
        }

        if (match) {
            size_t tail = lc_end - (lc_cur + cmdsize);
            memmove(lc_cur, lc_cur + cmdsize, tail);
            memset(lc_end - cmdsize, 0, cmdsize);
            lc_end -= cmdsize;
            hdr.ncmds      -= 1;
            hdr.sizeofcmds -= cmdsize;
            removed++;
            /* don't advance lc_cur or i: the next lc has shifted into place. */
            continue;
        }
        lc_cur += cmdsize;
        i++;
    }

    if (removed == 0) return 0;  /* nothing to do for this slice; not an error */

    struct mach_header_64 wh = hdr;
    if (swap) {
        wh.cputype     = OSSwapInt32(wh.cputype);
        wh.cpusubtype  = OSSwapInt32(wh.cpusubtype);
        wh.filetype    = OSSwapInt32(wh.filetype);
        wh.ncmds       = OSSwapInt32(wh.ncmds);
        wh.sizeofcmds  = OSSwapInt32(wh.sizeofcmds);
        wh.flags       = OSSwapInt32(wh.flags);
    }
    memcpy(data, &wh, sizeof(wh));
    return (int)removed;
}

static int run_codesign(const char *path, char *err, size_t elen) {
    pid_t pid;
    char *const argv[] = { "codesign", "--force", "--sign", "-", (char *)path, NULL };
    int rc = posix_spawnp(&pid, "codesign", NULL, NULL, argv, environ);
    if (rc != 0) { seterr(err, elen, "spawn codesign: %s", strerror(rc)); return -1; }
    int st = 0;
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        seterr(err, elen, "codesign failed (exit %d)", WEXITSTATUS(st));
        return -1;
    }
    return 0;
}

int vm_stowaway_patch(const char *binary, const char *payload_install_name,
                      const vm_stowaway_patch_opts_t *opts,
                      char *errbuf, size_t errlen) {
    vm_stowaway_patch_opts_t defaults = { .resign = 1, .strip_existing_sig = 1 };
    if (!opts) opts = &defaults;

    const char *target = binary;
    if (opts->out_path && strcmp(opts->out_path, binary) != 0) {
        if (copy_file(binary, opts->out_path, errbuf, errlen) < 0) return -1;
        target = opts->out_path;
    }

    int fd = open(target, O_RDWR);
    if (fd < 0) { seterr(errbuf, errlen, "open(%s): %s", target, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { seterr(errbuf, errlen, "stat: %s", strerror(errno)); close(fd); return -1; }
    if (st.st_size < 4) { seterr(errbuf, errlen, "file too small"); close(fd); return -1; }

    uint8_t *data = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
    if (data == MAP_FAILED) {
        seterr(errbuf, errlen, "mmap: %s", strerror(errno));
        close(fd);
        return -1;
    }

    uint32_t magic;
    memcpy(&magic, data, 4);

    int rc = 0;
    if (magic == FAT_MAGIC || magic == FAT_CIGAM ||
        magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {

        int fat_swap = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
        int fat_64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
        struct fat_header fh;
        memcpy(&fh, data, sizeof(fh));
        uint32_t narch = fat_swap ? OSSwapInt32(fh.nfat_arch) : fh.nfat_arch;
        if (narch == 0 || narch > 32) {
            seterr(errbuf, errlen, "implausible fat_arch count %u", narch);
            rc = -1;
            goto out;
        }
        size_t off = sizeof(struct fat_header);
        for (uint32_t i = 0; i < narch; i++) {
            uint64_t slice_off = 0, slice_size = 0;
            if (fat_64) {
                struct fat_arch_64 fa;
                memcpy(&fa, data + off, sizeof(fa));
                slice_off  = fat_swap ? OSSwapInt64(fa.offset) : fa.offset;
                slice_size = fat_swap ? OSSwapInt64(fa.size)   : fa.size;
                off += sizeof(struct fat_arch_64);
            } else {
                struct fat_arch fa;
                memcpy(&fa, data + off, sizeof(fa));
                slice_off  = fat_swap ? OSSwapInt32(fa.offset) : fa.offset;
                slice_size = fat_swap ? OSSwapInt32(fa.size)   : fa.size;
                off += sizeof(struct fat_arch);
            }
            if (slice_off + slice_size > (uint64_t)st.st_size) {
                seterr(errbuf, errlen, "fat slice %u out of bounds", i);
                rc = -1;
                goto out;
            }
            rc = patch_slice(data + slice_off, slice_size,
                             payload_install_name, opts->weak,
                             opts->strip_existing_sig, errbuf, errlen);
            if (rc < 0) goto out;
        }
    } else {
        rc = patch_slice(data, (uint64_t)st.st_size,
                         payload_install_name, opts->weak,
                         opts->strip_existing_sig, errbuf, errlen);
        if (rc < 0) goto out;
    }

    msync(data, (size_t)st.st_size, MS_SYNC);

out:
    munmap(data, (size_t)st.st_size);
    close(fd);
    if (rc < 0) return -1;

    if (opts->resign) {
        if (run_codesign(target, errbuf, errlen) < 0) return -1;
    }
    return 0;
}

int vm_stowaway_unpatch(const char *binary, const char *name_substr,
                        const vm_stowaway_patch_opts_t *opts,
                        char *errbuf, size_t errlen) {
    vm_stowaway_patch_opts_t defaults = { .resign = 1 };
    if (!opts) opts = &defaults;
    if (!name_substr || !*name_substr) {
        seterr(errbuf, errlen, "empty name_substr"); return -1;
    }

    const char *target = binary;
    if (opts->out_path && strcmp(opts->out_path, binary) != 0) {
        if (copy_file(binary, opts->out_path, errbuf, errlen) < 0) return -1;
        target = opts->out_path;
    }

    int fd = open(target, O_RDWR);
    if (fd < 0) { seterr(errbuf, errlen, "open(%s): %s", target, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { seterr(errbuf, errlen, "stat: %s", strerror(errno)); close(fd); return -1; }
    if (st.st_size < 4) { seterr(errbuf, errlen, "file too small"); close(fd); return -1; }

    uint8_t *data = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
    if (data == MAP_FAILED) {
        seterr(errbuf, errlen, "mmap: %s", strerror(errno));
        close(fd);
        return -1;
    }

    uint32_t magic;
    memcpy(&magic, data, 4);

    int total_removed = 0;
    int rc = 0;
    if (magic == FAT_MAGIC || magic == FAT_CIGAM ||
        magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {

        int fat_swap = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
        int fat_64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
        struct fat_header fh;
        memcpy(&fh, data, sizeof(fh));
        uint32_t narch = fat_swap ? OSSwapInt32(fh.nfat_arch) : fh.nfat_arch;
        if (narch == 0 || narch > 32) {
            seterr(errbuf, errlen, "implausible fat_arch count %u", narch);
            rc = -1;
            goto out;
        }
        size_t off = sizeof(struct fat_header);
        for (uint32_t i = 0; i < narch; i++) {
            uint64_t slice_off = 0, slice_size = 0;
            if (fat_64) {
                struct fat_arch_64 fa;
                memcpy(&fa, data + off, sizeof(fa));
                slice_off  = fat_swap ? OSSwapInt64(fa.offset) : fa.offset;
                slice_size = fat_swap ? OSSwapInt64(fa.size)   : fa.size;
                off += sizeof(struct fat_arch_64);
            } else {
                struct fat_arch fa;
                memcpy(&fa, data + off, sizeof(fa));
                slice_off  = fat_swap ? OSSwapInt32(fa.offset) : fa.offset;
                slice_size = fat_swap ? OSSwapInt32(fa.size)   : fa.size;
                off += sizeof(struct fat_arch);
            }
            if (slice_off + slice_size > (uint64_t)st.st_size) {
                seterr(errbuf, errlen, "fat slice %u out of bounds", i);
                rc = -1;
                goto out;
            }
            int n = unpatch_slice(data + slice_off, slice_size,
                                  name_substr, errbuf, errlen);
            if (n < 0) { rc = -1; goto out; }
            total_removed += n;
        }
    } else {
        int n = unpatch_slice(data, (uint64_t)st.st_size,
                              name_substr, errbuf, errlen);
        if (n < 0) { rc = -1; goto out; }
        total_removed = n;
    }

    msync(data, (size_t)st.st_size, MS_SYNC);

out:
    munmap(data, (size_t)st.st_size);
    close(fd);
    if (rc < 0) return -1;

    if (total_removed == 0) {
        seterr(errbuf, errlen, "no matching LC_LOAD_DYLIB");
        return -1;
    }
    if (opts->resign) {
        if (run_codesign(target, errbuf, errlen) < 0) return -1;
    }
    return total_removed;
}
