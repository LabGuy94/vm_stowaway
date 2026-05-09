#ifndef VM_STOWAWAY_H
#define VM_STOWAWAY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * vm_stowaway: a library for reading and writing memory of a target macOS
 * process via a dylib that runs inside it.
 *
 * Spawn the target with vm_stowaway_launch(), which sets DYLD_INSERT_LIBRARIES
 * to point at the payload dylib. The payload listens on a Unix socket; the
 * controller (the side that links this header) talks to it via the functions
 * below.
 */

typedef struct vm_stowaway vm_stowaway_t;

typedef struct {
    /* Path to the payload dylib. If NULL, libvm_stowaway_payload.dylib is
     * resolved next to the controller binary, then via DYLD search. */
    const char *payload_path;

    /* Unix socket path. If NULL, /tmp/vm_stowaway.<pid>.sock is used after
     * the child reports its pid. */
    const char *socket_path;

    /* Seconds to wait for the payload to connect back. 0 -> 10s default. */
    int connect_timeout_s;

    /* If non-NULL, extra environment for the child (NULL-terminated). The
     * controller adds DYLD_INSERT_LIBRARIES and VM_STOWAWAY_SOCK on top. */
    char *const *extra_env;
} vm_stowaway_launch_opts_t;

typedef struct {
    uint64_t base;
    uint64_t slide;
    char     path[1024];
} vm_stowaway_image_t;

typedef struct {
    uint64_t base;
    uint64_t size;
    uint32_t prot;  /* VM_PROT_READ=1, WRITE=2, EXECUTE=4 */
} vm_stowaway_region_t;

/* -- lifecycle ---------------------------------------------------------- */

/* Spawn `path` with argv, injecting the payload via DYLD_INSERT_LIBRARIES.
 * Returns a handle, or NULL on error (errno set, errbuf filled if given). */
vm_stowaway_t *vm_stowaway_launch(const char *path,
                                  char *const argv[],
                                  const vm_stowaway_launch_opts_t *opts,
                                  char *errbuf, size_t errlen);

/* Connect to an already-running process that hosts the payload (i.e. was
 * launched with DYLD_INSERT_LIBRARIES outside of this library). */
vm_stowaway_t *vm_stowaway_attach(pid_t pid,
                                  const char *socket_path,
                                  int connect_timeout_s,
                                  char *errbuf, size_t errlen);

void vm_stowaway_close(vm_stowaway_t *h);

/* Underlying pid of the target. */
pid_t vm_stowaway_pid(const vm_stowaway_t *h);

/* -- memory operations -------------------------------------------------- */

/* Read up to `len` bytes from `addr` into `buf`. Returns bytes read, or -1
 * on error. Reads use mach_vm_read_overwrite inside the target so bad
 * addresses fail cleanly instead of crashing the host. */
ssize_t vm_stowaway_read(vm_stowaway_t *h,
                         uint64_t addr, void *buf, size_t len);

/* Write `len` bytes from `buf` to `addr`. Returns bytes written, -1 on
 * error. Pages are made writable first via mach_vm_protect. */
ssize_t vm_stowaway_write(vm_stowaway_t *h,
                          uint64_t addr, const void *buf, size_t len);

/* Resolve a symbol. `image` is a substring matched against loaded image
 * paths (e.g. "Foundation" matches /System/Library/.../Foundation), or
 * NULL to search the main executable. Returns the absolute address, or 0
 * if not found. */
uint64_t vm_stowaway_resolve(vm_stowaway_t *h,
                             const char *image,
                             const char *symbol);

/* List loaded Mach-O images. Writes up to `max` entries to `out`, returns
 * the total count (which may exceed `max`). */
ssize_t vm_stowaway_images(vm_stowaway_t *h,
                           vm_stowaway_image_t *out, size_t max);

/* Enumerate VM regions in the target. Writes up to `max`, returns total. */
ssize_t vm_stowaway_regions(vm_stowaway_t *h,
                            vm_stowaway_region_t *out, size_t max);

/* Scan [start, end) for `pattern` of `pat_len` bytes. `mask` may be NULL
 * (exact match) or `pat_len` bytes where 0xFF=match, 0x00=wildcard. Writes
 * up to `max_hits` matching addresses to `out`, returns the total count. */
ssize_t vm_stowaway_scan(vm_stowaway_t *h,
                         uint64_t start, uint64_t end,
                         const uint8_t *pattern, const uint8_t *mask,
                         size_t pat_len,
                         uint64_t *out, size_t max_hits);

/* -- diagnostics -------------------------------------------------------- */

const char *vm_stowaway_last_error(const vm_stowaway_t *h);

#ifdef __cplusplus
}
#endif

#endif
