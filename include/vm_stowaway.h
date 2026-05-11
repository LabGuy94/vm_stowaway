#ifndef VM_STOWAWAY_H
#define VM_STOWAWAY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* read/write memory in a macOS process via an in-target payload dylib.
 * payload gets in via vm_stowaway_launch (DYLD_INSERT) or vm_stowaway_patch
 * (LC_LOAD_DYLIB rewrite + ad-hoc resign). */

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

    /* Extra env appended to the inherited environ (NULL-terminated). The
     * controller always sets DYLD_INSERT_LIBRARIES and VM_STOWAWAY_SOCK. */
    char *const *extra_env;
} vm_stowaway_launch_opts_t;

typedef struct {
    /* Output path. NULL -> patch in place. */
    const char *out_path;

    /* If true, emit LC_LOAD_WEAK_DYLIB so a missing payload doesn't abort
     * the host. Useful when shipping a patched binary that should still run
     * without the payload installed. */
    int weak;

    /* If true (default), shell out to `codesign --force --sign -` after
     * patching. Set to 0 if you'll sign separately. */
    int resign;

    /* If true, also strip an existing LC_CODE_SIGNATURE load command before
     * resigning. Set to 0 to leave it alone (codesign will overwrite). */
    int strip_existing_sig;
} vm_stowaway_patch_opts_t;

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

/* lifecycle. */

/* Spawn `path` with argv, injecting the payload via DYLD_INSERT_LIBRARIES.
 * Returns a handle, or NULL on error (errno set, errbuf filled if given). */
vm_stowaway_t *vm_stowaway_launch(const char *path,
                                  char *const argv[],
                                  const vm_stowaway_launch_opts_t *opts,
                                  char *errbuf, size_t errlen);

/* Connect to a process whose binary was patched with vm_stowaway_patch and
 * which is already running. `pid` must be that process's pid. */
vm_stowaway_t *vm_stowaway_attach(pid_t pid,
                                  const char *socket_path,
                                  int connect_timeout_s,
                                  char *errbuf, size_t errlen);

void vm_stowaway_close(vm_stowaway_t *h);

/* Underlying pid of the target. */
pid_t vm_stowaway_pid(const vm_stowaway_t *h);

/* Look up the first process whose comm or executable basename equals `name`.
 * Returns the pid, or -1 if no match. Skips our own pid. */
pid_t vm_stowaway_find_pid(const char *name);

/* mach-o patcher. */

/* Add an LC_LOAD_DYLIB to `binary` pointing at `payload_install_name`.
 * Returns 0 on success, -1 on error. */
int vm_stowaway_patch(const char *binary,
                      const char *payload_install_name,
                      const vm_stowaway_patch_opts_t *opts,
                      char *errbuf, size_t errlen);

/* Strip every LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB whose name contains `name_substr`
 * from `binary`, in every Mach-O slice. ad-hoc resigns by default. */
int vm_stowaway_unpatch(const char *binary,
                        const char *name_substr,
                        const vm_stowaway_patch_opts_t *opts,
                        char *errbuf, size_t errlen);

/* memory ops. */

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

/* task / threads / alloc. */

/* Fetch the target's task_dyld_info (address + size + format of the
 * dyld_all_image_infos struct in the target's address space). */
int vm_stowaway_dyld_info(vm_stowaway_t *h,
                          uint64_t *all_image_info_addr,
                          uint64_t *all_image_info_size,
                          uint32_t *all_image_info_format);

/* List thread IDs in the target. Writes up to `max` ids; returns total. */
ssize_t vm_stowaway_threads(vm_stowaway_t *h,
                            uint64_t *tids_out, size_t max);

/* Get a thread's register state. `flavor` is a Mach thread_state_flavor_t
 * (e.g. ARM_THREAD_STATE64). On entry *count is the number of natural_t
 * (uint32_t) units the caller can accept; on exit it's how many were
 * written. Returns 0 on success, -1 on error. */
int vm_stowaway_thread_get_state(vm_stowaway_t *h,
                                 uint64_t tid, uint32_t flavor,
                                 uint32_t *count, void *state_out,
                                 size_t state_capacity);

/* Set a thread's register state. */
int vm_stowaway_thread_set_state(vm_stowaway_t *h,
                                 uint64_t tid, uint32_t flavor,
                                 uint32_t count, const void *state);

/* Allocate `size` bytes inside the target. Returns the address, or 0 on
 * failure. `flags` is VM_FLAGS_ANYWHERE etc. */
uint64_t vm_stowaway_allocate(vm_stowaway_t *h, uint64_t size, int flags);

/* Free memory previously allocated in the target. */
int vm_stowaway_deallocate(vm_stowaway_t *h, uint64_t addr, uint64_t size);

/* Invoke a function inside the target: addr(args[0]..args[nargs-1]).
 * Up to 6 u64 args. Returns the function's return value via *out_ret. */
int vm_stowaway_call(vm_stowaway_t *h, uint64_t addr,
                     const uint64_t *args, uint32_t nargs,
                     uint64_t *out_ret);

/* Software breakpoints (BRK/INT3). Set returns an opaque id; clear removes the
 * trap. wait blocks until any breakpoint fires, returning the firing bp_id, the
 * thread id, and the pc of the trap. cont restores the original instruction at
 * that bp and resumes the suspended thread (so the same bp will not fire again
 * unless you re-arm). timeout_ms < 0 means wait forever; 0 = poll. */
int vm_stowaway_break_set(vm_stowaway_t *h, uint64_t addr, uint32_t *out_bp_id);
int vm_stowaway_break_clear(vm_stowaway_t *h, uint32_t bp_id);
int vm_stowaway_break_wait(vm_stowaway_t *h, int timeout_ms,
                           uint32_t *bp_id, uint64_t *tid, uint64_t *pc);
int vm_stowaway_break_cont(vm_stowaway_t *h, uint64_t tid);

/* Negotiated payload protocol version + pid. */
int vm_stowaway_remote_info(vm_stowaway_t *h, uint32_t *version, uint64_t *pid);

/* diagnostics. */

const char *vm_stowaway_last_error(const vm_stowaway_t *h);

#ifdef __cplusplus
}
#endif

#endif
