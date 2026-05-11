# vm_stowaway

read and write memory in a macOS process by injecting a small dylib into it. ships as a static + dynamic C library, a `DYLD_INTERPOSE` shim that retrofits existing `mach_vm_*` tools, and a CLI wrapper around the same primitives.

two ways the payload gets in:

- `DYLD_INSERT_LIBRARIES` if you spawn the target. simple, but hardened runtime strips it on most signed apps
- `LC_LOAD_DYLIB` rewrite if you can write to the binary on disk. ad-hoc resigns, works on hardened apps

## install

```
curl -fsSL https://github.com/LabGuy94/vm_stowaway/releases/latest/download/vm_stowaway-macos-universal.tar.gz | sudo tar xz -C /usr/local --strip-components=1
```

or from source (needs xcode CLI tools):

```
curl -fsSL https://raw.githubusercontent.com/LabGuy94/vm_stowaway/master/install.sh | bash
# or:
git clone https://github.com/LabGuy94/vm_stowaway && cd vm_stowaway && make && sudo make install
```

installs `libvm_stowaway.{a,dylib}`, `libvm_stowaway_payload.dylib`, `libvm_stowaway_machshim.dylib`, `<prefix>/include/vm_stowaway.h`, and the `vm_stowaway` CLI. macOS 11+, universal (arm64 + x86_64).

## library

```c
#include <vm_stowaway.h>
```

link with `-lvm_stowaway`. the payload dylib has to exist somewhere the controller can find it at runtime — by default it looks next to its own binary, then via the dyld search path; pass `vm_stowaway_launch_opts_t.payload_path` to override.

spawn a target and rewrite a global:

```c
char err[256];
vm_stowaway_t *h = vm_stowaway_launch("./mytarget", argv, NULL, err, sizeof err);
if (!h) { fprintf(stderr, "%s\n", err); return 1; }

uint64_t addr = vm_stowaway_resolve(h, NULL, "g_secret");
uint64_t val  = 0xdeadbeef;
vm_stowaway_write(h, addr, &val, sizeof val);

vm_stowaway_close(h);
```

attach to a running, already-patched binary:

```c
vm_stowaway_t *h = vm_stowaway_attach(pid, NULL, 5, err, sizeof err);
```

call a function inside the target (up to 6 u64 args, return value in `ret`):

```c
uint64_t ret = 0;
uint64_t args[] = { 0x10 };
vm_stowaway_call(h, vm_stowaway_resolve(h, "libsystem_malloc", "malloc"),
                 args, 1, &ret);
```

software breakpoint, blocking wait, continue:

```c
uint32_t bp;
vm_stowaway_break_set(h, addr, &bp);
uint32_t fired; uint64_t tid, pc;
vm_stowaway_break_wait(h, -1, &fired, &tid, &pc);
/* inspect regs/memory here */
vm_stowaway_break_cont(h, tid);
```

mach-o patcher, standalone (no controller handle needed):

```c
vm_stowaway_patch_opts_t opts = { .resign = 1 };
vm_stowaway_patch("/path/to/binary", "@rpath/libvm_stowaway_payload.dylib",
                  &opts, err, sizeof err);
```

the full surface is in [`include/vm_stowaway.h`](include/vm_stowaway.h): `_read`, `_write`, `_resolve`, `_images`, `_regions`, `_scan`, `_threads`, `_thread_get_state`/`_set_state`, `_allocate`/`_deallocate`, `_call`, `_break_set`/`_wait`/`_clear`/`_cont`, `_dyld_info`, `_patch`/`_unpatch`, `_scan_hijacks`/`_hijack_drop`, `_find_pid`. examples in [`examples/controller_example.c`](examples/controller_example.c) (launch + read/write) and [`examples/attach_example.c`](examples/attach_example.c) (attach + call).

## shim

if you already have a memory-inspection tool that calls `task_for_pid` + the `mach_vm_*` family, `libvm_stowaway_machshim.dylib` is a drop-in: route those calls through the payload sitting inside the target, no SIP off / debug entitlements / `taskport.allow` needed.

```sh
DYLD_INSERT_LIBRARIES=/usr/local/lib/libvm_stowaway_machshim.dylib \
VM_STOWAWAY_TARGET_PID=1234 \
    your_memory_tool
```

env:

- `VM_STOWAWAY_TARGET_PID` — pid the tool is meant to inspect. required. `task_for_pid(self, pid, &t)` for this pid returns a sentinel port; every interposed mach call on that port is routed through the payload
- `VM_STOWAWAY_SOCK` — override the unix socket path (default `/tmp/vm_stowaway.<pid>.sock`)
- `VM_STOWAWAY_DEBUG` — set to anything to log interposed calls to stderr

interposed: `task_for_pid`, `pid_for_task`, `mach_vm_{read,read_overwrite,write,region,region_recurse,allocate,deallocate,protect}`, `task_{info,threads,suspend,resume,set_info}`, `thread_{get_state,set_state,info,suspend,resume,terminate}`, `mach_port_{deallocate,mod_refs,destroy}`, plus the legacy `vm_*` aliases. anything not interposed falls through.

`vm_stowaway wrap --pid <pid> -- <cmd> ...` is the CLI shortcut that sets the env vars and execs.

## cli

same primitives wrapped for shell:

```
vm_stowaway launch ./mytarget
vm_stowaway patch  ./mytarget "$PWD/build/libvm_stowaway_payload.dylib"
vm_stowaway unpatch ./mytarget libvm_stowaway_payload    # undo a patch

# target = pid OR process name
vm_stowaway resolve mytarget some_global
vm_stowaway read    1234 mytarget+0x1234 64 --syms
vm_stowaway write   1234 0x10000c000 deadbeef
vm_stowaway scan    1234 0x100000000 0x200000000 --i32 1337

# cheat-engine style: snapshot then filter
vm_stowaway diff start  1234 0x100000000 0x300000000 --i32 0
vm_stowaway diff filter 1234 changed

# call a function inside the target
vm_stowaway call 1234 0x19ed1215c              # = getpid()
vm_stowaway call 1234 libsystem_c.dylib+0xabc 1 2 3

# breakpoints (BRK/INT3 via mach exception ports)
vm_stowaway break set 1234 main+0x40
vm_stowaway break wait 1234
vm_stowaway break cont 1234 <tid>

# find apps already shipping with disable-library-validation + allow-dyld-environment
# (i.e. ones plain `launch` works against without any binary modification)
vm_stowaway scan-targets

# find Mach-O hijack candidates (writable paths where dropping a dylib makes
# the target load it as a missing dependency)
vm_stowaway scan-hijacks /Applications/Some.app/Contents/MacOS/Some
vm_stowaway hijack /Applications/Some.app/Contents/MacOS/Some --pick 0

# copy a hardened-runtime .app and ad-hoc resign it without hardened runtime
vm_stowaway unharden /Applications/Some.app /tmp/Some-open.app

# DYLD_INTERPOSE shim — see "shim" above
vm_stowaway wrap --pid 1234 -- /Applications/BitSlicer.app/Contents/MacOS/BitSlicer
```

`vm_stowaway --help` for the rest.
