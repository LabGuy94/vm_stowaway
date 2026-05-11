# vm_stowaway

Read and write memory in a macOS process by injecting a small dylib into it.

Two injection backends:

- `DYLD_INSERT_LIBRARIES` (spawn the target yourself). Simple, but stripped
  by hardened runtime + library validation on most signed apps.
- `LC_LOAD_DYLIB` rewrite (patch the binary, ad-hoc resign). Works on
  hardened-runtime apps you can write to on disk.

There's also a `DYLD_INTERPOSE` shim that makes existing memory-inspection
tools (anything that calls `task_for_pid` + the `mach_vm_*` family) work
without SIP off / debug entitlements. Wrap the tool with `vm_stowaway
wrap` and its mach calls get routed to a payload running inside the target.

## Build

```
make
```

macOS 11+ (arm64 + x86_64)

## Usage

```
vm_stowaway launch ./mytarget
vm_stowaway patch  ./mytarget "$PWD/build/libvm_stowaway_payload.dylib"

vm_stowaway resolve 1234 some_global
vm_stowaway read    1234 0x10000c000 64
vm_stowaway write   1234 0x10000c000 deadbeef

# Run a memory-inspection tool with the mach shim. The tool's task_for_pid
# + mach_vm_* calls for pid 1234 get routed through the payload.
vm_stowaway wrap --pid 1234 -- /Applications/BitSlicer.app/Contents/MacOS/BitSlicer
```

See `vm_stowaway --help` and `include/vm_stowaway.h` for the rest.
`examples/controller_example.c` shows the library API end to end.
`examples/mach_client.c` is a stand-in for a real memory-inspection tool
that exercises the shim directly.
