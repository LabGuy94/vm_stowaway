# vm_stowaway

read and write memory in a macOS process by injecting a small dylib into it

two ways to get the payload in:

- `DYLD_INSERT_LIBRARIES` if you spawn the target. simple, but hardened runtime strips it on most signed apps
- `LC_LOAD_DYLIB` rewrite if you can write to the binary on disk. ad-hoc resigns, works on hardened apps

there's also a `DYLD_INTERPOSE` shim so existing memory tools (anything calling `task_for_pid` + the `mach_vm_*` family) work without SIP off / debug entitlements. wrap the tool with `vm_stowaway wrap` and its mach calls get routed to the payload sitting inside the target

## install

```
curl -fsSL https://raw.githubusercontent.com/LabGuy94/vm_stowaway/master/install.sh | bash
```

builds from source and installs to `/usr/local` (will `sudo` if needed). macOS 11+, universal (arm64 + x86_64). xcode CLI tools required (`xcode-select --install`)

or from source: `git clone https://github.com/LabGuy94/vm_stowaway && cd vm_stowaway && make && sudo make install`

## usage

```
vm_stowaway launch ./mytarget
vm_stowaway patch  ./mytarget "$PWD/build/libvm_stowaway_payload.dylib"

vm_stowaway resolve 1234 some_global
vm_stowaway read    1234 0x10000c000 64
vm_stowaway write   1234 0x10000c000 deadbeef

# tool's task_for_pid + mach_vm_* for pid 1234 routed through the payload
vm_stowaway wrap --pid 1234 -- /Applications/BitSlicer.app/Contents/MacOS/BitSlicer
```

`vm_stowaway --help` and `include/vm_stowaway.h` for the rest. `examples/controller_example.c` shows the library API end to end, `examples/mach_client.c` stands in for a memory-inspection tool exercising the shim
