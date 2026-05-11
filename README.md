# vm_stowaway

read and write memory in a macOS process by injecting a small dylib into it

two ways to get the payload in:

- `DYLD_INSERT_LIBRARIES` if you spawn the target. simple, but hardened runtime strips it on most signed apps
- `LC_LOAD_DYLIB` rewrite if you can write to the binary on disk. ad-hoc resigns, works on hardened apps

there's also a `DYLD_INTERPOSE` shim so existing memory tools (anything calling `task_for_pid` + the `mach_vm_*` family) work without SIP off / debug entitlements. wrap the tool with `vm_stowaway wrap` and its mach calls get routed to the payload sitting inside the target

## install

prebuilt universal binary from the latest release:

```
curl -fsSL https://github.com/LabGuy94/vm_stowaway/releases/latest/download/vm_stowaway-macos-universal.tar.gz | sudo tar xz -C /usr/local --strip-components=1
```

or build from source (needs xcode CLI tools):

```
curl -fsSL https://raw.githubusercontent.com/LabGuy94/vm_stowaway/master/install.sh | bash
# or:
git clone https://github.com/LabGuy94/vm_stowaway && cd vm_stowaway && make && sudo make install
```

macOS 11+, universal (arm64 + x86_64).

## usage

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

# tool's task_for_pid + mach_vm_* for pid 1234 routed through the payload
vm_stowaway wrap --pid 1234 -- /Applications/BitSlicer.app/Contents/MacOS/BitSlicer
```

`vm_stowaway --help` and `include/vm_stowaway.h` for the rest. `examples/controller_example.c` shows the library API end to end, `examples/mach_client.c` stands in for a memory-inspection tool exercising the shim
