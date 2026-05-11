# vm_stowaway — python

ctypes bindings for `libvm_stowaway.dylib`. requires the native library; pip-install this package after you've installed the dylib (`/usr/local/lib/libvm_stowaway.dylib` is searched by default).

```sh
# get the native side first
curl -fsSL https://github.com/LabGuy94/vm_stowaway/releases/latest/download/vm_stowaway-macos-universal.tar.gz \
  | sudo tar xz -C /usr/local --strip-components=1

# then:
pip install ./python    # or `pip install vm_stowaway` once on pypi
```

```python
import vm_stowaway as vms

with vms.launch("./mytarget") as h:
    addr = h.resolve("g_secret")
    h.write_u32(addr, 0x1337)
    print(h.read_u32(addr))

# attach by pid (or name)
pid = vms.find_pid("Some.app") or 1234
with vms.attach(pid) as h:
    getpid = h.resolve("getpid", image="libsystem_c")
    print(h.call(getpid))   # should equal pid

# patcher / hijack / scanners (no handle needed)
vms.patch("/path/to/binary", "@rpath/libvm_stowaway_payload.dylib")
for app in vms.scan_apps(permissive_only=True):
    print(app.path)
```

env:

- `VM_STOWAWAY_LIB` — explicit path to `libvm_stowaway.dylib`. otherwise the loader searches next to the python module, `/usr/local/lib`, `/opt/homebrew/lib`, then `ctypes.util.find_library`.
