"""ctypes bindings for libvm_stowaway.

usage:
    import vm_stowaway as vms

    with vms.launch("./mytarget") as h:
        addr = h.resolve("g_secret")
        h.write_u32(addr, 0x1337)
        print(h.read(addr, 4).hex())

    with vms.attach(pid) as h:
        ret = h.call(h.resolve("getpid", image="libsystem_c"))

the dylib is located by, in order:
    1. VM_STOWAWAY_LIB env var
    2. libvm_stowaway.dylib next to this module
    3. /usr/local/lib/libvm_stowaway.dylib
    4. /opt/homebrew/lib/libvm_stowaway.dylib
    5. ctypes.util.find_library("vm_stowaway")
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from ctypes import (
    POINTER, byref, c_char, c_char_p, c_int, c_size_t, c_ssize_t,
    c_uint8, c_uint32, c_uint64, c_void_p,
)
from typing import Optional, Sequence

__all__ = [
    "VMStowawayError",
    "LaunchOpts", "PatchOpts",
    "Image", "Region", "Hijack", "App", "Electron",
    "Handle",
    "launch", "attach", "find_pid",
    "patch", "unpatch",
    "scan_hijacks", "hijack_drop",
    "scan_apps", "scan_electron", "find_app_bundle", "unharden",
]


# library loading --------------------------------------------------------

def _load_library() -> ctypes.CDLL:
    if sys.platform != "darwin":
        raise RuntimeError("vm_stowaway only runs on macOS")
    candidates = []
    env = os.environ.get("VM_STOWAWAY_LIB")
    if env:
        candidates.append(env)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates += [
        os.path.join(here, "libvm_stowaway.dylib"),
        "/usr/local/lib/libvm_stowaway.dylib",
        "/opt/homebrew/lib/libvm_stowaway.dylib",
    ]
    found = ctypes.util.find_library("vm_stowaway")
    if found:
        candidates.append(found)
    last_err: Optional[OSError] = None
    for path in candidates:
        if not path:
            continue
        try:
            return ctypes.CDLL(path)
        except OSError as e:
            last_err = e
    raise OSError(
        "couldn't load libvm_stowaway.dylib; set VM_STOWAWAY_LIB or install "
        "to /usr/local/lib. last error: %s" % last_err
    )


_lib = _load_library()


# types ------------------------------------------------------------------

class _CLaunchOpts(ctypes.Structure):
    _fields_ = [
        ("payload_path",       c_char_p),
        ("socket_path",        c_char_p),
        ("connect_timeout_s",  c_int),
        ("extra_env",          POINTER(c_char_p)),
    ]


class _CPatchOpts(ctypes.Structure):
    _fields_ = [
        ("out_path",           c_char_p),
        ("weak",               c_int),
        ("resign",             c_int),
        ("strip_existing_sig", c_int),
    ]


class _CImage(ctypes.Structure):
    _fields_ = [
        ("base",  c_uint64),
        ("slide", c_uint64),
        ("path",  c_char * 1024),
    ]


class _CRegion(ctypes.Structure):
    _fields_ = [
        ("base", c_uint64),
        ("size", c_uint64),
        ("prot", c_uint32),
    ]


class _CHijack(ctypes.Structure):
    _fields_ = [
        ("path",     c_char * 1024),
        ("dep_name", c_char * 256),
        ("weak",     c_int),
    ]


class _CApp(ctypes.Structure):
    _fields_ = [
        ("path",            c_char * 1024),
        ("allow_dyld_env",  c_int),
        ("disable_lib_val", c_int),
    ]


class _CElectron(ctypes.Structure):
    _fields_ = [
        ("path",        c_char * 1024),
        ("run_as_node", c_int),
    ]


# function prototypes ----------------------------------------------------

def _bind(name: str, restype, argtypes):
    fn = getattr(_lib, name)
    fn.restype = restype
    fn.argtypes = argtypes
    return fn


_p_void = c_void_p

_vm_stowaway_launch        = _bind("vm_stowaway_launch", _p_void,
    [c_char_p, POINTER(c_char_p), POINTER(_CLaunchOpts), c_char_p, c_size_t])
_vm_stowaway_attach        = _bind("vm_stowaway_attach", _p_void,
    [c_int, c_char_p, c_int, c_char_p, c_size_t])
_vm_stowaway_close         = _bind("vm_stowaway_close", None, [_p_void])
_vm_stowaway_pid           = _bind("vm_stowaway_pid", c_int, [_p_void])
_vm_stowaway_find_pid      = _bind("vm_stowaway_find_pid", c_int, [c_char_p])
_vm_stowaway_remote_info   = _bind("vm_stowaway_remote_info", c_int,
    [_p_void, POINTER(c_uint32), POINTER(c_uint64)])
_vm_stowaway_last_error    = _bind("vm_stowaway_last_error", c_char_p, [_p_void])

_vm_stowaway_read          = _bind("vm_stowaway_read", c_ssize_t,
    [_p_void, c_uint64, c_void_p, c_size_t])
_vm_stowaway_write         = _bind("vm_stowaway_write", c_ssize_t,
    [_p_void, c_uint64, c_void_p, c_size_t])
_vm_stowaway_resolve       = _bind("vm_stowaway_resolve", c_uint64,
    [_p_void, c_char_p, c_char_p])

_vm_stowaway_images        = _bind("vm_stowaway_images", c_ssize_t,
    [_p_void, POINTER(_CImage), c_size_t])
_vm_stowaway_regions       = _bind("vm_stowaway_regions", c_ssize_t,
    [_p_void, POINTER(_CRegion), c_size_t])
_vm_stowaway_scan          = _bind("vm_stowaway_scan", c_ssize_t,
    [_p_void, c_uint64, c_uint64,
     POINTER(c_uint8), POINTER(c_uint8), c_size_t,
     POINTER(c_uint64), c_size_t])

_vm_stowaway_dyld_info     = _bind("vm_stowaway_dyld_info", c_int,
    [_p_void, POINTER(c_uint64), POINTER(c_uint64), POINTER(c_uint32)])

_vm_stowaway_threads       = _bind("vm_stowaway_threads", c_ssize_t,
    [_p_void, POINTER(c_uint64), c_size_t])
_vm_stowaway_thread_get_state = _bind("vm_stowaway_thread_get_state", c_int,
    [_p_void, c_uint64, c_uint32, POINTER(c_uint32), c_void_p, c_size_t])
_vm_stowaway_thread_set_state = _bind("vm_stowaway_thread_set_state", c_int,
    [_p_void, c_uint64, c_uint32, c_uint32, c_void_p])

_vm_stowaway_allocate      = _bind("vm_stowaway_allocate", c_uint64,
    [_p_void, c_uint64, c_int])
_vm_stowaway_deallocate    = _bind("vm_stowaway_deallocate", c_int,
    [_p_void, c_uint64, c_uint64])

_vm_stowaway_call          = _bind("vm_stowaway_call", c_int,
    [_p_void, c_uint64, POINTER(c_uint64), c_uint32, POINTER(c_uint64)])

_vm_stowaway_break_set     = _bind("vm_stowaway_break_set", c_int,
    [_p_void, c_uint64, POINTER(c_uint32)])
_vm_stowaway_break_clear   = _bind("vm_stowaway_break_clear", c_int,
    [_p_void, c_uint32])
_vm_stowaway_break_wait    = _bind("vm_stowaway_break_wait", c_int,
    [_p_void, c_int, POINTER(c_uint32), POINTER(c_uint64), POINTER(c_uint64)])
_vm_stowaway_break_cont    = _bind("vm_stowaway_break_cont", c_int,
    [_p_void, c_uint64])

_vm_stowaway_patch         = _bind("vm_stowaway_patch", c_int,
    [c_char_p, c_char_p, POINTER(_CPatchOpts), c_char_p, c_size_t])
_vm_stowaway_unpatch       = _bind("vm_stowaway_unpatch", c_int,
    [c_char_p, c_char_p, POINTER(_CPatchOpts), c_char_p, c_size_t])
_vm_stowaway_scan_hijacks  = _bind("vm_stowaway_scan_hijacks", c_ssize_t,
    [c_char_p, POINTER(_CHijack), c_size_t, c_char_p, c_size_t])
_vm_stowaway_hijack_drop   = _bind("vm_stowaway_hijack_drop", c_int,
    [c_char_p, c_char_p, c_char_p, c_size_t])

_vm_stowaway_scan_apps     = _bind("vm_stowaway_scan_apps", c_ssize_t,
    [c_char_p, c_int, POINTER(_CApp), c_size_t, c_char_p, c_size_t])
_vm_stowaway_scan_electron = _bind("vm_stowaway_scan_electron", c_ssize_t,
    [c_char_p, POINTER(_CElectron), c_size_t, c_char_p, c_size_t])
_vm_stowaway_find_app_bundle = _bind("vm_stowaway_find_app_bundle", c_int,
    [c_char_p, c_char_p, c_size_t])
_vm_stowaway_unharden      = _bind("vm_stowaway_unharden", c_int,
    [c_char_p, c_char_p, c_char_p, c_size_t])


# python-side types ------------------------------------------------------

class VMStowawayError(Exception):
    pass


class LaunchOpts:
    __slots__ = ("payload_path", "socket_path", "connect_timeout_s", "extra_env")

    def __init__(self, payload_path: Optional[str] = None,
                 socket_path: Optional[str] = None,
                 connect_timeout_s: int = 0,
                 extra_env: Optional[Sequence[str]] = None) -> None:
        self.payload_path = payload_path
        self.socket_path = socket_path
        self.connect_timeout_s = connect_timeout_s
        self.extra_env = extra_env

    def _c(self) -> _CLaunchOpts:
        envp = None
        if self.extra_env:
            arr_t = c_char_p * (len(self.extra_env) + 1)
            envp = arr_t(*[e.encode() for e in self.extra_env], None)
        return _CLaunchOpts(
            self.payload_path.encode() if self.payload_path else None,
            self.socket_path.encode() if self.socket_path else None,
            self.connect_timeout_s,
            envp,
        )


class PatchOpts:
    __slots__ = ("out_path", "weak", "resign", "strip_existing_sig")

    def __init__(self, out_path: Optional[str] = None,
                 weak: bool = False, resign: bool = True,
                 strip_existing_sig: bool = False) -> None:
        self.out_path = out_path
        self.weak = weak
        self.resign = resign
        self.strip_existing_sig = strip_existing_sig

    def _c(self) -> _CPatchOpts:
        return _CPatchOpts(
            self.out_path.encode() if self.out_path else None,
            int(self.weak), int(self.resign), int(self.strip_existing_sig),
        )


class Image:
    __slots__ = ("base", "slide", "path")

    def __init__(self, base: int, slide: int, path: str) -> None:
        self.base = base
        self.slide = slide
        self.path = path

    def __repr__(self) -> str:
        return f"Image(base=0x{self.base:x}, slide=0x{self.slide:x}, path={self.path!r})"


class Region:
    __slots__ = ("base", "size", "prot")

    def __init__(self, base: int, size: int, prot: int) -> None:
        self.base = base
        self.size = size
        self.prot = prot

    def __repr__(self) -> str:
        rwx = "".join(c if (self.prot >> i) & 1 else "-" for i, c in enumerate("rwx"))
        return f"Region(base=0x{self.base:x}, size=0x{self.size:x}, prot={rwx})"


class Hijack:
    __slots__ = ("path", "dep_name", "weak")

    def __init__(self, path: str, dep_name: str, weak: bool) -> None:
        self.path = path
        self.dep_name = dep_name
        self.weak = weak

    def __repr__(self) -> str:
        return f"Hijack(path={self.path!r}, dep_name={self.dep_name!r}, weak={self.weak})"


class App:
    __slots__ = ("path", "allow_dyld_env", "disable_lib_val")

    def __init__(self, path: str, allow_dyld_env: bool, disable_lib_val: bool) -> None:
        self.path = path
        self.allow_dyld_env = allow_dyld_env
        self.disable_lib_val = disable_lib_val

    def __repr__(self) -> str:
        return (f"App(path={self.path!r}, allow_dyld_env={self.allow_dyld_env}, "
                f"disable_lib_val={self.disable_lib_val})")


class Electron:
    __slots__ = ("path", "run_as_node")

    def __init__(self, path: str, run_as_node: Optional[bool]) -> None:
        self.path = path
        self.run_as_node = run_as_node  # True/False/None

    def __repr__(self) -> str:
        return f"Electron(path={self.path!r}, run_as_node={self.run_as_node})"


# handle wrapper ---------------------------------------------------------

class Handle:
    """Wraps a vm_stowaway_t*. Use vms.launch() or vms.attach() to create one."""

    def __init__(self, ptr: int) -> None:
        if not ptr:
            raise VMStowawayError("null handle")
        self._ptr = ctypes.c_void_p(ptr)

    def __enter__(self) -> "Handle":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def close(self) -> None:
        if self._ptr:
            _vm_stowaway_close(self._ptr)
            self._ptr = ctypes.c_void_p(0)

    @property
    def pid(self) -> int:
        return _vm_stowaway_pid(self._ptr)

    def _err(self, op: str) -> VMStowawayError:
        msg = _vm_stowaway_last_error(self._ptr)
        return VMStowawayError(f"{op}: {msg.decode() if msg else '<no message>'}")

    def remote_info(self) -> tuple[int, int]:
        ver = c_uint32(0)
        rpid = c_uint64(0)
        if _vm_stowaway_remote_info(self._ptr, byref(ver), byref(rpid)) < 0:
            raise self._err("remote_info")
        return ver.value, rpid.value

    # memory ---

    def read(self, addr: int, length: int) -> bytes:
        buf = (c_uint8 * length)()
        got = _vm_stowaway_read(self._ptr, addr, buf, length)
        if got < 0:
            raise self._err(f"read(0x{addr:x}, {length})")
        return bytes(buf[:got])

    def write(self, addr: int, data: bytes) -> int:
        buf = (c_uint8 * len(data)).from_buffer_copy(data)
        n = _vm_stowaway_write(self._ptr, addr, buf, len(data))
        if n < 0:
            raise self._err(f"write(0x{addr:x}, len={len(data)})")
        return n

    def read_u8(self,  addr: int) -> int: return self.read(addr, 1)[0]
    def read_u16(self, addr: int) -> int: return int.from_bytes(self.read(addr, 2), "little")
    def read_u32(self, addr: int) -> int: return int.from_bytes(self.read(addr, 4), "little")
    def read_u64(self, addr: int) -> int: return int.from_bytes(self.read(addr, 8), "little")

    def write_u8(self,  addr: int, val: int) -> None: self.write(addr, val.to_bytes(1, "little"))
    def write_u16(self, addr: int, val: int) -> None: self.write(addr, val.to_bytes(2, "little"))
    def write_u32(self, addr: int, val: int) -> None: self.write(addr, val.to_bytes(4, "little"))
    def write_u64(self, addr: int, val: int) -> None: self.write(addr, val.to_bytes(8, "little"))

    def resolve(self, symbol: str, image: Optional[str] = None) -> int:
        addr = _vm_stowaway_resolve(
            self._ptr,
            image.encode() if image else None,
            symbol.encode(),
        )
        if addr == 0:
            raise self._err(f"resolve({image!r}, {symbol!r})")
        return addr

    def images(self) -> list[Image]:
        return _grow_array(
            lambda buf, n: _vm_stowaway_images(self._ptr, buf, n),
            _CImage,
            lambda c: Image(c.base, c.slide, c.path.decode(errors="replace")),
        )

    def regions(self) -> list[Region]:
        return _grow_array(
            lambda buf, n: _vm_stowaway_regions(self._ptr, buf, n),
            _CRegion,
            lambda c: Region(c.base, c.size, c.prot),
        )

    def scan(self, start: int, end: int, pattern: bytes,
             mask: Optional[bytes] = None, max_hits: int = 1024) -> list[int]:
        if mask is not None and len(mask) != len(pattern):
            raise ValueError("mask must be same length as pattern")
        pat = (c_uint8 * len(pattern)).from_buffer_copy(pattern)
        msk = (c_uint8 * len(mask)).from_buffer_copy(mask) if mask else None
        out = (c_uint64 * max_hits)()
        n = _vm_stowaway_scan(self._ptr, start, end,
                              pat, msk, len(pattern), out, max_hits)
        if n < 0:
            raise self._err("scan")
        return [out[i] for i in range(min(n, max_hits))]

    # task / threads / alloc ---

    def dyld_info(self) -> tuple[int, int, int]:
        addr = c_uint64(0); size = c_uint64(0); fmt = c_uint32(0)
        if _vm_stowaway_dyld_info(self._ptr, byref(addr), byref(size), byref(fmt)) < 0:
            raise self._err("dyld_info")
        return addr.value, size.value, fmt.value

    def threads(self) -> list[int]:
        return _grow_array(
            lambda buf, n: _vm_stowaway_threads(self._ptr, buf, n),
            c_uint64,
            lambda v: v,
        )

    def thread_get_state(self, tid: int, flavor: int, max_units: int = 64) -> tuple[int, bytes]:
        count = c_uint32(max_units)
        buf = (c_uint32 * max_units)()
        if _vm_stowaway_thread_get_state(self._ptr, tid, flavor, byref(count),
                                          buf, max_units * 4) < 0:
            raise self._err("thread_get_state")
        return count.value, bytes(buf)[: count.value * 4]

    def thread_set_state(self, tid: int, flavor: int, state: bytes) -> None:
        if len(state) % 4 != 0:
            raise ValueError("state length must be a multiple of 4 (natural_t units)")
        count = len(state) // 4
        buf = (c_uint8 * len(state)).from_buffer_copy(state)
        if _vm_stowaway_thread_set_state(self._ptr, tid, flavor, count, buf) < 0:
            raise self._err("thread_set_state")

    def allocate(self, size: int, flags: int = 0) -> int:
        addr = _vm_stowaway_allocate(self._ptr, size, flags)
        if addr == 0:
            raise self._err(f"allocate({size})")
        return addr

    def deallocate(self, addr: int, size: int) -> None:
        if _vm_stowaway_deallocate(self._ptr, addr, size) < 0:
            raise self._err(f"deallocate(0x{addr:x}, {size})")

    def call(self, addr: int, args: Sequence[int] = ()) -> int:
        if len(args) > 6:
            raise ValueError("up to 6 args supported")
        n = len(args)
        argv = (c_uint64 * max(n, 1))(*args)
        ret = c_uint64(0)
        if _vm_stowaway_call(self._ptr, addr, argv, n, byref(ret)) < 0:
            raise self._err(f"call(0x{addr:x})")
        return ret.value

    # breakpoints ---

    def break_set(self, addr: int) -> int:
        bp = c_uint32(0)
        if _vm_stowaway_break_set(self._ptr, addr, byref(bp)) < 0:
            raise self._err(f"break_set(0x{addr:x})")
        return bp.value

    def break_clear(self, bp_id: int) -> None:
        if _vm_stowaway_break_clear(self._ptr, bp_id) < 0:
            raise self._err(f"break_clear({bp_id})")

    def break_wait(self, timeout_ms: int = -1) -> tuple[int, int, int]:
        bp = c_uint32(0); tid = c_uint64(0); pc = c_uint64(0)
        rc = _vm_stowaway_break_wait(self._ptr, timeout_ms, byref(bp),
                                      byref(tid), byref(pc))
        if rc < 0:
            raise self._err("break_wait")
        return bp.value, tid.value, pc.value

    def break_cont(self, tid: int) -> None:
        if _vm_stowaway_break_cont(self._ptr, tid) < 0:
            raise self._err(f"break_cont({tid})")


# module-level entry points ---------------------------------------------

def launch(path: str, argv: Optional[Sequence[str]] = None,
           opts: Optional[LaunchOpts] = None) -> Handle:
    """Spawn `path` with the payload injected via DYLD_INSERT_LIBRARIES."""
    full_argv = [path] + list(argv or [])
    arr_t = c_char_p * (len(full_argv) + 1)
    cargv = arr_t(*[a.encode() for a in full_argv], None)
    copts = (opts or LaunchOpts())._c()
    err = ctypes.create_string_buffer(256)
    h = _vm_stowaway_launch(path.encode(), cargv, byref(copts), err, len(err))
    if not h:
        raise VMStowawayError(f"launch({path!r}): {err.value.decode(errors='replace')}")
    return Handle(h)


def attach(pid: int, socket_path: Optional[str] = None,
           connect_timeout_s: int = 5) -> Handle:
    """Attach to a running, payload-loaded process by pid."""
    err = ctypes.create_string_buffer(256)
    h = _vm_stowaway_attach(
        pid,
        socket_path.encode() if socket_path else None,
        connect_timeout_s,
        err, len(err),
    )
    if not h:
        raise VMStowawayError(f"attach({pid}): {err.value.decode(errors='replace')}")
    return Handle(h)


def find_pid(name: str) -> Optional[int]:
    """Look up the first process whose comm/basename matches `name`. None if not found."""
    pid = _vm_stowaway_find_pid(name.encode())
    return pid if pid > 0 else None


# patcher (no handle needed) ---

def patch(binary: str, payload_install_name: str,
          opts: Optional[PatchOpts] = None) -> None:
    err = ctypes.create_string_buffer(512)
    copts = (opts or PatchOpts())._c()
    if _vm_stowaway_patch(binary.encode(), payload_install_name.encode(),
                          byref(copts), err, len(err)) < 0:
        raise VMStowawayError(f"patch({binary!r}): {err.value.decode(errors='replace')}")


def unpatch(binary: str, name_substr: str,
            opts: Optional[PatchOpts] = None) -> int:
    err = ctypes.create_string_buffer(512)
    copts = (opts or PatchOpts())._c()
    n = _vm_stowaway_unpatch(binary.encode(), name_substr.encode(),
                              byref(copts), err, len(err))
    if n < 0:
        raise VMStowawayError(f"unpatch({binary!r}): {err.value.decode(errors='replace')}")
    return n


def scan_hijacks(binary: str, max_results: int = 64) -> list[Hijack]:
    err = ctypes.create_string_buffer(512)
    buf = (_CHijack * max_results)()
    n = _vm_stowaway_scan_hijacks(binary.encode(), buf, max_results, err, len(err))
    if n < 0:
        raise VMStowawayError(f"scan_hijacks({binary!r}): {err.value.decode(errors='replace')}")
    return [Hijack(buf[i].path.decode(errors="replace"),
                    buf[i].dep_name.decode(errors="replace"),
                    bool(buf[i].weak))
            for i in range(min(n, max_results))]


def hijack_drop(payload_path: str, dest: str) -> None:
    err = ctypes.create_string_buffer(512)
    if _vm_stowaway_hijack_drop(payload_path.encode(), dest.encode(),
                                 err, len(err)) < 0:
        raise VMStowawayError(f"hijack_drop({dest!r}): {err.value.decode(errors='replace')}")


# bundle scanners ---

def scan_apps(dir: Optional[str] = None, permissive_only: bool = True,
              max_results: int = 256) -> list[App]:
    err = ctypes.create_string_buffer(256)
    buf = (_CApp * max_results)()
    n = _vm_stowaway_scan_apps(
        dir.encode() if dir else None,
        int(permissive_only), buf, max_results, err, len(err),
    )
    if n < 0:
        raise VMStowawayError(f"scan_apps: {err.value.decode(errors='replace')}")
    return [App(buf[i].path.decode(errors="replace"),
                 bool(buf[i].allow_dyld_env),
                 bool(buf[i].disable_lib_val))
            for i in range(min(n, max_results))]


def scan_electron(dir: Optional[str] = None,
                  max_results: int = 256) -> list[Electron]:
    err = ctypes.create_string_buffer(256)
    buf = (_CElectron * max_results)()
    n = _vm_stowaway_scan_electron(
        dir.encode() if dir else None,
        buf, max_results, err, len(err),
    )
    if n < 0:
        raise VMStowawayError(f"scan_electron: {err.value.decode(errors='replace')}")
    out = []
    for i in range(min(n, max_results)):
        ran = buf[i].run_as_node
        out.append(Electron(buf[i].path.decode(errors="replace"),
                             True if ran == 1 else False if ran == 0 else None))
    return out


def find_app_bundle(path: str) -> Optional[str]:
    out = ctypes.create_string_buffer(2048)
    if _vm_stowaway_find_app_bundle(path.encode(), out, len(out)) < 0:
        return None
    return out.value.decode()


def unharden(src_app: str, dst_app: str) -> None:
    err = ctypes.create_string_buffer(256)
    if _vm_stowaway_unharden(src_app.encode(), dst_app.encode(),
                              err, len(err)) < 0:
        raise VMStowawayError(f"unharden({src_app!r}): {err.value.decode(errors='replace')}")


# internal: re-call into the library to grow when the first array was too small

def _grow_array(call, ctype, convert):
    """call(buf, max) returns total count, which may exceed max."""
    cap = 256
    while True:
        buf = (ctype * cap)()
        n = call(buf, cap)
        if n < 0:
            raise VMStowawayError("grow_array: enumeration failed")
        if n <= cap:
            return [convert(buf[i]) for i in range(n)]
        cap = n
