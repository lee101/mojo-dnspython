"""Load the compiled Mojo DNS wire-format library."""

from __future__ import annotations

import ctypes
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LIB = os.environ.get("MOJO_DNSPYTHON_LIB") or os.path.join(
    ROOT, "dist", "libmojo-dnspython.so"
)

I = ctypes.c_int64

_SIGNATURES = {
    "mdns_name_decode": ([I, I, I, I, I, I], None),
    "mdns_names_decode": ([I, I, I, I, I, I, I], None),
    "mdns_name_encode": ([I, I, I, I, I, I], None),
    "mdns_scan_message": ([I, I, I, I, I, I], None),
}


class BuildError(RuntimeError):
    pass


def build(force: bool = False) -> str:
    source = os.path.join(ROOT, "src", "dns_wire.mojo")
    if os.environ.get("MOJO_DNSPYTHON_LIB"):
        if os.path.exists(LIB):
            return LIB
        raise BuildError(f"MOJO_DNSPYTHON_LIB does not exist: {LIB}")
    if not force and os.path.exists(LIB) and os.path.getmtime(LIB) >= os.path.getmtime(source):
        return LIB
    proc = subprocess.run(
        ["bash", os.path.join(ROOT, "build", "build.sh")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    if proc.returncode != 0 or not os.path.exists(LIB):
        raise BuildError((proc.stderr or proc.stdout).strip()[:4000])
    return LIB


_library: ctypes.CDLL | None = None


def lib() -> ctypes.CDLL:
    global _library
    if _library is None:
        _library = ctypes.CDLL(build())
        for name, (argtypes, restype) in _SIGNATURES.items():
            function = getattr(_library, name)
            function.argtypes = argtypes
            function.restype = restype
    return _library


def address(buffer) -> int:
    return buffer.ctypes.data
