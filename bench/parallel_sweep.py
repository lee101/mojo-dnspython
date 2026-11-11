"""Crossover sweep for the parallel batch name decoder — evidence, not a path.

The parallel path measured with this file was removed from the tree after the
numbers showed it loses at every size real callers pass (see the "PARALLEL
phase: evaluated, not adopted" section of the README). This file records the
sweep that decided the threshold, so the next pass can re-check the crossover
after a toolchain or host change instead of relitigating it blind.

It needs a build with `parallelize` wired into `mdns_names_decode` plus the
`decode_names(..., workers=N)` keyword from that pass, so it does not run
against the shipped library. Build the serial library as `lib_serial.so` and the
parallel one as `lib_parallel.so` (in an env that has the `max` package, so the
parallel build can load its runtime), then:

    SERIAL_LIB=/tmp/lib_serial.so PARALLEL_LIB=/tmp/lib_parallel.so \
        pixi run python bench/parallel_sweep.py

Each child process loads exactly the library it is given, and the 1-worker
column should come from the serial build: `parallelize` adds launch cost even at
one worker. Timing is end to end per `decode_names` call, median of five.
"""

from __future__ import annotations

import os
import statistics
import subprocess
import sys
import time

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python"))

SIZES = (128, 512, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 100_000)
WORKERS = (1, 2, 4)

# One child process per (size, workers) so a fresh `ctypes.CDLL` picks up
# MOJO_DNSPYTHON_LIB and repeated reads do not contend with a warm Python loop.
CHILD = r"""
import os, statistics, sys, time
import numpy as np
sys.path.insert(0, os.path.join(os.environ["REPO_ROOT"], "python"))
import mojo_dnspython as mdns

size, workers, library = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
base = b"\x07example\x03com\x00"
wire_bytes = bytearray(base)
offsets = np.empty(size, dtype=np.int64)
for index in range(size):
    offsets[index] = len(wire_bytes)
    label = f"h{index:06d}".encode()
    wire_bytes.extend(bytes((len(label),)))
    wire_bytes.extend(label)
    wire_bytes.extend(b"\xc0\x00")
wire = bytes(wire_bytes)
samples = []
for _ in range(5):
    start = time.perf_counter()
    mdns.decode_names(wire, offsets, workers=workers)
    samples.append(time.perf_counter() - start)
print("RESULT", statistics.median(samples) * 1e3)
print("LIB", mdns._lib.LIB, "W", os.environ.get("MOJO_DNSPYTHON_WORKERS"), file=sys.stderr)
"""


def compressed_names(count: int):
    base = b"\x07example\x03com\x00"
    wire = bytearray(base)
    offsets = np.empty(count, dtype=np.int64)
    for index in range(count):
        offsets[index] = len(wire)
        label = f"h{index:06d}".encode()
        wire.extend(bytes((len(label),)))
        wire.extend(label)
        wire.extend(b"\xc0\x00")
    return bytes(wire), offsets


def run_child(size: int, workers: int, library: str) -> float:
    prefix = os.path.join(ROOT, ".pixi", "envs", "default")
    runtime_path = os.path.join(prefix, "lib")
    env = dict(os.environ, REPO_ROOT=ROOT, MODULAR_HOME=os.path.join(prefix, "share", "max"))
    env["MOJO_DNSPYTHON_LIB"] = library
    env["LD_LIBRARY_PATH"] = runtime_path + os.pathsep + env.get("LD_LIBRARY_PATH", "")
    proc = subprocess.run(
        [sys.executable, "-c", CHILD, str(size), str(workers), library],
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip()[-2000:])
    line = next(l for l in proc.stdout.splitlines() if l.startswith("RESULT"))
    note = next(
        (l.split("LIB ", 1)[1] for l in proc.stderr.splitlines() if l.startswith("LIB ")),
        "",
    )
    return float(line.split()[1]), note


def main() -> None:
    serial = os.environ.get("SERIAL_LIB", "/tmp/lib_serial.so")
    parallel = os.environ.get("PARALLEL_LIB", "/tmp/lib_parallel.so")
    print("Recorded sweep: serial library for 1 worker, parallel library otherwise.")
    print("| names | 1 worker (serial build) | 2 workers | 4 workers |")
    print("|---|---:|---:|---:|")
    for size in SIZES:
        value, note = run_child(size, 1, serial)
        row = [value]
        for workers in WORKERS[1:]:
            value, note = run_child(size, workers, parallel)
            row.append(value)
        print(f"| {size} | " + " | ".join(f"{v:.3f} ms" for v in row) + f" | {note} |")


if __name__ == "__main__":
    main()
