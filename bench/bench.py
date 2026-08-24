"""Benchmarks against dnspython on identical DNS wire data."""

from __future__ import annotations

import os
import platform
import statistics
import sys
import time

import dns.message
import dns.name
import numpy as np

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "python"),
)

import mojo_dnspython as mdns  # noqa: E402


def timeit(function, repeat: int = 5) -> float:
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        function()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def compressed_names(count: int) -> tuple[bytes, np.ndarray]:
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


def a_record_message(count: int) -> bytes:
    if count > 65535:
        raise ValueError("DNS section counts are 16-bit")
    header = (
        b"\x12\x34\x81\x80\x00\x01"
        + count.to_bytes(2, "big")
        + b"\x00\x00\x00\x00"
    )
    question = b"\x07example\x03com\x00\x00\x01\x00\x01"
    records = bytearray()
    for index in range(count):
        records.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04")
        records.extend(
            bytes((192, 0, (index >> 8) & 255, index & 255))
        )
    return header + question + bytes(records)


def row(name: str, ours: float, upstream: float) -> str:
    speedup = upstream / ours
    return f"| {name} | {ours * 1e3:.2f} ms | {upstream * 1e3:.2f} ms | {speedup:.2f}x |"


def repeat(function, count: int) -> None:
    for _ in range(count):
        function()


def main() -> None:
    names_wire, offsets = compressed_names(100_000)
    packet = a_record_message(20_000)
    ordinary_wire = b"\x03www\x07example\x03com\x00"
    ours_name = mdns.from_text("WWW.Example.COM.")
    upstream_name = dns.name.from_text("WWW.Example.COM.")

    cases = [
        (
            "decode one name 20k times",
            lambda: repeat(lambda: mdns.from_wire(ordinary_wire, 0), 20_000),
            lambda: repeat(lambda: dns.name.from_wire(ordinary_wire, 0), 20_000),
        ),
        (
            "encode one name 20k times",
            lambda: repeat(ours_name.to_wire, 20_000),
            lambda: repeat(upstream_name.to_wire, 20_000),
        ),
        (
            "decode 100k compressed names",
            lambda: mdns.decode_names(names_wire, offsets),
            lambda: [dns.name.from_wire(names_wire, int(offset)) for offset in offsets],
        ),
        (
            "scan 20k A-record envelopes",
            lambda: mdns.scan_message(packet),
            lambda: dns.message.from_wire(packet, one_rr_per_rrset=True),
        ),
    ]

    for _, ours, upstream in cases:
        ours()
        upstream()

    print("| case | mojo-dnspython | dnspython 2.8.0 | speedup |")
    print("|---|---:|---:|---:|")
    for name, ours, upstream in cases:
        print(row(name, timeit(ours), timeit(upstream)))

    cpu = platform.processor()
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as file:
            cpu = next(
                line.split(":", 1)[1].strip()
                for line in file
                if line.startswith("model name")
            )
    except (OSError, StopIteration):
        cpu = cpu or "unknown CPU"
    print()
    print(f"Machine: {cpu}; {platform.system()} {platform.machine()}; Python {platform.python_version()}.")


if __name__ == "__main__":
    main()
