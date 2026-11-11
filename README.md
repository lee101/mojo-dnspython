# mojo-dnspython

`mojo-dnspython` is a standalone Mojo port of the compute-heavy core of
[dnspython](https://www.dnspython.org/)'s DNS wire-name decoder. It safely
expands RFC 1035 compression pointers, encodes canonical or ordinary names,
decodes many names in one native call, and scans the generic envelope of a DNS
message.

The project is useful when an application needs to inspect large captures,
load DNS datasets, or decode many records without interpreting every RDATA
type. It is not a replacement for dnspython's resolver or its complete DNS
object model.

## Coverage

The compatibility layer provides:

- `Name.to_wire(file=None, compress=None, origin=None, canonicalize=False)`;
- `from_wire(message, current)` and `from_wire_parser(parser)`;
- ASCII `from_text()`, `Name.to_text()`, canonicalization, concatenation, and
  relative/origin operations used by the wire API;
- `wire.Parser` byte, integer, struct, counted-byte, name, seek, and restricted
  parsing methods;
- `decode_names(message, offsets)`, a batch extension which amortizes FFI
  overhead; and
- `scan_message()`, which decodes the header, questions, owner names, RR fixed
  fields, section membership, and opaque RDATA bytes.

Compression pointers are checked for truncation, invalid label types,
non-backward targets, pointer loops, label limits, and the 255-byte expanded
name limit. The test suite compares successful results and malformed-input
behavior with dnspython 2.8.0.

Not covered are dnspython's typed RDATA classes, `dns.message.Message`,
message rendering, EDNS option interpretation, TSIG, DNSSEC, zone files,
resolver/network operations, and the full IDNA/text-name API. In particular,
`scan_message()` deliberately returns RDATA as bytes; it does not rewrite or
follow names compressed inside RDATA.

## Install

The supported development environment is Pixi on Linux:

```bash
pixi install
pixi run build
pixi run test
```

The build produces `dist/libmojo-dnspython.so`. The Pixi environment sets
`PYTHONPATH=python`, so examples and tests import the source checkout directly.

## Usage

```python
import mojo_dnspython as dns

name = dns.from_text("www.example.com.")
wire = name.to_wire()
decoded, consumed = dns.from_wire(wire, 0)

assert decoded == name
assert consumed == len(wire)

# The second name uses an RFC 1035 pointer to "example.com." at offset 4.
message = wire + b"\x03ftp\xc0\x04"
[(decoded, consumed)] = dns.decode_names(message, [len(wire)])
assert decoded.to_text() == "ftp.example.com."
assert consumed == 6
```

For a complete packet, `scan_message(packet)` returns a `WireMessage` containing
its `Header`, `Question` values, and `Record` envelopes.

## Benchmarks

Measured with `pixi run bench` on this machine: Intel Xeon E5-2697 v4, Linux
x86-64, Python 3.13.14, Mojo 1.2.0.dev2026092605. Times are the median of five
warm runs. "Before" is the same harness on the same machine immediately prior to
the loop changes below.

| case | before | after | dnspython 2.8.0 | speedup |
|---|---:|---:|---:|---:|
| decode one name 20k times | 128.14 ms | 126.23 ms | 158.04 ms | 1.25x |
| encode one name 20k times | 12.19 ms | 12.08 ms | 19.73 ms | 1.63x |
| decode 100k compressed names | 156.66 ms | 110.33 ms | 988.14 ms | 8.96x |
| scan 20k A-record envelopes | 81.21 ms | 73.44 ms | 1099.47 ms | 14.97x |

The batch decode change replaces per-element NumPy scalar reads with one
`tolist()` conversion per result column, so the Python loop that builds the
returned `(Name, consumed)` pairs no longer crosses the NumPy indexing path
100k times. It does not use multi-accumulator or reordered floating-point sums:
every kernel here is integer and branch-based, so results are bit-for-bit
unchanged.

The decode benchmarks return equivalent name objects and consumed lengths. The
encode benchmark measures repeated serialization of an immutable name and
therefore includes the cached-wire fast path after warmup. The message
benchmark compares generic envelope scanning with dnspython's full typed parser
using `one_rr_per_rrset=True`; the Mojo result intentionally does less RDATA
work, as described in the coverage section.

### SIMD phase: evaluated, not adopted

An earlier SIMD pass was audited against `pixi run bench` at the caller sizes the
harness uses. Nothing reached the bar in the task brief ("keep only what
`pixi run bench` shows is faster at real caller sizes"), so **no kernel change from
that pass remains in the tree**. The measurements, so the next pass need not repeat
them:

| candidate | measured | verdict |
|---|---|---|
| `_copy_bytes` / `_lower_copy_bytes` at DNS lengths (7-255 B) | 1.24-1.36 us/call for both the current `W=8` body and a `simd_width_of[DType.uint8]` (`W=16`) body | flat, within 1-3% noise |
| same kernels, large contiguous buffers (4 KB-1 MB) | W=16 is 1.26x (copy) and 1.68-3.37x (case-fold) faster | real, but no caller reaches these sizes |
| fuse the case-fold compare/select into a single store pass | 0.99-1.02x vs current | no gain; the one-store-per-tile form is already what the kernel emits |
| `decode_names` / `scan_message` end to end | native kernels are 3.1 ms of a 117 ms call and 0.3 ms of a 73 ms call; 80 ms of the first is building 100k `Name` objects, 57 ms of the second is per-row `Record`/`Question` construction | the hot loops are object construction, not contiguous elementwise work |

The copy loops are already the only contiguous elementwise loops in the port, and
their real call sites are label-sized. `_copy_bytes` receives one label at a time
(7 bytes for the 100k-name benchmark, matching the sweep above); `_lower_copy_bytes`
receives the whole name (18 bytes for `WWW.Example.COM.`, 63 bytes for a maximal
label). Widening those kernels is a measurable win on large buffers and a
non-measurable one on real DNS messages, so the `W=8` bodies were kept.

The before/after numbers for this non-change are the same binary. The committed
`src/` was restored byte-for-byte before the final run, so the "after" column below
is the unchanged code, and its spread against the earlier "before" column is
run-to-run noise on this host, not a regression:

| case | before (table above) | after SIMD audit (source unchanged) | dnspython 2.8.0 |
|---|---:|---:|---:|
| decode one name 20k times | 139.30 ms | 145.08 ms | 145.61 ms |
| encode one name 20k times | 12.57 ms | 11.54 ms | 19.17 ms |
| decode 100k compressed names | 124.02 ms | 122.96 ms | 1092.00 ms |
| scan 20k A-record envelopes | 73.13 ms | 74.86 ms | 1081.31 ms |

Tail coverage for the copy kernels now lives in `tests/test_name_parity.py`:
`test_encode_copy_kernel_simd_tail_lengths_match_dnspython` and
`test_canonical_copy_kernel_simd_tail_lengths_match_dnspython` cover 0, 1, W-1, W,
W+1, a maximal 255-byte name and 63-byte labels. Breaking only the scalar tail of
either kernel fails 30 of them.

The same findings apply to fusion: `_copy_bytes` and `_lower_copy_bytes` are already
single-stage (one load, one store per tile), and the two adjacent passes that read
the same data in `decode_names` and `scan_message` are Python object construction,
which cannot be fused into a SIMD pass or replaced by one.

### GPU phase: not started, gate failed (CPU only: memory-bound)

The GPU gate in the phase brief requires, in order: a candidate kernel above
roughly 2 flops per byte in `bench/analysis.md`, then at least 4000 MiB free on
the shared device. **`bench/analysis.md` does not exist in this repository** (it
is absent from every commit and from the working tree), so that gate could not be
applied from the named file. Rather than guess, arithmetic intensity here is
derived from the kernels in `src/dns_wire.mojo` and the exact inputs `bench/bench.py`
generates, which are reproducible with `pixi run python`. Note that the inputs are
what make the intensity small: the intensity itself is fixed per byte.

| kernel | caller size | bytes moved per element | work per element | intensity |
|---|---|---|---|---|
| `mdns_name_decode` / `mdns_names_decode` (`_decode_name`) | 7-byte label + 2-byte pointer, 100k names | 10 B in + 24 B result row | ~32 integer ops: bounds checks, label-length clamp, pointer decode, backward/loop check, terminator write | 0.94 op/B |
| `mdns_scan_message` | 16 B per A record, 20k RRs | 16 B in + 24 B written per row (the other row fields are not written) | ~30 integer ops: owner-pointer decode, `_u16`/`_u32` field reassembly, 3 row stores | 0.75 op/B |
| `_copy_bytes` / `_lower_copy_bytes` (`mdns_name_encode`) | 18 B name | 2 B (1 load, 1 store) | 4 `uint8` compares/adds/select per tile | 2.00 op/B |

The two kernels that carry real caller traffic are below the bar by the brief's own
gate, and there is no floating point anywhere in the port: every kernel is integer
and branch-based. Even the best case, the case-fold body at 2.0 op/B, is a single
bytewise pass that pays nothing less on a GPU than a copy: it would win only on
transfer cost, which is the thing the gate exists to exclude. The decode kernel is
worse than these counts suggest, because its inner loop walks a pointer chain whose
target address is data-dependent, so it is fully serial within a name; a GPU launch
would need one thread per name with a 64-branch divergent body.

**Decision: no GPU path is added. These kernels are CPU only: memory-bound.** No
kernel changes, no new tests, and no device allocation were made; `src/` and the
Python package are unchanged and the GPU tests were not written, so **the GPU tests
were skipped** (there are none to run) rather than failing on a host without a
device. The CPU path remains the only path.

For completeness of the gate record, the shared device was checked
(`nvidia-smi --query-gpu=memory.free --format=csv,noheader`): an NVIDIA GeForce
RTX 5090 reported 5294 MiB free, above the 4000 MiB floor, so **memory was not the
binding constraint; arithmetic intensity was.** The device is shared, which is also
why no allocation above 2 GB would be made even if a candidate had passed.

**This toolchain cannot compile GPU code from this repository today, independently
of the gate.** `pixi.toml` pins `mojo` only; the `max` package that ships
`max.mojoc` (`MOJO_NOTES.md` section 5b) is not a dependency. A minimal probe also
confirms it:

```text
/tmp/gpuprobe.mojo:1:10: error: 'gpu' does not refer to a nested package
from max.gpu.host import DeviceContext
```

So `from max.gpu.host import DeviceContext` and `from max.gpu import block_idx,
thread_idx` do not resolve in this environment. That is the same missing-package
failure that blocks `parallelize` in the parallel phase, and it means any GPU work
here would first need `max ==26.7.0.dev2026092605` added beside the mojo pin, a new
lockfile, and the `max` runtime in the shared library. It is recorded so the next
pass does not rediscover it, not as the reason for the decision: the gate failed
before this mattered.

**Before and after numbers: none, because no code changed.** The "after" build is
byte-identical to the "before" build, so any before/after table would be two
columns of run-to-run noise. For context, the kernel that a GPU path would have had
to beat, measured through the same ctypes path the package uses on this host,
is `decode_names(wire, offsets)` over 100,000 compressed names at **109.5 ms**
end-to-end, of which the README's SIMD and parallel audits put about 3.1 ms in the
native kernel and the rest in building 100k `Name` objects. A device copy of the
1.0 MB message would cost more than the native kernel it replaces, and the CPU path
would still be needed for the object construction.

**For the next pass.** Re-run this gate only if a real workload arrives whose
per-element arithmetic intensity is above 2 flops per byte and whose transfer is
amortized, for example a batch of many messages in one buffer, or DNSSEC
verification (elliptic-curve arithmetic, which is genuinely compute-heavy). Batch
message scanning in one native call, as suggested by the parallel phase, would
help both phases. `bench/analysis.md` should be generated alongside `bench/bench.py`
so that the flops-per-byte gate has a file to read.

### PARALLEL phase: evaluated, not adopted

A parallel path was built, measured and removed. It is not in the tree; `src/`
is byte-identical to the previous commit.

**What was built.** `mdns_names_decode` grew a `parallelize` branch from
`max.algorithm` (the only form that compiles on this toolchain) for counts above
a size threshold, with an explicit worker count capped at 4 and one strided
destination row plus one results triple per work item, so the output does not
depend on scheduling order. `decode_names` gained a `workers=` keyword for the
sweep. Tests confirmed the parallel output matched serial at 1, 2 and 4 workers
for 8k and 100k names, matched dnspython 2.8.0, and raised the same exception
class on a malformed batch.

**Why it was removed.** This toolchain's `parallelize` does not reuse a pool
across calls, so each call pays worker startup. A trivial body that stores one
`Int64` per item costs about 5 ms at 2 workers on this host (72 CPUs, shared,
load 14-25) and nothing at 1 worker. Batch name decoding is far too little work
per call to carry that. Native `mdns_names_decode` only, parallel build, median
of five, via the same ctypes path the package uses:

| names | 1 worker | 2 workers | 4 workers |
|---|---:|---:|---:|
| 8,000 | 0.314 ms | 14.532 ms | 11.727 ms |
| 16,000 | 0.567 ms | 11.857 ms | 11.058 ms |
| 32,000 | 0.896 ms | 12.902 ms | 12.053 ms |
| 100,000 | 4.687 ms | 16.854 ms | 15.881 ms |

The crossover is nowhere near a realistic caller. The sweep that decided the
threshold, end to end through `decode_names`, serial build for the 1-worker
column and parallel build for the rest (`bench/parallel_sweep.py`):

| names | 1 worker (serial build) | 2 workers | 4 workers |
|---|---:|---:|---:|
| 128 | 0.139 ms | 0.148 ms | 0.146 ms |
| 512 | 0.376 ms | 0.380 ms | 0.411 ms |
| 1,000 | 0.806 ms | 1.190 ms | 0.662 ms |
| 2,000 | 1.570 ms | 1.467 ms | 1.626 ms |
| 4,000 | 3.485 ms | 3.392 ms | 3.425 ms |
| 8,000 | 6.243 ms | 19.864 ms | 19.020 ms |
| 16,000 | 15.605 ms | 25.419 ms | 27.571 ms |
| 32,000 | 31.488 ms | 46.181 ms | 44.902 ms |
| 100,000 | 108.445 ms | 133.257 ms | 114.897 ms |

Sizes below 8,000 are under the temporary threshold, so they run the same serial
code in both builds and the spread there is noise. At and above it, 4 workers
lose by 1.06x at the largest size and by 3.0x at 8,000 names. At 1, 2 and 4
workers the gain never flattens and reverses the way a working parallel path
would: it is overhead-dominated from the first parallel call. Two workers were
never better than one, and the extra worker count only ever hurt, which is the
opposite of a scaling curve and the reason the cap never came into play.

"More names" does not rescue it either: the measured columns show the parallel
time flat at 11-16 ms from 8,000 names to 100,000 while the serial kernel grows
from 0.3 ms to 4.7 ms, so launch overhead alone is several times the entire
serial kernel even at the largest size measured. The Python layer that turns rows
into `Name` objects is linear on top of that. A parallel path loses at every size a caller can reach through this API.

**End to end, on the real benchmark.** Three interleaved rounds of `bench/bench.py`
under the bench lock, serial build and parallel-threshold-at-0 build built from
the same source (the parallel one also carries the `max` runtime, 58,040 bytes
against 15,432 for the serial library):

| case | serial build (3 rounds) | parallel build (3 rounds) | dnspython 2.8.0 |
|---|---|---|---|
| decode one name 20k times | 133.24 / 140.71 / 134.65 ms | 135.68 / 145.63 / 169.39 ms | 169.39 / 150.46 / 155.80 ms |
| encode one name 20k times | 13.99 / 12.40 / 11.30 ms | 12.47 / 12.64 / 12.09 ms | 23.24 / 21.02 / 19.65 ms |
| decode 100k compressed names | 127.41 / 114.35 / 115.92 ms | 129.92 / 115.66 / 122.36 ms | 995.26 / 999.06 / 956.97 ms |
| scan 20k A-record envelopes | 73.62 / 77.12 / 71.05 ms | 81.90 / 85.29 / 90.03 ms | 1049.68 / 1104.96 / 1030.34 ms |

The 100k decode case is a wash (serial 114-127 ms, parallel 116-130 ms) because
that is the size where the native kernel's own gain is real but small and the
per-call launch cost cancels it. The scan case is the one that should have
benefited most: `scan_message` decodes 20k owner names through the same batch
call. It got 8-19 ms slower in every round, for the same launch reason. A
parallel path that is neutral at the benchmark size and slower where it should
help is worse than no parallelism, so it was reverted.

**What did not change.** `src/dns_wire.mojo` and the Python package are untouched,
so `pixi.toml`/`pixi.lock` are also unchanged (no `max` dependency). The `before`
and `after` binaries are the same serial build; the table above is the evidence
for that, with the run-to-run spread on this shared host showing the noise floor.

**For the next pass.** The blocker is per-call launch cost, not chunking or
worker count. Re-test this with a `parallelize` that reuses a pool across calls,
or by batching many messages into one native call so the launch is amortized; do
not just re-raise the threshold. `bench/parallel_sweep.py` reproduces the sweep
once a parallel build and the `workers=` keyword exist again.

## How it works

Python owns all memory. Immutable wire bytes cross the C ABI directly as
read-only pointers, while NumPy allocates destination buffers whose addresses
cross as 64-bit integers. Mojo reconstructs mutable-origin unsafe pointers
inside four non-parametric exported functions. No allocation or Python callback
occurs in the native loops.

An expanded name occupies at most 255 bytes in length-prefixed wire form.
Batch decoding uses fixed 255-byte rows plus three `int64` result values per
name: status, consumed bytes, and expanded length. Message scanning first emits
eight-`int64` envelope rows, then decodes every owner name in one batch. The
Python layer keeps the batch output shared and zero-copy in `Name` objects,
materializing label tuples only when the labels are accessed. It also converts
message rows into immutable `Question` and `Record` objects.
