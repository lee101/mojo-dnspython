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

There is no GPU path. DNS name decoding and envelope scanning are branch-heavy
byte-processing kernels with arithmetic intensity well below two operations per
byte moved, so host/device transfer and launch overhead would dominate.

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
