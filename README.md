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

Measured with `pixi run bench` on this machine on 2026-08-24: Intel Xeon
E5-2697 v4, Linux x86-64, Python 3.13.14, Mojo
1.1.0.dev2026081105. Times are the median of five warm runs.

| case | mojo-dnspython | dnspython 2.8.0 | speedup |
|---|---:|---:|---:|
| decode one name 20k times | 132.76 ms | 146.03 ms | 1.10x |
| encode one name 20k times | 12.21 ms | 20.10 ms | 1.65x |
| decode 100k compressed names | 148.13 ms | 953.77 ms | 6.44x |
| scan 20k A-record envelopes | 79.07 ms | 1093.10 ms | 13.82x |

The decode benchmarks return equivalent name objects and consumed lengths. The
encode benchmark measures repeated serialization of an immutable name and
therefore includes the cached-wire fast path after warmup. The message
benchmark compares generic envelope scanning with dnspython's full typed parser
using `one_rr_per_rrset=True`; the Mojo result intentionally does less RDATA
work, as described in the coverage section.

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
