from __future__ import annotations

import io
import random

import dns.exception
import dns.name
import numpy as np
import pytest

import mojo_dnspython as mdns


@pytest.mark.parametrize(
    "text",
    [
        ".",
        "www.example.com.",
        "MiXeD.Example.",
        r"escaped\.dot.example.",
        r"binary\000\255.example.",
        "relative.example",
        "@",
    ],
)
def test_text_and_wire_match_dnspython(text):
    ours = mdns.from_text(text)
    upstream = dns.name.from_text(text)
    assert ours.labels == upstream.labels
    assert ours.to_text() == upstream.to_text()
    assert ours.to_wire() == upstream.to_wire()


def test_canonical_wire_matches_dnspython():
    ours = mdns.from_text("MiXeD.Example.")
    upstream = dns.name.from_text("MiXeD.Example.")
    assert ours.to_wire(canonicalize=True) == upstream.to_wire(canonicalize=True)
    assert ours.canonicalize().labels == upstream.canonicalize().labels


@pytest.mark.parametrize("label_length", [1, 3, 4, 7, 8, 15, 16, 31, 32, 63])
def test_canonical_encode_simd_tail_lengths_match_dnspython(label_length):
    label = bytes(65 + index % 26 for index in range(label_length))
    ours = mdns.Name((label, b""))
    upstream = dns.name.Name((label, b""))
    assert ours.to_wire(canonicalize=True) == upstream.to_wire(canonicalize=True)
    assert ours.to_wire(canonicalize=True) == upstream.to_wire(canonicalize=True)


def test_relative_name_with_origin_matches_dnspython():
    ours = mdns.Name((b"www",))
    ours_origin = mdns.from_text("example.")
    upstream = dns.name.Name((b"www",))
    upstream_origin = dns.name.from_text("example.")
    assert ours.to_wire(origin=ours_origin) == upstream.to_wire(origin=upstream_origin)


def test_relative_and_concatenation_operations_match_dnspython():
    ours_relative = mdns.Name((b"www",))
    ours_origin = mdns.from_text("example.")
    upstream_relative = dns.name.Name((b"www",))
    upstream_origin = dns.name.from_text("example.")

    ours_absolute = ours_relative.concatenate(ours_origin)
    upstream_absolute = upstream_relative.concatenate(upstream_origin)
    assert ours_absolute.labels == upstream_absolute.labels
    assert ours_absolute.is_subdomain(ours_origin) == upstream_absolute.is_subdomain(
        upstream_origin
    )
    assert ours_absolute.relativize(ours_origin).labels == upstream_absolute.relativize(
        upstream_origin
    ).labels
    assert ours_relative.derelativize(ours_origin).labels == upstream_relative.derelativize(
        upstream_origin
    ).labels


def test_relative_name_without_origin_raises():
    with pytest.raises(mdns.NeedAbsoluteNameOrOrigin):
        mdns.Name((b"www",)).to_wire()


def test_compressed_file_encoding_matches_dnspython():
    ours_file = io.BytesIO()
    upstream_file = io.BytesIO()
    ours_compress = {}
    upstream_compress = {}
    texts = ("www.example.com.", "mail.example.com.", "example.com.", ".")
    for text in texts:
        mdns.from_text(text).to_wire(ours_file, ours_compress)
        dns.name.from_text(text).to_wire(upstream_file, upstream_compress)
    assert ours_file.getvalue() == upstream_file.getvalue()


def test_rfc_style_compressed_pointer_decode_matches_dnspython():
    message = b"\x03www\x07example\x03com\x00\x03ftp\xc0\x04"
    for offset in (0, 17):
        ours, ours_used = mdns.from_wire(message, offset)
        upstream, upstream_used = dns.name.from_wire(message, offset)
        assert ours.labels == upstream.labels
        assert ours_used == upstream_used


def test_pointer_chain_decode_matches_dnspython():
    message = b"\x03com\x00\x07example\xc0\x00\x03www\xc0\x05"
    ours, ours_used = mdns.from_wire(message, 15)
    upstream, upstream_used = dns.name.from_wire(message, 15)
    assert ours.labels == upstream.labels
    assert ours_used == upstream_used == 6


def test_bulk_decode_matches_repeated_dnspython_calls():
    stream = io.BytesIO()
    compress = {}
    offsets = []
    upstream_names = []
    for index in range(500):
        name = dns.name.from_text(f"host-{index}.service.example.")
        offsets.append(stream.tell())
        upstream_names.append(name)
        name.to_wire(stream, compress)
    message = stream.getvalue()
    got = mdns.decode_names(message, offsets)
    expected = [dns.name.from_wire(message, offset) for offset in offsets]
    assert [(name.labels, used) for name, used in got] == [
        (name.labels, used) for name, used in expected
    ]


def test_bulk_decode_accepts_offset_generator():
    message = b"\x03www\x07example\x00"
    got = mdns.decode_names(message, (offset for offset in [0]))
    expected = dns.name.from_wire(message, 0)
    assert (got[0][0].labels, got[0][1]) == (expected[0].labels, expected[1])


@pytest.mark.parametrize(
    "offsets",
    [
        [0.0],
        np.array([[0]], dtype=np.int64),
        [2**63],
    ],
)
def test_bulk_decode_rejects_narrowing_and_non_vector_offsets(offsets):
    with pytest.raises(ValueError):
        mdns.decode_names(b"\x00", offsets)


@pytest.mark.parametrize("offset", [-1, 1])
def test_bulk_decode_rejects_out_of_bounds_offsets(offset):
    with pytest.raises(mdns.FormError):
        mdns.decode_names(b"\x00", [offset])


@pytest.mark.parametrize("label_length", [1, 3, 4, 7, 8, 15, 16, 63])
def test_bulk_decode_simd_tail_lengths_match_dnspython(label_length):
    label = bytes((index % 251) + 1 for index in range(label_length))
    message = bytes((label_length,)) + label + b"\x00"
    got = mdns.decode_names(message, [0])
    expected = dns.name.from_wire(message, 0)
    assert (got[0][0].labels, got[0][1]) == (expected[0].labels, expected[1])


@pytest.mark.parametrize("count", [4095, 4096])
def test_bulk_decode_parallel_threshold_matches_dnspython(count):
    base = b"\x07example\x03com\x00"
    message = bytearray(base)
    offsets = []
    for index in range(count):
        offsets.append(len(message))
        label = f"h{index:06d}".encode()
        message.extend(bytes((len(label),)) + label + b"\xc0\x00")
    wire = bytes(message)
    got = mdns.decode_names(wire, offsets)
    assert len(got) == count
    for index in (0, count // 2, count - 1):
        expected = dns.name.from_wire(wire, offsets[index])
        assert (got[index][0].labels, got[index][1]) == (
            expected[0].labels,
            expected[1],
        )


def test_random_uncompressed_names_match_dnspython():
    rng = random.Random(7)
    for _ in range(500):
        labels = [
            bytes(rng.randrange(1, 127) for _ in range(rng.randrange(1, 20)))
            for _ in range(rng.randrange(1, 7))
        ] + [b""]
        ours = mdns.Name(labels)
        upstream = dns.name.Name(labels)
        wire = upstream.to_wire()
        decoded, used = mdns.from_wire(wire, 0)
        assert ours.to_wire() == wire
        assert decoded.labels == upstream.labels
        assert used == len(wire)


@pytest.mark.parametrize(
    ("wire", "ours_error", "upstream_error"),
    [
        (b"\xc0\x00", mdns.BadPointer, dns.name.BadPointer),
        (b"\x80\x00", mdns.BadLabelType, dns.name.BadLabelType),
        (b"\x03ab", mdns.FormError, dns.exception.FormError),
        (b"\xc0", mdns.FormError, dns.exception.FormError),
    ],
)
def test_malformed_name_errors_match_dnspython(wire, ours_error, upstream_error):
    with pytest.raises(ours_error):
        mdns.from_wire(wire, 0)
    with pytest.raises(upstream_error):
        dns.name.from_wire(wire, 0)


def test_name_length_limits_match_dnspython():
    too_long_label = b"x" * 64
    with pytest.raises(mdns.LabelTooLong):
        mdns.Name((too_long_label, b""))
    with pytest.raises(dns.name.LabelTooLong):
        dns.name.Name((too_long_label, b""))

    labels = (b"x" * 63,) * 4 + (b"",)
    with pytest.raises(mdns.NameTooLong):
        mdns.Name(labels)
    with pytest.raises(dns.name.NameTooLong):
        dns.name.Name(labels)


def test_expanded_wire_name_length_limit_matches_dnspython():
    wire = b"".join(b"\x3f" + bytes((index + 1,)) * 63 for index in range(4)) + b"\x00"
    with pytest.raises(mdns.NameTooLong):
        mdns.from_wire(wire, 0)
    with pytest.raises(dns.name.NameTooLong):
        dns.name.from_wire(wire, 0)


def test_case_insensitive_name_equality_and_hash():
    left = mdns.from_text("WWW.Example.")
    right = mdns.from_text("www.example.")
    assert left == right
    assert hash(left) == hash(right)


def test_non_bytes_from_wire_rejected_like_dnspython():
    with pytest.raises(ValueError):
        mdns.from_wire(bytearray(b"\x00"), 0)
    with pytest.raises(ValueError):
        dns.name.from_wire(bytearray(b"\x00"), 0)
