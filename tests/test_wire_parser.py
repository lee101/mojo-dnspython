from __future__ import annotations

import dns.exception
import dns.name
import dns.wire
import pytest

import mojo_dnspython as mdns


def test_integer_and_counted_reads_match_dnspython():
    wire = bytes(range(1, 32))
    ours = mdns.Parser(wire)
    upstream = dns.wire.Parser(wire)
    assert ours.get_uint8() == upstream.get_uint8()
    assert ours.get_uint16() == upstream.get_uint16()
    assert ours.get_uint32() == upstream.get_uint32()
    assert ours.get_uint48() == upstream.get_uint48()
    assert ours.get_counted_bytes() == upstream.get_counted_bytes()
    assert ours.current == upstream.current
    assert ours.remaining() == upstream.remaining()


def test_struct_read_matches_dnspython():
    wire = b"\x12\x34\x89\xab\xcd\xef"
    ours = mdns.Parser(wire)
    upstream = dns.wire.Parser(wire)
    assert ours.get_struct("!HI") == upstream.get_struct("!HI")


def test_parser_compressed_name_matches_dnspython():
    wire = b"\x03www\x07example\x00\x04mail\xc0\x04"
    ours = mdns.Parser(wire, 13)
    upstream = dns.wire.Parser(wire, 13)
    assert ours.get_name().labels == upstream.get_name().labels
    assert ours.current == upstream.current


def test_parser_name_relativization_matches_dnspython():
    wire = b"\x03www\x07example\x00"
    ours = mdns.Parser(wire)
    upstream = dns.wire.Parser(wire)
    assert ours.get_name(mdns.from_text("example.")).labels == upstream.get_name(
        dns.name.from_text("example.")
    ).labels


def test_restrict_to_success_and_failure_match_dnspython():
    ours = mdns.Parser(b"abcdef")
    upstream = dns.wire.Parser(b"abcdef")
    with ours.restrict_to(3):
        assert ours.get_bytes(3) == b"abc"
    with upstream.restrict_to(3):
        assert upstream.get_bytes(3) == b"abc"
    assert ours.current == upstream.current == 3

    with pytest.raises(mdns.FormError):
        with ours.restrict_to(2):
            ours.get_bytes(1)
    with pytest.raises(dns.exception.FormError):
        with upstream.restrict_to(2):
            upstream.get_bytes(1)


def test_restriction_applies_to_name_label_bytes():
    wire = b"\x03abc\x00"
    ours = mdns.Parser(wire)
    upstream = dns.wire.Parser(wire)
    with pytest.raises(mdns.FormError):
        with ours.restrict_to(2):
            ours.get_name()
    with pytest.raises(dns.exception.FormError):
        with upstream.restrict_to(2):
            upstream.get_name()


def test_seek_bounds_match_dnspython():
    for where in (-1, 7):
        with pytest.raises(mdns.FormError):
            mdns.Parser(b"abcdef").seek(where)
        with pytest.raises(dns.exception.FormError):
            dns.wire.Parser(b"abcdef").seek(where)


def test_parser_truncation_matches_dnspython():
    with pytest.raises(mdns.FormError):
        mdns.Parser(b"\x01").get_uint16()
    with pytest.raises(dns.exception.FormError):
        dns.wire.Parser(b"\x01").get_uint16()


def test_get_remaining_and_restore_furthest_match_dnspython():
    ours = mdns.Parser(b"abcdef")
    upstream = dns.wire.Parser(b"abcdef")
    ours.get_bytes(4)
    upstream.get_bytes(4)
    with ours.restore_furthest(), upstream.restore_furthest():
        ours.seek(1)
        upstream.seek(1)
        assert ours.get_bytes(1) == upstream.get_bytes(1)
    assert ours.current == upstream.current == 4
    assert ours.get_remaining() == upstream.get_remaining() == b"ef"
