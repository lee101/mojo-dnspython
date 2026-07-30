from __future__ import annotations

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

import mojo_dnspython as mdns


def _response_wire() -> tuple[bytes, dns.message.Message]:
    query = dns.message.make_query("www.example.", dns.rdatatype.A)
    response = dns.message.make_response(query)
    response.answer.append(
        dns.rrset.from_text("www.example.", 300, "IN", "A", "192.0.2.1")
    )
    response.authority.append(
        dns.rrset.from_text("example.", 600, "IN", "TXT", '"authority"')
    )
    response.additional.append(
        dns.rrset.from_text("ns.example.", 900, "IN", "AAAA", "2001:db8::1")
    )
    return response.to_wire(), response


def test_scan_real_dnspython_message_header_and_questions():
    wire, upstream = _response_wire()
    got = mdns.scan_message(wire)
    assert got.header.id == upstream.id
    assert got.header.flags == upstream.flags
    assert got.header.question_count == len(upstream.question)
    assert got.header.answer_count == len(upstream.answer)
    assert got.header.authority_count == len(upstream.authority)
    assert got.header.additional_count == len(upstream.additional)
    assert got.questions[0].name.labels == upstream.question[0].name.labels
    assert got.questions[0].rdtype == upstream.question[0].rdtype
    assert got.questions[0].rdclass == upstream.question[0].rdclass
    assert got.consumed == len(wire)


def test_scan_record_envelopes_match_dnspython():
    wire, upstream = _response_wire()
    got = mdns.scan_message(wire)
    expected = []
    for section, rrsets in enumerate(
        (upstream.answer, upstream.authority, upstream.additional), start=1
    ):
        for rrset in rrsets:
            for rdata in rrset:
                expected.append(
                    (
                        section,
                        rrset.name.labels,
                        rrset.rdtype,
                        rrset.rdclass,
                        rrset.ttl,
                        rdata.to_wire(),
                    )
                )
    assert [
        (
            record.section,
            record.name.labels,
            record.rdtype,
            record.rdclass,
            record.ttl,
            record.rdata,
        )
        for record in got.records
    ] == expected


def test_scan_query_only_message():
    wire = dns.message.make_query("example.", "MX").to_wire()
    got = mdns.scan_message(wire)
    assert len(got.questions) == 1
    assert got.questions[0].name.to_text() == "example."
    assert got.questions[0].rdtype == dns.rdatatype.MX
    assert not got.records


def test_scan_rejects_truncated_messages_like_upstream():
    wire, _ = _response_wire()
    for truncated in (wire[:5], wire[:-1]):
        with pytest.raises(mdns.FormError):
            mdns.scan_message(truncated)
        with pytest.raises(dns.exception.FormError):
            dns.message.from_wire(truncated)


def test_scan_trailing_junk_policy_matches_upstream_option():
    wire = dns.message.make_query("example.", "A").to_wire() + b"junk"
    with pytest.raises(mdns.TrailingJunk):
        mdns.scan_message(wire)
    with pytest.raises(dns.message.TrailingJunk):
        dns.message.from_wire(wire)
    assert mdns.scan_message(wire, ignore_trailing=True).consumed == len(wire) - 4
    assert dns.message.from_wire(wire, ignore_trailing=True).question


def test_scan_rejects_bad_owner_pointer():
    header = b"\x00\x01\x81\x80\x00\x00\x00\x01\x00\x00\x00\x00"
    bad_rr = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x01"
    with pytest.raises(mdns.BadPointer):
        mdns.scan_message(header + bad_rr)
