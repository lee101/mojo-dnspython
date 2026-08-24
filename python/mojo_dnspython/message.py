"""Generic DNS message envelope scanning without RDATA interpretation."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from ._lib import address, lib
from .exception import FormError
from .name import BadLabelType, BadPointer, Name, NameTooLong, decode_names


class TrailingJunk(FormError):
    pass


@dataclass(frozen=True)
class Header:
    id: int
    flags: int
    question_count: int
    answer_count: int
    authority_count: int
    additional_count: int


@dataclass(frozen=True)
class Question:
    name: Name
    rdtype: int
    rdclass: int


@dataclass(frozen=True)
class Record:
    section: int
    name: Name
    rdtype: int
    rdclass: int
    ttl: int
    rdata: bytes


@dataclass(frozen=True)
class WireMessage:
    header: Header
    questions: tuple[Question, ...]
    records: tuple[Record, ...]
    consumed: int


_ERRORS = {
    1: FormError,
    2: BadPointer,
    3: BadLabelType,
    4: NameTooLong,
    5: FormError,
    6: TrailingJunk,
}


def scan_message(wire: bytes, *, ignore_trailing: bool = False) -> WireMessage:
    """Decode headers, names, RR envelopes, and opaque RDATA bytes."""
    if not isinstance(wire, bytes):
        raise ValueError("wire must be bytes")
    if len(wire) < 12:
        raise FormError
    values = [int.from_bytes(wire[index : index + 2], "big") for index in range(0, 12, 2)]
    header = Header(*values)
    total = sum(values[2:])
    rows = np.empty((max(total, 1), 8), dtype=np.int64)
    result = np.empty(6, dtype=np.int64)
    lib().mdns_scan_message(
        wire,
        len(wire),
        address(rows),
        total,
        int(ignore_trailing),
        address(result),
    )
    if result[0]:
        raise _ERRORS.get(int(result[0]), FormError)()

    row_count = int(result[1])
    decoded = decode_names(wire, rows[:row_count, 1])
    questions: list[Question] = []
    records: list[Record] = []
    for row, (owner, consumed) in zip(rows[:row_count], decoded):
        if consumed != int(row[2]):
            raise FormError
        if row[0] == 0:
            questions.append(Question(owner, int(row[3]), int(row[4])))
        else:
            offset, length = int(row[6]), int(row[7])
            records.append(
                Record(
                    int(row[0]),
                    owner,
                    int(row[3]),
                    int(row[4]),
                    int(row[5]),
                    wire[offset : offset + length],
                )
            )
    return WireMessage(header, tuple(questions), tuple(records), int(result[2]))
