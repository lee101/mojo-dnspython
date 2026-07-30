"""DNS names with dnspython-compatible wire encoding and decoding."""

from __future__ import annotations

import operator
from typing import Iterable

import numpy as np

from ._lib import address, lib
from .exception import DNSException, FormError


class NameException(DNSException):
    pass


class EmptyLabel(NameException):
    pass


class BadEscape(NameException):
    pass


class BadPointer(NameException):
    pass


class BadLabelType(NameException):
    pass


class NeedAbsoluteNameOrOrigin(NameException):
    pass


class AbsoluteConcatenation(NameException):
    pass


class NameTooLong(NameException):
    pass


class LabelTooLong(NameException):
    pass


_STATUS_ERRORS = {
    1: FormError,
    2: BadPointer,
    3: BadLabelType,
    4: NameTooLong,
}


def _raise_status(status: int) -> None:
    error = _STATUS_ERRORS.get(status, ValueError)
    raise error()


def _wire_array(message: bytes) -> np.ndarray:
    return np.frombuffer(message, dtype=np.uint8)


def _labels_from_data(data: bytes) -> tuple[bytes, ...]:
    labels: list[bytes] = []
    position = 0
    while position < len(data):
        size = data[position]
        position += 1
        labels.append(data[position : position + size])
        position += size
        if size == 0:
            break
    return tuple(labels)


def _positions_array(offsets: Iterable[int]) -> np.ndarray:
    try:
        values = list(offsets)
    except TypeError as error:
        raise ValueError("offsets must be an iterable of integers") from error
    converted = np.empty(len(values), dtype=np.int64)
    for index, value in enumerate(values):
        try:
            converted[index] = operator.index(value)
        except (TypeError, ValueError, OverflowError) as error:
            raise ValueError("offsets must contain signed 64-bit integers") from error
    return converted


class Name:
    """A sequence of DNS labels, matching the covered dnspython Name API."""

    __slots__ = ("_labels", "_wire", "_wire_offset", "_wire_length")

    def __init__(self, labels: Iterable[bytes]):
        converted = tuple(bytes(label) for label in labels)
        for index, label in enumerate(converted):
            if len(label) > 63:
                raise LabelTooLong
            if not label and index != len(converted) - 1:
                raise EmptyLabel
        if sum(len(label) + 1 for label in converted) > 255:
            raise NameTooLong
        self._labels: tuple[bytes, ...] | None = converted
        self._wire: np.ndarray | None = None
        self._wire_offset = 0
        self._wire_length = 0

    @property
    def labels(self) -> tuple[bytes, ...]:
        if self._labels is None:
            assert self._wire is not None
            data = self._wire.reshape(-1)[
                self._wire_offset : self._wire_offset + self._wire_length
            ].tobytes()
            self._labels = _labels_from_data(data)
            self._wire = None
        return self._labels

    def __len__(self) -> int:
        return len(self.labels)

    def __iter__(self):
        return iter(self.labels)

    def __getitem__(self, item):
        value = self.labels[item]
        return Name(value) if isinstance(item, slice) else value

    def __repr__(self) -> str:
        return f"<DNS name {self.to_text()}>"

    def __str__(self) -> str:
        return self.to_text()

    def __hash__(self) -> int:
        return hash(tuple(label.lower() for label in self.labels))

    def __eq__(self, other) -> bool:
        if not isinstance(other, Name) or len(self) != len(other):
            return False
        return all(a.lower() == b.lower() for a, b in zip(self.labels, other.labels))

    def is_absolute(self) -> bool:
        return bool(self.labels) and self.labels[-1] == b""

    def canonicalize(self) -> "Name":
        return Name(label.lower() for label in self.labels)

    def concatenate(self, other: "Name") -> "Name":
        if self.is_absolute() and len(other) > 0:
            raise AbsoluteConcatenation
        return Name(self.labels + other.labels)

    def is_subdomain(self, other: "Name") -> bool:
        if len(self) < len(other):
            return False
        return Name(self.labels[-len(other) :]) == other if other.labels else True

    def relativize(self, origin: "Name") -> "Name":
        if origin is not None and self.is_subdomain(origin):
            return Name(self.labels[: -len(origin)]) if len(origin) else self
        return self

    def derelativize(self, origin: "Name") -> "Name":
        return self.concatenate(origin) if not self.is_absolute() else self

    def to_text(self, omit_final_dot: bool = False) -> str:
        if not self.labels:
            return "@"
        if self.labels == (b"",):
            return "."
        labels = self.labels[:-1] if omit_final_dot and self.is_absolute() else self.labels
        return ".".join(_escapify(label) for label in labels)

    def to_wire(
        self,
        file=None,
        compress: dict["Name", int] | None = None,
        origin: "Name | None" = None,
        canonicalize: bool = False,
    ) -> bytes | None:
        labels: tuple[bytes, ...]
        if not self.is_absolute():
            if origin is None or not origin.is_absolute():
                raise NeedAbsoluteNameOrOrigin
            labels = self.labels + origin.labels
        else:
            labels = self.labels

        if file is None:
            raw = b"".join(bytes((len(label),)) + label for label in labels)
            src = np.frombuffer(raw, dtype=np.uint8)
            dst = np.empty(len(raw), dtype=np.uint8)
            result = np.empty(2, dtype=np.int64)
            lib().mdns_name_encode(
                address(src),
                len(src),
                address(dst),
                len(dst),
                int(canonicalize),
                address(result),
            )
            if result[0]:
                _raise_status(int(result[0]))
            return dst[: int(result[1])].tobytes()

        for index, label in enumerate(labels):
            suffix = Name(labels[index:])
            position = compress.get(suffix) if compress is not None else None
            if position is not None:
                file.write((0xC000 + position).to_bytes(2, "big"))
                break
            if compress is not None and len(suffix) > 1:
                position = file.tell()
                if position <= 0x3FFF:
                    compress[suffix] = position
            file.write(bytes((len(label),)))
            if label:
                file.write(label.lower() if canonicalize else label)
        return None


def _name_from_wire_unchecked(
    wire: np.ndarray, offset: int, length: int
) -> Name:
    value = object.__new__(Name)
    value._labels = None
    value._wire = wire
    value._wire_offset = offset
    value._wire_length = length
    return value


def _escapify(label: bytes) -> str:
    pieces = []
    for value in label:
        if value in b'"().;\\@$':
            pieces.append("\\" + chr(value))
        elif 0x21 <= value <= 0x7E:
            pieces.append(chr(value))
        else:
            pieces.append(f"\\{value:03d}")
    return "".join(pieces)


root = Name((b"",))
empty = Name(())


def from_text(text: bytes | str, origin: Name | None = root, idna_codec=None) -> Name:
    if isinstance(text, str):
        if not text.isascii():
            text = text.encode("idna")
        else:
            text = text.encode("ascii")
    if not isinstance(text, bytes):
        raise ValueError("input to from_text() must be a string")
    if origin is not None and not isinstance(origin, Name):
        raise ValueError("origin must be a Name or None")
    if text == b".":
        return root
    if text == b"@":
        text = b""

    labels: list[bytes] = []
    label = bytearray()
    index = 0
    while index < len(text):
        value = text[index]
        if value == 46:
            if not label:
                raise EmptyLabel
            labels.append(bytes(label))
            label.clear()
        elif value == 92:
            index += 1
            if index >= len(text):
                raise BadEscape
            if 48 <= text[index] <= 57:
                if index + 2 >= len(text) or not all(
                    48 <= digit <= 57 for digit in text[index : index + 3]
                ):
                    raise BadEscape
                escaped = int(text[index : index + 3])
                if escaped > 255:
                    raise BadEscape
                label.append(escaped)
                index += 2
            else:
                label.append(text[index])
        else:
            label.append(value)
        index += 1
    if label:
        labels.append(bytes(label))
    elif text:
        labels.append(b"")
    if (not labels or labels[-1] != b"") and origin is not None:
        labels.extend(origin.labels)
    return Name(labels)


def _from_wire(message: bytes, current: int, end: int) -> tuple[Name, int]:
    if not 0 <= current < end <= len(message):
        raise FormError
    source = _wire_array(message)
    output = np.empty(255, dtype=np.uint8)
    result = np.empty(3, dtype=np.int64)
    lib().mdns_name_decode(
        address(source), end, current, address(output), len(output), address(result)
    )
    if result[0]:
        _raise_status(int(result[0]))
    return _name_from_wire_unchecked(output, 0, int(result[2])), int(result[1])


def from_wire(message: bytes, current: int) -> tuple[Name, int]:
    if not isinstance(message, bytes):
        raise ValueError("input to from_wire() must be a byte string")
    return _from_wire(message, current, len(message))


def from_wire_parser(parser) -> Name:
    decoded, consumed = _from_wire(parser.wire, parser.current, parser.end)
    parser.furthest = max(parser.furthest, parser.current + consumed)
    parser.current = parser.furthest
    return decoded


def decode_names(message: bytes, offsets: Iterable[int]) -> list[tuple[Name, int]]:
    """Decode many names from one message in a single Mojo call."""
    if not isinstance(message, bytes):
        raise ValueError("message must be bytes")
    positions = _positions_array(offsets)
    if not len(positions):
        return []
    if np.any(positions < 0) or np.any(positions >= len(message)):
        raise FormError
    source = _wire_array(message)
    output = np.empty((len(positions), 255), dtype=np.uint8)
    results = np.empty((len(positions), 3), dtype=np.int64)
    lib().mdns_names_decode(
        address(source),
        len(source),
        address(positions),
        len(positions),
        address(output),
        output.shape[1],
        address(results),
    )
    failures = np.flatnonzero(results[:, 0])
    if len(failures):
        _raise_status(int(results[int(failures[0]), 0]))
    stride = output.shape[1]
    return [
        (
            _name_from_wire_unchecked(
                output, index * stride, int(results[index, 2])
            ),
            int(results[index, 1]),
        )
        for index in range(len(positions))
    ]
