"""A dnspython-compatible parser for DNS wire primitives."""

from __future__ import annotations

import contextlib
import struct

from . import name as dns_name
from .exception import FormError


class Parser:
    def __init__(self, wire: bytes, current: int = 0):
        self.wire = wire
        self.current = 0
        self.end = len(wire)
        if current:
            self.seek(current)
        self.furthest = current

    def remaining(self) -> int:
        return self.end - self.current

    def get_bytes(self, size: int) -> bytes:
        assert size >= 0
        if size > self.remaining():
            raise FormError
        output = self.wire[self.current : self.current + size]
        self.current += size
        self.furthest = max(self.furthest, self.current)
        return output

    def get_counted_bytes(self, length_size: int = 1) -> bytes:
        length = int.from_bytes(self.get_bytes(length_size), "big")
        return self.get_bytes(length)

    def get_remaining(self) -> bytes:
        return self.get_bytes(self.remaining())

    def get_uint8(self) -> int:
        return self.get_bytes(1)[0]

    def get_uint16(self) -> int:
        return int.from_bytes(self.get_bytes(2), "big")

    def get_uint32(self) -> int:
        return int.from_bytes(self.get_bytes(4), "big")

    def get_uint48(self) -> int:
        return int.from_bytes(self.get_bytes(6), "big")

    def get_struct(self, format: str) -> tuple:
        return struct.unpack(format, self.get_bytes(struct.calcsize(format)))

    def get_name(self, origin: dns_name.Name | None = None) -> dns_name.Name:
        value = dns_name.from_wire_parser(self)
        return value.relativize(origin) if origin else value

    def seek(self, where: int) -> None:
        if where < 0 or where > self.end:
            raise FormError
        self.current = where

    @contextlib.contextmanager
    def restrict_to(self, size: int):
        assert size >= 0
        if size > self.remaining():
            raise FormError
        saved_end = self.end
        try:
            self.end = self.current + size
            yield
            if self.current != self.end:
                raise FormError
        finally:
            self.end = saved_end

    @contextlib.contextmanager
    def restore_furthest(self):
        try:
            yield None
        finally:
            self.current = self.furthest
