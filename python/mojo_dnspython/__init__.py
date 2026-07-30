"""Mojo-accelerated DNS wire-format encoding and decoding."""

from .message import Header, Question, Record, TrailingJunk, WireMessage, scan_message
from .exception import FormError
from .name import (
    AbsoluteConcatenation,
    BadEscape,
    BadLabelType,
    BadPointer,
    EmptyLabel,
    LabelTooLong,
    Name,
    NameTooLong,
    NeedAbsoluteNameOrOrigin,
    decode_names,
    empty,
    from_text,
    from_wire,
    from_wire_parser,
    root,
)
from .wire import Parser

__all__ = [
    "AbsoluteConcatenation",
    "BadEscape",
    "BadLabelType",
    "BadPointer",
    "EmptyLabel",
    "FormError",
    "Header",
    "LabelTooLong",
    "Name",
    "NameTooLong",
    "NeedAbsoluteNameOrOrigin",
    "Parser",
    "Question",
    "Record",
    "TrailingJunk",
    "WireMessage",
    "decode_names",
    "empty",
    "from_text",
    "from_wire",
    "from_wire_parser",
    "root",
    "scan_message",
]
