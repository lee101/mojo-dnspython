"""Exceptions shared by the wire-format modules."""


class DNSException(Exception):
    pass


class FormError(DNSException):
    pass
