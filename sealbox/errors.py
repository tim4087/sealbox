"""Exceptions used across sealbox."""

from __future__ import annotations


class SealboxError(Exception):
    """Base class for all sealbox errors."""


class WrongPassphrase(SealboxError):
    """Passphrase is wrong or the box data has been tampered with.

    AES-GCM is authenticated, so both cases are indistinguishable.
    """


class CorruptedBox(SealboxError):
    """The box file is malformed and cannot even be parsed."""


class UnsupportedFormat(SealboxError):
    """The box was created by an incompatible sealbox version."""
