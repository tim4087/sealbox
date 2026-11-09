"""Key derivation functions (KDF) for sealbox.

Two algorithms are supported:

- ``scrypt``  — from the standard library (:func:`hashlib.scrypt`), no extra
  dependencies required.
- ``argon2id`` — via the optional ``argon2-cffi`` package; preferred when it is
  installed because it is memory-hard and resists GPU/ASIC attacks better.

The chosen algorithm and its parameters are stored inside every sealed box, so
boxes stay readable even after defaults change in future versions.
"""

from __future__ import annotations

import hashlib
import importlib.util
from typing import Any, Mapping

from .errors import CorruptedBox, SealboxError

#: Length of derived keys (AES-256).
KEY_BYTES = 32

#: scrypt is calibrated for ~50-100 ms on a modern desktop CPU.
DEFAULT_SCRYPT_PARAMS: dict[str, int] = {"n": 2**15, "r": 8, "p": 1}

#: argon2id is calibrated for ~50-100 ms with 64 MiB of memory.
DEFAULT_ARGON2ID_PARAMS: dict[str, int] = {
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4,
}

# Upper bounds enforced when *reading* a box, so a maliciously crafted file
# cannot ask us to burn gigabytes of RAM or hours of CPU on key derivation.
# Individual limits are NOT enough: scrypt cost is 128 * n * r bytes of memory,
# so the *product* is capped separately (SCRYPT_MAX_N_R).
SCRYPT_LIMITS = {"n": 2**20, "r": 32, "p": 8}
#: Cap on scrypt memory usage: n * r <= 2**20, i.e. 128 * n * r <= 128 MiB.
SCRYPT_MAX_N_R = 2**20
ARGON2ID_LIMITS = {"time_cost": 10, "memory_cost": 2**19, "parallelism": 8}


def argon2_available() -> bool:
    """Return True if the optional ``argon2-cffi`` package is installed."""
    try:
        return importlib.util.find_spec("argon2") is not None
    except (ImportError, ValueError):  # pragma: no cover - exotic environments
        return False


def available_algorithms() -> list[str]:
    """List KDF algorithms usable on this machine."""
    algs = ["scrypt"]
    if argon2_available():
        algs.insert(0, "argon2id")
    return algs


def default_algorithm() -> str:
    """Best available algorithm: argon2id when installed, scrypt otherwise."""
    return "argon2id" if argon2_available() else "scrypt"


def default_params(algorithm: str) -> dict[str, Any]:
    """Return a fresh copy of the default parameters for *algorithm*."""
    if algorithm == "scrypt":
        return dict(DEFAULT_SCRYPT_PARAMS)
    if algorithm == "argon2id":
        return dict(DEFAULT_ARGON2ID_PARAMS)
    raise SealboxError(f"unknown KDF algorithm: {algorithm!r}")


def _validate_params(algorithm: str, params: Mapping[str, Any]) -> None:
    """Light sanity check for parameters coming from an untrusted box file."""
    if algorithm == "scrypt":
        limits, expected = SCRYPT_LIMITS, {"n", "r", "p"}
    elif algorithm == "argon2id":
        limits, expected = ARGON2ID_LIMITS, {"time_cost", "memory_cost", "parallelism"}
    else:
        raise SealboxError(f"unknown KDF algorithm: {algorithm!r}")

    if set(params) != expected:
        raise CorruptedBox(
            f"unexpected KDF parameters {sorted(params)} for {algorithm!r}"
        )
    for name, value in params.items():
        if not isinstance(value, int) or isinstance(value, bool):
            raise CorruptedBox(f"KDF parameter {name!r} must be an integer")
        if not 1 <= value <= limits[name]:
            raise CorruptedBox(f"KDF parameter {name!r} out of sane range: {value}")

    # Cross-parameter constraints (argparse-style per-key limits are not enough).
    if algorithm == "scrypt" and params["n"] * params["r"] > SCRYPT_MAX_N_R:
        raise CorruptedBox(
            f"scrypt n*r = {params['n'] * params['r']} exceeds the {SCRYPT_MAX_N_R} cap"
        )
    if algorithm == "argon2id" and params["memory_cost"] < 8 * params["parallelism"]:
        # argon2 itself requires this invariant; enforce it as CorruptedBox
        # instead of letting hash_secret_raw raise a bare ValueError.
        raise CorruptedBox("argon2id memory_cost must be at least 8 * parallelism")


def derive_key(
    passphrase: bytes | str,
    salt: bytes,
    algorithm: str,
    params: Mapping[str, Any],
) -> bytes:
    """Derive a 32-byte key from *passphrase*.

    This function is used both for sealing (with trusted default parameters)
    and for opening (with parameters read from an untrusted box file, which are
    validated first).
    """
    _validate_params(algorithm, params)

    secret = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
    if not secret:
        raise SealboxError("passphrase must not be empty")

    if algorithm == "scrypt":
        n, r, p = params["n"], params["r"], params["p"]
        # hashlib.scrypt needs maxmem >= 128 * r * (n + p); add a 32 MiB cushion
        # so odd-but-valid combinations never trip OpenSSL's default ceiling.
        maxmem = 128 * r * (n + p) + (32 << 20)
        return hashlib.scrypt(secret, salt=salt, dklen=KEY_BYTES, maxmem=maxmem, n=n, r=r, p=p)

    if algorithm == "argon2id":
        if not argon2_available():
            raise SealboxError(
                "this box uses argon2id; install the optional extra: "
                "pip install 'sealbox[argon2]'"
            )
        from argon2.low_level import Type, hash_secret_raw  # noqa: PLC0415

        return hash_secret_raw(
            secret=secret,
            salt=salt,
            hash_len=KEY_BYTES,
            type=Type.ID,
            time_cost=params["time_cost"],
            memory_cost=params["memory_cost"],
            parallelism=params["parallelism"],
        )

    raise SealboxError(f"unknown KDF algorithm: {algorithm!r}")
