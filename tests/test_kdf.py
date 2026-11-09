from __future__ import annotations

import pytest

from sealbox import kdf
from sealbox.errors import CorruptedBox, SealboxError


def test_scrypt_derive_is_deterministic():
    a = kdf.derive_key("pass", b"salt" * 4, "scrypt", {"n": 1024, "r": 8, "p": 1})
    b = kdf.derive_key("pass", b"salt" * 4, "scrypt", {"n": 1024, "r": 8, "p": 1})
    assert a == b
    assert len(a) == kdf.KEY_BYTES == 32


def test_different_salt_gives_different_key():
    a = kdf.derive_key("pass", b"salt" * 4, "scrypt", {"n": 1024, "r": 8, "p": 1})
    b = kdf.derive_key("pass", b"pepper" * 4, "scrypt", {"n": 1024, "r": 8, "p": 1})
    assert a != b


def test_default_params_returns_copies():
    params = kdf.default_params("scrypt")
    params["n"] = 1
    assert kdf.default_params("scrypt")["n"] == kdf.DEFAULT_SCRYPT_PARAMS["n"]


def test_unknown_algorithm_rejected():
    with pytest.raises(SealboxError):
        kdf.derive_key("pass", b"s" * 16, "pbkdf2", {})


def test_empty_passphrase_rejected():
    with pytest.raises(SealboxError):
        kdf.derive_key("", b"s" * 16, "scrypt", {"n": 1024, "r": 8, "p": 1})


@pytest.mark.parametrize(
    "params",
    [
        {"n": 2**30, "r": 8, "p": 1},  # absurd n
        {"n": 1024, "r": 9999, "p": 1},  # absurd r
        {"n": 1024, "r": 8, "p": 0},  # zero
        {"n": 1024, "r": 8},  # missing key
        {"n": 1024, "r": 8, "p": 1, "extra": 1},  # unknown key
        {"n": "many", "r": 8, "p": 1},  # wrong type
        {"n": True, "r": 8, "p": 1},  # bool, not int
    ],
)
def test_malicious_scrypt_params_rejected(params):
    with pytest.raises((CorruptedBox, SealboxError)):
        kdf.derive_key("pass", b"s" * 16, "scrypt", params)


def test_scrypt_memory_cap_enforced_on_product():
    # n and r are individually within limits, but n*r blows the 128 MiB cap
    params = {"n": 2**20, "r": 32, "p": 1}
    assert params["n"] <= kdf.SCRYPT_LIMITS["n"]
    assert params["r"] <= kdf.SCRYPT_LIMITS["r"]
    with pytest.raises(CorruptedBox):
        kdf.derive_key("pass", b"s" * 16, "scrypt", params)


def test_argon2_memory_parallelism_invariant_enforced():
    # memory_cost < 8 * parallelism would make argon2 raise a bare ValueError
    params = {"time_cost": 1, "memory_cost": 8, "parallelism": 4}
    with pytest.raises(CorruptedBox):
        kdf.derive_key("pass", b"s" * 16, "argon2id", params)


def test_argon2_roundtrip_when_available():
    pytest.importorskip("argon2")
    key = kdf.derive_key(
        "pass", b"s" * 16, "argon2id", {"time_cost": 1, "memory_cost": 8192, "parallelism": 1}
    )
    assert len(key) == 32
    assert kdf.argon2_available() is True
    assert "argon2id" in kdf.available_algorithms()
