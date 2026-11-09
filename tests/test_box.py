from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

import sealbox
from sealbox import box as box_mod
from sealbox.errors import (
    CorruptedBox,
    SealboxError,
    UnsupportedFormat,
    WrongPassphrase,
)

SECRET = b"DATABASE_URL=postgres://user:pw@localhost/db\n"
PASS = "correct horse battery staple"
FAST = {"n": 1024, "r": 8, "p": 1}


@pytest.fixture()
def sealed() -> bytes:
    return sealbox.seal_bytes(SECRET, PASS, algorithm="scrypt", kdf_params=FAST)


# ---------------------------------------------------------------- bytes API


def test_roundtrip_bytes(sealed):
    assert sealbox.open_bytes(sealed, PASS) == SECRET


def test_seal_is_nondeterministic(sealed):
    other = sealbox.seal_bytes(SECRET, PASS, algorithm="scrypt", kdf_params=FAST)
    assert other != sealed  # fresh salt + nonce every time


def test_wrong_passphrase(sealed):
    with pytest.raises(WrongPassphrase):
        sealbox.open_bytes(sealed, "wrong")


def test_passphrase_accepts_bytes(sealed):
    assert sealbox.open_bytes(sealed, PASS.encode()) == SECRET


def test_tampered_ciphertext(sealed):
    env = json.loads(sealed)
    import base64

    ct = bytearray(base64.b64decode(env["ciphertext"]))
    ct[0] ^= 0xFF
    env["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    with pytest.raises(WrongPassphrase):
        sealbox.open_bytes(json.dumps(env).encode(), PASS)


def test_tampered_salt_changes_key(sealed):
    env = json.loads(sealed)
    env["salt"] = "AAAAAAAAAAAAAAAAAAAAAA=="
    with pytest.raises(WrongPassphrase):
        sealbox.open_bytes(json.dumps(env).encode(), PASS)


@pytest.mark.parametrize("salt_len", [7, 65])
def test_salt_length_bounds_enforced(sealed, salt_len):
    import base64

    env = json.loads(sealed)
    env["salt"] = base64.b64encode(b"x" * salt_len).decode()
    with pytest.raises(CorruptedBox):
        sealbox.open_bytes(json.dumps(env).encode(), PASS)


def test_garbage_input():
    with pytest.raises(CorruptedBox):
        sealbox.open_bytes(b"not json at all", PASS)


def test_wrong_format_field():
    fake = json.dumps({"format": "other", "version": 1}).encode()
    with pytest.raises(UnsupportedFormat):
        sealbox.open_bytes(fake, PASS)


def test_future_version(sealed):
    env = json.loads(sealed)
    env["version"] = 99
    with pytest.raises(UnsupportedFormat):
        sealbox.open_bytes(json.dumps(env).encode(), PASS)


def test_missing_fields(sealed):
    env = json.loads(sealed)
    del env["nonce"]
    with pytest.raises(CorruptedBox):
        sealbox.open_bytes(json.dumps(env).encode(), PASS)


def test_empty_plaintext_rejected():
    with pytest.raises(SealboxError):
        sealbox.seal_bytes(b"", PASS, kdf_params=FAST, algorithm="scrypt")


def test_inspect_bytes(sealed):
    meta = sealbox.inspect_bytes(sealed)
    assert meta["format"] == "sealbox"
    assert meta["version"] == 1
    assert meta["kdf"]["algorithm"] == "scrypt"
    assert meta["salt_bytes"] == box_mod.SALT_BYTES
    assert meta["nonce_bytes"] == box_mod.NONCE_BYTES
    assert meta["ciphertext_bytes"] == len(SECRET)  # tag cancels out 16-byte prefix


def test_argon2_roundtrip_when_available():
    pytest.importorskip("argon2")
    data = sealbox.seal_bytes(
        SECRET,
        PASS,
        algorithm="argon2id",
        kdf_params={"time_cost": 1, "memory_cost": 8192, "parallelism": 1},
    )
    assert sealbox.open_bytes(data, PASS) == SECRET


# ---------------------------------------------------------------- files API


def test_file_roundtrip(tmp_path: Path):
    src = tmp_path / "secrets.env"
    src.write_bytes(SECRET)

    box = sealbox.seal_file(src, passphrase=PASS, kdf_params=FAST, algorithm="scrypt")
    assert box == tmp_path / "secrets.env.sealbox"
    assert box.read_bytes() != SECRET  # never plaintext on disk

    src.unlink()  # simulate the real flow: plaintext gone, only the box remains
    out = sealbox.open_file(box, passphrase=PASS)
    assert out == src
    assert out.read_bytes() == SECRET


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_decrypted_file_is_owner_only(tmp_path: Path):
    src = tmp_path / "secrets.env"
    src.write_bytes(SECRET)
    box = sealbox.seal_file(src, passphrase=PASS, kdf_params=FAST, algorithm="scrypt")
    src.unlink()

    out = sealbox.open_file(box, passphrase=PASS)
    mode = stat.S_IMODE(out.stat().st_mode)
    assert mode == 0o600


def test_seal_refuses_overwrite(tmp_path: Path):
    src = tmp_path / "secrets.env"
    src.write_bytes(SECRET)
    sealbox.seal_file(src, passphrase=PASS, kdf_params=FAST, algorithm="scrypt")
    with pytest.raises(SealboxError):
        sealbox.seal_file(src, passphrase=PASS, kdf_params=FAST, algorithm="scrypt")
    sealbox.seal_file(src, passphrase=PASS, kdf_params=FAST, algorithm="scrypt", overwrite=True)


def test_open_refuses_overwrite(tmp_path: Path):
    src = tmp_path / "secrets.env"
    src.write_bytes(SECRET)
    box = sealbox.seal_file(src, passphrase=PASS, kdf_params=FAST, algorithm="scrypt")
    with pytest.raises(SealboxError):
        sealbox.open_file(box, passphrase=PASS)
    sealbox.open_file(box, passphrase=PASS, overwrite=True)


def test_open_output_can_be_forced(tmp_path: Path):
    src = tmp_path / "secrets.env"
    src.write_bytes(SECRET)
    box = sealbox.seal_file(src, passphrase=PASS, kdf_params=FAST, algorithm="scrypt")
    out = tmp_path / "restored.env"
    sealbox.open_file(box, out, passphrase=PASS)
    assert out.read_bytes() == SECRET


def test_default_plain_path_requires_suffix(tmp_path: Path):
    with pytest.raises(SealboxError):
        sealbox.open_file(tmp_path / "box_without_suffix", passphrase=PASS)


def test_missing_source_file(tmp_path: Path):
    with pytest.raises(SealboxError):
        sealbox.seal_file(tmp_path / "nope.env", passphrase=PASS)


def test_inspect_file(tmp_path: Path):
    src = tmp_path / "secrets.env"
    src.write_bytes(SECRET)
    box_path = sealbox.seal_file(src, passphrase=PASS, kdf_params=FAST, algorithm="scrypt")
    meta = sealbox.inspect_file(box_path)
    assert meta["kdf"]["algorithm"] == "scrypt"
