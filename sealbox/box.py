"""Core sealing/opening logic: the box envelope format and file helpers.

A sealed box is a UTF-8 JSON document that looks like this::

    {
     "ciphertext": "<base64, AES-256-GCM (last 16 bytes are the tag)>",
     "format": "sealbox",
     "kdf": {"algorithm": "scrypt", "n": 32768, "p": 1, "r": 8},
     "nonce": "<base64, 12 bytes>",
     "salt": "<base64, 16 bytes>",
     "version": 1
    }

The JSON is deliberately flat and sorted so that re-sealing the same payload
with the same salt/nonce produces byte-identical files (nice for git).
Only the AES-GCM ciphertext is base64-encoded, never the plaintext.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import kdf
from .errors import CorruptedBox, SealboxError, UnsupportedFormat, WrongPassphrase

FORMAT = "sealbox"
VERSION = 1

#: Suffix appended to sealed files: ``secrets.env`` -> ``secrets.env.sealbox``.
SUFFIX = ".sealbox"

SALT_BYTES = 16
#: Accepted salt range when *reading* boxes (argon2 needs >= 8 bytes).
SALT_MIN_BYTES = 8
SALT_MAX_BYTES = 64
NONCE_BYTES = 12
KEY_BYTES = kdf.KEY_BYTES

#: Additional authenticated data: binds the box to its format and version.
_AAD = f"{FORMAT}/{VERSION}".encode("ascii")

PathLike = Union[str, "os.PathLike[str]"]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise CorruptedBox("invalid base64 payload in box") from exc


def _wipe(buf: bytearray) -> None:
    """Best-effort zeroization of sensitive memory (Python gives no guarantees)."""
    for i in range(len(buf)):
        buf[i] = 0


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Write *data* to *path* atomically (tmp file in the same dir + rename)."""
    tmp = path.with_name(f".{path.name}.tmp-{os.urandom(4).hex()}")
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if tmp.exists():  # only on failure paths
            tmp.unlink(missing_ok=True)


def _set_owner_only(path: Path) -> None:
    """Best-effort chmod 0600 on platforms that support it."""
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - Windows/exotic filesystems
        pass


# --------------------------------------------------------------------------
# bytes-level API
# --------------------------------------------------------------------------

def seal_bytes(
    plaintext: bytes,
    passphrase: bytes | str,
    *,
    algorithm: Optional[str] = None,
    kdf_params: Optional[Mapping[str, Any]] = None,
) -> bytes:
    """Encrypt *plaintext* with *passphrase* and return serialized box bytes."""
    if not plaintext:
        raise SealboxError("plaintext must not be empty")

    algorithm = algorithm or kdf.default_algorithm()
    params = dict(kdf_params) if kdf_params is not None else kdf.default_params(algorithm)

    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)

    key = bytearray(kdf.derive_key(passphrase, salt, algorithm, params))
    try:
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, plaintext, _AAD)
    finally:
        _wipe(key)

    envelope = {
        "format": FORMAT,
        "version": VERSION,
        "kdf": {"algorithm": algorithm, **params},
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }
    return (json.dumps(envelope, sort_keys=True, indent=1) + "\n").encode("utf-8")


def open_bytes(box_data: bytes, passphrase: bytes | str) -> bytes:
    """Decrypt a serialized box and return the plaintext bytes."""
    try:
        envelope = json.loads(box_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorruptedBox("not a valid sealbox file (invalid JSON)") from exc
    if not isinstance(envelope, dict):
        raise CorruptedBox("not a valid sealbox file (root is not an object)")

    if envelope.get("format") != FORMAT:
        raise UnsupportedFormat(f"not a sealbox file: format={envelope.get('format')!r}")
    if envelope.get("version") != VERSION:
        raise UnsupportedFormat(
            f"unsupported box version {envelope.get('version')!r} "
            f"(this sealbox understands version {VERSION})"
        )

    try:
        kdf_header = envelope["kdf"]
        algorithm = kdf_header["algorithm"]
        params = {k: v for k, v in kdf_header.items() if k != "algorithm"}
        salt = _b64decode(envelope["salt"])
        nonce = _b64decode(envelope["nonce"])
        ciphertext = _b64decode(envelope["ciphertext"])
    except (KeyError, TypeError) as exc:
        raise CorruptedBox(f"box is missing required field: {exc}") from exc

    if len(nonce) != NONCE_BYTES:
        raise CorruptedBox("nonce has unexpected length")
    if not SALT_MIN_BYTES <= len(salt) <= SALT_MAX_BYTES:
        raise CorruptedBox(f"salt length {len(salt)} outside the accepted range")
    if len(ciphertext) < 16:  # GCM tag alone is 16 bytes
        raise CorruptedBox("ciphertext is too short to be valid")

    try:
        key_material = kdf.derive_key(passphrase, salt, algorithm, params)
    except SealboxError:
        raise
    except (ValueError, TypeError, OverflowError) as exc:
        # e.g. hashlib/argon2 rejecting impossible parameter combinations
        raise CorruptedBox(f"KDF rejected the box parameters: {exc}") from exc
    key = bytearray(key_material)
    try:
        try:
            return AESGCM(bytes(key)).decrypt(nonce, ciphertext, _AAD)
        except InvalidTag as exc:
            raise WrongPassphrase(
                "wrong passphrase, or the box has been tampered with"
            ) from exc
    finally:
        _wipe(key)


def inspect_bytes(box_data: bytes) -> dict[str, Any]:
    """Return box metadata (no passphrase needed). Never exposes plaintext."""
    try:
        envelope = json.loads(box_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorruptedBox("not a valid sealbox file (invalid JSON)") from exc
    if not isinstance(envelope, dict) or envelope.get("format") != FORMAT:
        raise UnsupportedFormat("not a sealbox file")

    return {
        "format": envelope.get("format"),
        "version": envelope.get("version"),
        "kdf": envelope.get("kdf"),
        "salt_bytes": len(_b64decode(envelope.get("salt", ""))) if "salt" in envelope else None,
        "nonce_bytes": len(_b64decode(envelope.get("nonce", ""))) if "nonce" in envelope else None,
        "ciphertext_bytes": (
            len(_b64decode(envelope["ciphertext"])) - 16 if "ciphertext" in envelope else None
        ),
    }


# --------------------------------------------------------------------------
# file-level API
# --------------------------------------------------------------------------

def default_box_path(src: PathLike) -> Path:
    """``dir/file.env`` -> ``dir/file.env.sealbox``."""
    return Path(src).with_name(Path(src).name + SUFFIX)


def default_plain_path(box: PathLike) -> Path:
    """``dir/file.env.sealbox`` -> ``dir/file.env`` (errors if suffix missing)."""
    p = Path(box)
    if p.suffix != SUFFIX:
        raise SealboxError(
            f"cannot guess output name for {p}: expected the {SUFFIX} suffix, "
            "pass -o/--output explicitly"
        )
    return p.with_name(p.name[: -len(SUFFIX)])


def seal_file(
    src: PathLike,
    dst: Optional[PathLike] = None,
    *,
    passphrase: bytes | str,
    algorithm: Optional[str] = None,
    kdf_params: Optional[Mapping[str, Any]] = None,
    overwrite: bool = False,
) -> Path:
    """Encrypt the file *src* and write the box to *dst* (default: src + suffix)."""
    src_path = Path(src)
    if not src_path.is_file():
        raise SealboxError(f"no such file: {src_path}")

    dst_path = Path(dst) if dst is not None else default_box_path(src_path)
    if dst_path.exists() and not overwrite:
        raise SealboxError(f"refusing to overwrite existing file {dst_path} (use overwrite=True)")

    box_data = seal_bytes(
        src_path.read_bytes(), passphrase, algorithm=algorithm, kdf_params=kdf_params
    )
    _atomic_write(dst_path, box_data, mode=0o644)  # the box itself is ciphertext
    return dst_path


def open_file(
    box: PathLike,
    dst: Optional[PathLike] = None,
    *,
    passphrase: bytes | str,
    overwrite: bool = False,
) -> Path:
    """Decrypt the box file *box* and write plaintext to *dst* with mode 0600."""
    box_path = Path(box)
    if not box_path.is_file():
        raise SealboxError(f"no such file: {box_path}")

    dst_path = Path(dst) if dst is not None else default_plain_path(box_path)
    if dst_path.exists() and not overwrite:
        raise SealboxError(f"refusing to overwrite existing file {dst_path} (use overwrite=True)")

    plaintext = open_bytes(box_path.read_bytes(), passphrase)
    _atomic_write(dst_path, plaintext, mode=0o600)
    _set_owner_only(dst_path)
    return dst_path


def inspect_file(box: PathLike) -> dict[str, Any]:
    """Return metadata about a box file without needing the passphrase."""
    return inspect_bytes(Path(box).read_bytes())
