"""sealbox — a tiny encrypted vault for secrets.

Seal any file (``.env``, keys, dumps) with a single passphrase using
AES-256-GCM and a memory-hard KDF (scrypt or Argon2id).  The result is a
portable JSON "box" that is safe to commit to git.

    >>> import sealbox
    >>> box = sealbox.seal_bytes(b"TOKEN=s3cr3t", "hunter2")
    >>> sealbox.open_bytes(box, "hunter2")
    b'TOKEN=s3cr3t'
"""

from __future__ import annotations

from .box import (
    FORMAT,
    SUFFIX,
    VERSION,
    default_box_path,
    default_plain_path,
    inspect_bytes,
    inspect_file,
    open_bytes,
    open_file,
    seal_bytes,
    seal_file,
)
from .env import load_sealed_env, parse_env, run_with_sealed_env
from .errors import CorruptedBox, SealboxError, UnsupportedFormat, WrongPassphrase

__version__ = "0.1.0"

__all__ = [
    "FORMAT",
    "SUFFIX",
    "VERSION",
    "CorruptedBox",
    "SealboxError",
    "UnsupportedFormat",
    "WrongPassphrase",
    "default_box_path",
    "default_plain_path",
    "inspect_bytes",
    "inspect_file",
    "load_sealed_env",
    "open_bytes",
    "open_file",
    "parse_env",
    "run_with_sealed_env",
    "seal_bytes",
    "seal_file",
    "__version__",
]
