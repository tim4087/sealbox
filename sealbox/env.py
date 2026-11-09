"""Helpers for working with sealed ``.env`` files.

A typical workflow: keep ``secrets.env.sealbox`` in git, never the plaintext
``secrets.env``. Locally (or in CI) the box is opened with a passphrase and the
secrets are injected into ``os.environ`` or into a child process.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence, Union

from .box import open_bytes

PathLike = Union[str, "os.PathLike[str]"]


def parse_env(text: str) -> dict[str, str]:
    """Parse simple ``KEY=VALUE`` .env content into a dict.

    Supported: blank lines, ``#`` comments, an optional ``export `` prefix,
    and values wrapped entirely in single or double quotes.  Inline ``#`` is
    *not* treated as a comment start, so values containing ``#`` survive.
    """
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            result[key] = value
    return result


def load_sealed_env(
    box: PathLike,
    passphrase: bytes | str,
    *,
    override: bool = False,
) -> dict[str, str]:
    """Decrypt a sealed .env file and merge it into :data:`os.environ`.

    Existing variables win unless ``override=True``.  Returns the parsed
    key/value pairs without touching the environment copy.
    """
    env = parse_env(open_bytes(Path(box).read_bytes(), passphrase).decode("utf-8"))
    for key, value in env.items():
        if override or key not in os.environ:
            os.environ[key] = value
    return env


def run_with_sealed_env(
    box: PathLike,
    argv: Sequence[str],
    passphrase: bytes | str,
) -> int:
    """Run ``argv`` as a subprocess with secrets from the box in its environment.

    Returns the process exit code.  On Windows this raises
    :class:`RuntimeError` because semantics of credential-bearing environment
    inheritance differ; use :func:`load_sealed_env` there instead.
    """
    if sys.platform == "win32":  # pragma: no cover - documented limitation
        raise RuntimeError("run_with_sealed_env is not supported on Windows")

    secrets = parse_env(open_bytes(Path(box).read_bytes(), passphrase).decode("utf-8"))
    env = os.environ.copy()
    env.update(secrets)
    return subprocess.call(list(argv), env=env)


def read_passphrase(
    *,
    passphrase_file: Optional[PathLike] = None,
    env_var: str = "SEALBOX_PASSPHRASE",
    prompt: str = "Passphrase: ",
) -> Optional[str]:
    """Resolve a passphrase without ever taking it from a CLI argument.

    Priority: file -> environment variable -> interactive prompt (None here
    means "caller should ask interactively").  Kept in this module so both the
    CLI and user code share one policy.
    """
    if passphrase_file is not None:
        path = Path(passphrase_file)
        if not path.is_file():
            raise FileNotFoundError(f"passphrase file not found: {path}")
        with open(path, "r", encoding="utf-8") as fh:
            return fh.readline().rstrip("\r\n")

    env_value = os.environ.get(env_var)
    if env_value:
        return env_value

    return None
