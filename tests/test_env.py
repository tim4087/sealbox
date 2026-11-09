from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import sealbox
from sealbox.env import parse_env, read_passphrase, run_with_sealed_env

FAST = {"n": 1024, "r": 8, "p": 1}
PASS = "pass-123"
ENV_TEXT = (
    "# comment line\n"
    "\n"
    "DATABASE_URL=postgres://user:pw@localhost/db\n"
    "export API_TOKEN=abc123\n"
    "QUOTED='hello world'\n"
    "DQUOTED=\"with # hash\"\n"
    "NO_EQUALS_LINE\n"
    "EMPTY=\n"
)


def test_parse_env_basics():
    env = parse_env(ENV_TEXT)
    assert env == {
        "DATABASE_URL": "postgres://user:pw@localhost/db",
        "API_TOKEN": "abc123",
        "QUOTED": "hello world",
        "DQUOTED": "with # hash",
        "EMPTY": "",
    }


def test_load_sealed_env_sets_environ(tmp_path: Path, monkeypatch):
    box = tmp_path / "env.sealbox"
    box.write_bytes(sealbox.seal_bytes(ENV_TEXT.encode(), PASS, kdf_params=FAST, algorithm="scrypt"))

    monkeypatch.delenv("API_TOKEN", raising=False)
    loaded = sealbox.load_sealed_env(box, PASS)
    assert loaded["API_TOKEN"] == "abc123"
    assert os.environ["API_TOKEN"] == "abc123"


def test_load_sealed_env_respects_existing(monkeypatch, tmp_path: Path):
    box = tmp_path / "env.sealbox"
    box.write_bytes(sealbox.seal_bytes(b"API_TOKEN=from_box\n", PASS, kdf_params=FAST, algorithm="scrypt"))

    monkeypatch.setenv("API_TOKEN", "already_here")
    sealbox.load_sealed_env(box, PASS)
    assert os.environ["API_TOKEN"] == "already_here"

    sealbox.load_sealed_env(box, PASS, override=True)
    assert os.environ["API_TOKEN"] == "from_box"


def test_run_with_sealed_env(tmp_path: Path):
    box = tmp_path / "env.sealbox"
    box.write_bytes(sealbox.seal_bytes(b"SEALBOX_TEST_VAR=42\n", PASS, kdf_params=FAST, algorithm="scrypt"))

    code = run_with_sealed_env(
        box,
        [sys.executable, "-c", "import os; raise SystemExit(0 if os.environ['SEALBOX_TEST_VAR']=='42' else 3)"],
        PASS,
    )
    assert code == 0


def test_read_passphrase_from_file(tmp_path: Path):
    pf = tmp_path / "pass.txt"
    pf.write_text("s3cret\n")
    assert read_passphrase(passphrase_file=pf) == "s3cret"


def test_read_passphrase_from_env(monkeypatch):
    monkeypatch.setenv("SEALBOX_PASSPHRASE", "env-secret")
    assert read_passphrase() == "env-secret"


def test_read_passphrase_priority_file_wins(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SEALBOX_PASSPHRASE", "env-secret")
    pf = tmp_path / "pass.txt"
    pf.write_text("file-secret\n")
    assert read_passphrase(passphrase_file=pf) == "file-secret"


def test_read_passphrase_missing_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        read_passphrase(passphrase_file=tmp_path / "nope.txt")
