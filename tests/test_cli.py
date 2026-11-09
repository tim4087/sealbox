from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from sealbox.cli import main

PASS = "cli-pass-42"
ENV_TEXT = b"API_TOKEN=super-secret\nDB_HOST=localhost\n"


@pytest.fixture(autouse=True)
def _fast_passphrase(monkeypatch):
    """CLI tests use the env var; no interactive prompts."""
    monkeypatch.setenv("SEALBOX_PASSPHRASE", PASS)


@pytest.fixture()
def env_file(tmp_path: Path) -> Path:
    p = tmp_path / "secrets.env"
    p.write_bytes(ENV_TEXT)
    return p


def _fast(monkeypatch):
    """Cut KDF cost so tests run instantly (valid params, just small)."""
    from sealbox import kdf

    monkeypatch.setattr(kdf, "default_algorithm", lambda: "scrypt")
    real = kdf.default_params

    def fast(algorithm):
        if algorithm == "scrypt":
            return {"n": 1024, "r": 8, "p": 1}
        return real(algorithm)

    monkeypatch.setattr(kdf, "default_params", fast)


def test_seal_then_open_roundtrip(tmp_path: Path, env_file: Path, monkeypatch, capsys):
    _fast(monkeypatch)
    assert main(["seal", str(env_file)]) == 0
    box = tmp_path / "secrets.env.sealbox"
    assert box.is_file()
    assert box.read_bytes() != ENV_TEXT

    # plaintext removed -> open recreates it
    env_file.unlink()
    assert main(["open", str(box)]) == 0
    assert env_file.read_bytes() == ENV_TEXT


def test_open_refuses_overwrite(tmp_path: Path, env_file: Path, monkeypatch):
    _fast(monkeypatch)
    main(["seal", str(env_file)])
    box = tmp_path / "secrets.env.sealbox"
    assert main(["open", str(box)]) == 1  # secrets.env already exists

    assert main(["open", str(box), "--force"]) == 0


def test_open_wrong_passphrase(tmp_path: Path, env_file: Path, monkeypatch, capsys):
    _fast(monkeypatch)
    main(["seal", str(env_file)])
    env_file.unlink()

    monkeypatch.setenv("SEALBOX_PASSPHRASE", "not-it")
    assert main(["open", str(tmp_path / "secrets.env.sealbox")]) == 1
    assert "sealbox" in capsys.readouterr().err


def test_show_prints_plaintext(tmp_path: Path, env_file: Path, monkeypatch, capsys):
    _fast(monkeypatch)
    main(["seal", str(env_file)])
    capsys.readouterr()

    assert main(["show", str(tmp_path / "secrets.env.sealbox")]) == 0
    out = capsys.readouterr().out
    assert "API_TOKEN=super-secret" in out


def test_show_writes_exact_bytes(tmp_path: Path, monkeypatch, capsysbinary):
    """`show` must not invent a trailing newline: binary payloads get corrupted."""
    from sealbox import seal_bytes

    _fast(monkeypatch)
    payload = b"\x00\x01binary-no-newline"  # no trailing \n on purpose
    box = tmp_path / "blob.sealbox"
    box.write_bytes(seal_bytes(payload, PASS, algorithm="scrypt", kdf_params={"n": 1024, "r": 8, "p": 1}))

    assert main(["show", str(box)]) == 0
    assert capsysbinary.readouterr().out == payload


def test_python_dash_m_invocation(monkeypatch):
    import subprocess

    _fast(monkeypatch)
    proc = subprocess.run(
        [sys.executable, "-m", "sealbox", "--version"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "sealbox" in proc.stdout


def test_empty_passphrase_file_rejected(tmp_path: Path, env_file: Path, monkeypatch):
    _fast(monkeypatch)
    monkeypatch.delenv("SEALBOX_PASSPHRASE", raising=False)
    pf = tmp_path / "empty.txt"
    pf.write_text("\n")
    assert main(["open", str(tmp_path / "secrets.env.sealbox"), "--passphrase-file", str(pf)]) == 1


def test_env_command_runs_subprocess(tmp_path: Path, env_file: Path, monkeypatch, capfd):
    _fast(monkeypatch)
    main(["seal", str(env_file)])
    box = str(tmp_path / "secrets.env.sealbox")

    probe = "import os; print(os.environ.get('API_TOKEN', 'MISSING'))"
    assert main(["env", box, "--", sys.executable, "-c", probe]) == 0
    assert "super-secret" in capfd.readouterr().out


def test_rotate_changes_passphrase(tmp_path: Path, env_file: Path, monkeypatch):
    _fast(monkeypatch)
    main(["seal", str(env_file)])
    box = tmp_path / "secrets.env.sealbox"

    new_pass_file = tmp_path / "newpass.txt"
    new_pass_file.write_text("brand-new-pass\n")
    assert main(["rotate", str(box), "--new-passphrase-file", str(new_pass_file)]) == 0

    # old passphrase no longer works, new one does
    from sealbox import open_bytes
    from sealbox.errors import WrongPassphrase

    with pytest.raises(WrongPassphrase):
        open_bytes(box.read_bytes(), PASS)
    assert open_bytes(box.read_bytes(), "brand-new-pass") == ENV_TEXT


def test_inspect(tmp_path: Path, env_file: Path, monkeypatch, capsys):
    _fast(monkeypatch)
    main(["seal", str(env_file)])
    capsys.readouterr()
    assert main(["inspect", str(tmp_path / "secrets.env.sealbox")]) == 0
    meta = json.loads(capsys.readouterr().out)
    assert meta["format"] == "sealbox"
    assert meta["version"] == 1
    assert "ciphertext" not in meta  # no secrets in metadata


def test_passphrase_file_option(tmp_path: Path, env_file: Path, monkeypatch, capsys):
    _fast(monkeypatch)
    monkeypatch.delenv("SEALBOX_PASSPHRASE", raising=False)
    pf = tmp_path / "pass.txt"
    pf.write_text(PASS + "\n")

    assert main(["seal", str(env_file), "--passphrase-file", str(pf)]) == 0
    env_file.unlink()
    assert main(["open", str(tmp_path / "secrets.env.sealbox"), "--passphrase-file", str(pf)]) == 0
    assert env_file.read_bytes() == ENV_TEXT


def test_seal_missing_file(tmp_path: Path, capsys):
    assert main(["seal", str(tmp_path / "ghost.env")]) == 1
    assert "ошибка" in capsys.readouterr().err


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_open_sets_0600(tmp_path: Path, env_file: Path, monkeypatch):
    _fast(monkeypatch)
    main(["seal", str(env_file)])
    env_file.unlink()
    main(["open", str(tmp_path / "secrets.env.sealbox")])
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
