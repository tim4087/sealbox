# sealbox 🔐

**A tiny encrypted vault for your secrets.** Seal `.env` files, keys, or any
other file with a single passphrase — the result is a compact JSON "box" that
is safe to commit to git.

[Читать по-русски](README.ru.md)

- **AES-256-GCM** — battle-tested authenticated encryption (via the `cryptography` library)
- **scrypt** (from the stdlib) or **Argon2id** (optional) — memory-hard key derivation
- Fresh **salt + nonce** on every seal; any tampering is detected (GCM tag)
- **No passphrases in command-line arguments** — file, environment variable, or hidden prompt only
- Atomic writes, `0600` permissions on decrypted files, zero dependencies beyond `cryptography`
- CLI + Python API, fully typed, 59 tests

```text
$ sealbox seal secrets.env          # -> secrets.env.sealbox (asks for a passphrase twice)
$ sealbox open secrets.env.sealbox  # -> secrets.env
$ sealbox env secrets.env.sealbox -- python app.py   # secrets land in os.environ
```

Think `age` or `sops`, but tiny and built around a single passphrase.

## Installation

```bash
pip install sealbox            # from source: pip install .
pip install 'sealbox[argon2]'  # + Argon2id instead of scrypt (recommended)
```

Requires Python 3.9+.

## CLI

| Command | What it does |
|---|---|
| `sealbox seal FILE [-o OUT] [--algo scrypt\|argon2id] [-f]` | Encrypt a file (defaults to `FILE.sealbox`) |
| `sealbox open BOX [-o OUT] [-f]` | Decrypt to a file (`0600` permissions) |
| `sealbox show BOX` | Print the contents to stdout |
| `sealbox env BOX -- CMD [ARGS...]` | Run a command with `KEY=VALUE` pairs from the box in its environment |
| `sealbox rotate BOX` | Change the passphrase (the KDF is upgraded to the current default) |
| `sealbox inspect BOX` | Show metadata without the passphrase (KDF, sizes) |

**How the passphrase is supplied** (by priority; never as a CLI argument):

1. `--passphrase-file FILE` — the first line of the file;
2. the `SEALBOX_PASSPHRASE` environment variable (handy in CI);
3. a hidden interactive prompt (`seal` asks twice).

A typical CI snippet:

```bash
echo "$SEALBOX_PASS" > /tmp/pass.txt
sealbox open secrets.env.sealbox --passphrase-file /tmp/pass.txt
shred -u /tmp/pass.txt
```

The CLI also works as a module: `python -m sealbox …`.

## Python API

```python
import sealbox

# bytes
box = sealbox.seal_bytes(b"TOKEN=s3cr3t", passphrase)
assert sealbox.open_bytes(box, passphrase) == b"TOKEN=s3cr3t"

# files
sealbox.seal_file("secrets.env", passphrase=passphrase)          # -> secrets.env.sealbox
sealbox.open_file("secrets.env.sealbox", passphrase=passphrase)  # -> secrets.env

# .env variables straight into os.environ
sealbox.load_sealed_env("secrets.env.sealbox", passphrase)

# run a child process with the secrets in its environment
sealbox.run_with_sealed_env("secrets.env.sealbox", ["python", "app.py"], passphrase)

# metadata (no passphrase needed)
print(sealbox.inspect_file("secrets.env.sealbox"))
```

Exceptions: `WrongPassphrase` (wrong passphrase or modified data — AES-GCM
cannot tell the two apart), `CorruptedBox`, `UnsupportedFormat`, all deriving
from `SealboxError`.

## Box format

UTF-8 JSON with base64 fields, keys sorted:

```json
{
 "ciphertext": "…(AES-256-GCM, last 16 bytes are the tag)…",
 "format": "sealbox",
 "kdf": {"algorithm": "scrypt", "n": 32768, "p": 1, "r": 8},
 "nonce": "…12 bytes…",
 "salt": "…16 bytes…",
 "version": 1
}
```

- AAD = `"sealbox/1"` binds the ciphertext to the format version.
- KDF parameters live inside the box, so changing defaults in future releases
  never breaks old files (and boxes with excessive parameters are rejected).
- The original file name is not stored — metadata is kept to a minimum.

## Threat model

**Protects against:** secrets leaking through git, backups, accidentally
shared folders, screenshots/copies of the encrypted file — without the
passphrase it is all noise.

**Does NOT protect against:** keyloggers and a compromised OS, brute-forcing
a weak passphrase (the KDF slows cracking down but is no substitute for a
strong passphrase), a lost passphrase (there is no recovery), or plaintext
sitting next to the box.

Passphrases are deliberately never accepted as CLI arguments: arguments are
visible in shell history and in `/proc/<pid>/cmdline`.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev,argon2]'
pytest
```

## Roadmap

- [ ] `sealbox seal --shred` — best-effort wiping of plaintext after sealing
- [ ] `sealbox seal-dir` — sealing whole directories (tar + encryption)
- [ ] Multiple recipients (public-key sealing)
- [ ] `sealbox audit` — check whether plaintext ever leaked into git history

## License

MIT — see [LICENSE](LICENSE).
