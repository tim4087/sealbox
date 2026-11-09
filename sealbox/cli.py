"""Command-line interface: ``sealbox <command> ...``.

The passphrase is never accepted as a plain command-line argument (it would
leak into shell history and ``/proc``).  Instead, in priority order:

1. ``--passphrase-file PATH`` — first line of the file is used;
2. ``SEALBOX_PASSPHRASE`` environment variable;
3. interactive hidden prompt (``seal`` asks twice).
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .box import default_box_path, open_bytes, open_file, seal_bytes, seal_file
from .env import read_passphrase, run_with_sealed_env
from .errors import SealboxError
from .kdf import available_algorithms, default_algorithm

ENV_VAR = "SEALBOX_PASSPHRASE"


# --------------------------------------------------------------------------
# passphrase handling
# --------------------------------------------------------------------------

def _resolve_passphrase(args: argparse.Namespace) -> str:
    secret = read_passphrase(passphrase_file=getattr(args, "passphrase_file", None))
    if secret is not None:
        if not secret:
            raise SealboxError("passphrase file must not be empty")
        return secret
    try:
        return getpass.getpass("Пароль: ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise SealboxError("passphrase input cancelled") from exc


def _resolve_new_passphrase(args: argparse.Namespace, file_attr: str = "new_passphrase_file") -> str:
    secret = read_passphrase(passphrase_file=getattr(args, file_attr, None))
    if secret is not None:
        if not secret:
            raise SealboxError("passphrase file must not be empty")
        return secret
    try:
        first = getpass.getpass("Новый пароль: ")
        second = getpass.getpass("Повторите пароль: ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise SealboxError("passphrase input cancelled") from exc
    if first != second:
        raise SealboxError("passwords do not match")
    if not first:
        raise SealboxError("passphrase must not be empty")
    return first


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_seal(args: argparse.Namespace) -> int:
    src = Path(args.file)
    dst = Path(args.output) if args.output else default_box_path(src)
    # sealing *sets* a new passphrase, so a file source needs no confirmation
    passphrase = _resolve_new_passphrase(args, file_attr="passphrase_file")
    seal_file(
        src,
        dst,
        passphrase=passphrase,
        algorithm=args.algo,
        overwrite=args.force,
    )
    print(f"Запечатано: {src} -> {dst} ({args.algo or default_algorithm()})")
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    dst = open_file(
        args.box,
        args.output,
        passphrase=_resolve_passphrase(args),
        overwrite=args.force,
    )
    print(f"Распечатано: {args.box} -> {dst}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    plaintext = open_bytes(Path(args.box).read_bytes(), _resolve_passphrase(args))
    # Write exact bytes: appending a newline would corrupt binary payloads
    # when the output is redirected to a file.
    sys.stdout.buffer.write(plaintext)
    sys.stdout.buffer.flush()
    return 0


def cmd_env(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("sealbox env: команда для запуска не указана", file=sys.stderr)
        return 2
    return run_with_sealed_env(args.box, command, _resolve_passphrase(args))


def cmd_rotate(args: argparse.Namespace) -> int:
    box_path = Path(args.box)
    plaintext = open_bytes(box_path.read_bytes(), _resolve_passphrase(args))
    new_passphrase = _resolve_new_passphrase(args)

    new_box = seal_bytes(plaintext, new_passphrase, algorithm=args.algo)
    tmp = box_path.with_name(f".{box_path.name}.tmp-{os.urandom(4).hex()}")
    try:
        tmp.write_bytes(new_box)
        os.replace(tmp, box_path)
    finally:
        tmp.unlink(missing_ok=True)
    print(f"Перезапечатано с новым паролем: {box_path}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    from .box import inspect_file

    meta = inspect_file(args.box)
    print(json.dumps(meta, indent=2, sort_keys=True))
    return 0


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sealbox",
        description="Мини-сейф для секретов: шифрует файлы одним паролем (AES-256-GCM).",
    )
    parser.add_argument("--version", action="version", version=f"sealbox {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_passphrase_options(p: argparse.ArgumentParser, new: bool = False) -> None:
        if new:
            p.add_argument(
                "--new-passphrase-file",
                metavar="FILE",
                help=f"файл с новым паролем (иначе спросит дважды; или {ENV_VAR})",
            )
        else:
            p.add_argument(
                "--passphrase-file",
                metavar="FILE",
                help=f"файл с паролем (иначе спросит; или переменная {ENV_VAR})",
            )

    p_seal = sub.add_parser("seal", help="зашифровать файл")
    p_seal.add_argument("file", help="файл с секретами, например secrets.env")
    p_seal.add_argument("-o", "--output", help="куда записать бокс (по умолчанию FILE.sealbox)")
    p_seal.add_argument(
        "--algo",
        choices=available_algorithms(),
        default=None,
        help=f"KDF для ключа (по умолчанию {default_algorithm()})",
    )
    p_seal.add_argument("-f", "--force", action="store_true", help="перезаписать существующий бокс")
    add_passphrase_options(p_seal)
    p_seal.set_defaults(func=cmd_seal)

    p_open = sub.add_parser("open", help="расшифровать бокс в файл")
    p_open.add_argument("box", help="файл .sealbox")
    p_open.add_argument("-o", "--output", help="куда записать (по умолчанию убрать суффикс)")
    p_open.add_argument("-f", "--force", action="store_true", help="перезаписать существующий файл")
    add_passphrase_options(p_open)
    p_open.set_defaults(func=cmd_open)

    p_show = sub.add_parser("show", help="показать содержимое бокса в stdout")
    p_show.add_argument("box", help="файл .sealbox")
    add_passphrase_options(p_show)
    p_show.set_defaults(func=cmd_show)

    p_env = sub.add_parser("env", help="запустить команду с секретами из бокса в окружении")
    p_env.add_argument("box", help="файл .sealbox с переменными KEY=VALUE")
    p_env.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        metavar="CMD",
        help="команда: sealbox env box.sealbox -- python app.py",
    )
    add_passphrase_options(p_env)
    p_env.set_defaults(func=cmd_env)

    p_rotate = sub.add_parser("rotate", help="сменить пароль бокса")
    p_rotate.add_argument("box", help="файл .sealbox")
    p_rotate.add_argument("--algo", choices=available_algorithms(), default=None)
    add_passphrase_options(p_rotate)  # old passphrase
    p_rotate.add_argument(
        "--new-passphrase-file",
        metavar="FILE",
        help="файл с новым паролем",
    )
    p_rotate.set_defaults(func=cmd_rotate)

    p_inspect = sub.add_parser("inspect", help="показать метаданные бокса (без пароля)")
    p_inspect.add_argument("box", help="файл .sealbox")
    p_inspect.set_defaults(func=cmd_inspect)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SealboxError as exc:
        print(f"sealbox: ошибка: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:  # full disk, permissions, missing files, ...
        print(f"sealbox: ошибка ввода-вывода: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
