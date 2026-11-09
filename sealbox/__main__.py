"""Allow running the CLI as ``python -m sealbox``."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
