"""Entry point for ``python -m toob``."""

import os
import sys

# Ensure UTF-8 output on Windows terminals (prevents UnicodeEncodeError
# when click tries to print characters outside the system codepage).
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

from toob.cli import main  # noqa: E402 — env must be set first

main()
