"""
Standalone PyInstaller Executable Builder for AnubisTrace.
Compiles the application into a single self-contained portable executable (anubis.exe / anubis)
ready for field triage on a USB drive without requiring Python or external runtimes.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path


def build_binary() -> int:
    """Builds the single-file executable using PyInstaller."""
    root_dir = Path(__file__).parent.parent.parent.resolve()
    entry_point = root_dir / "anubistrace" / "cli.py"
    rules_dir = root_dir / "rules"

    print("=" * 65)
    print("  AnubisTrace - Standalone Portable USB Builder")
    print("=" * 65)
    print(f"[*] Project root: {root_dir}")
    print(f"[*] Target entry point: {entry_point}")

    # Determine data separator (; on Windows, : on Linux)
    sep = ";" if platform.system().lower() == "windows" else ":"
    data_arg = f"--add-data={rules_dir}{sep}rules"

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--clean",
        "--name=anubis",
        data_arg,
        str(entry_point),
    ]

    print(f"[*] Executing build command:\n    {' '.join(cmd)}\n")

    try:
        proc = subprocess.run(cmd, cwd=str(root_dir))
        if proc.returncode == 0:
            dist_path = root_dir / "dist"
            print("-" * 65)
            print("[✓] BUILD SUCCEEDED!")
            print(f"[✓] Standalone binary is located in: {dist_path}")
            return 0
        else:
            print(f"[-] PyInstaller failed with exit code: {proc.returncode}", file=sys.stderr)
            return proc.returncode
    except FileNotFoundError:
        print("[-] PyInstaller is not installed in the current environment.", file=sys.stderr)
        print("    Install it via: pip install pyinstaller", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(build_binary())
