#!/usr/bin/env python3
"""Fails if a Microsoft Store build holds what the `store` feature leaves out.

The Store installs, updates and removes r7z, so its programs have no use for the portable
copy's updater, installer or self-delete. Keeping them out matters beyond size: Huorong
removed the Store build of 0.1.9 as ransomware, and a program that encrypts files, walks
drives and also deletes itself with a hidden `cmd` is what such rules look for.

    python scripts/check_store_build.py target/store/release
"""
import sys
from pathlib import Path

PROGRAMS = ("r7z.exe", "r7z-gui.exe", "r7z_shell.dll")

# Text each piece of left-out code can't run without. Compared without regard to case.
MARKERS = {
    "ping -n": "the self-delete that follows uninstalling",
    "rd /s": "the self-delete that follows uninstalling",
    "powershell.exe": "registering the Windows 11 menu",
    "add-appxpackage": "registering the Windows 11 menu",
    "remove-appxpackage": "registering the Windows 11 menu",
    r"currentversion\uninstall": "the Installed apps entry",
    "ureq": "the HTTP client, which only the updater uses",
    "r7z-update": "the updater's signed manifest",
}


def findings(data: bytes) -> list[str]:
    """The markers found in a program, as ASCII or as UTF-16."""
    data = data.lower()
    found = []
    for marker in MARKERS:
        if marker.encode() in data or marker.encode("utf-16-le") in data:
            found.append(marker)
    return found


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    target = Path(argv[1])
    paths = [target] if target.is_file() else [target / name for name in PROGRAMS]
    failed = False
    for path in paths:
        if not path.is_file():
            print(f"{path}: missing", file=sys.stderr)
            failed = True
            continue
        found = findings(path.read_bytes())
        for marker in found:
            print(f"{path.name}: holds {marker!r} ({MARKERS[marker]})", file=sys.stderr)
        failed |= bool(found)
    if not failed:
        print("the Store build holds none of the left-out code")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
