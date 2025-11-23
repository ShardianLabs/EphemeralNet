#!/usr/bin/env python3
"""Emit a stable hash for CMake configuration inputs."""
from __future__ import annotations

import hashlib
from pathlib import Path

PATTERNS = [
    "CMakeLists.txt",
    "cmake/**/*.cmake",
]

def main() -> None:
    root = Path.cwd()
    files = set()
    for pattern in PATTERNS:
        files.update(path for path in root.glob(pattern) if path.is_file())

    if not files:
        print("none")
        return

    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(path.read_bytes())
    print(digest.hexdigest())


if __name__ == "__main__":
    main()
