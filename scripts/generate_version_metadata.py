#!/usr/bin/env python3
"""Emit latest release metadata for eph.shardian.com/latest.json."""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Any, Dict

ROOT = pathlib.Path(__file__).resolve().parent.parent
CMAKE_PATH = ROOT / "CMakeLists.txt"
DEFAULT_REPO = "ShardianLabs/EphemeralNet"

PROJECT_VERSION_PATTERN = re.compile(r"project\(\s*EphemeralNet\s+VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)


def read_project_version() -> str:
    match = PROJECT_VERSION_PATTERN.search(CMAKE_PATH.read_text(encoding="utf-8"))
    if not match:
        raise RuntimeError("Unable to determine project version from CMakeLists.txt")
    return match.group(1)


def detect_commit(provided: str | None) -> str:
    if provided:
        return provided
    env_commit = os.environ.get("GITHUB_SHA")
    if env_commit:
        return env_commit
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True)
    except Exception as exc:  # pragma: no cover - best effort fallback
        raise RuntimeError("Unable to determine commit SHA") from exc
    return result.stdout.strip()


def build_downloads(repo: str, tag: str) -> Dict[str, Dict[str, Any]]:
    base = f"https://github.com/{repo}/releases/download/{tag}"
    return {
        "windows": {
            "url": f"{base}/eph-{tag}-windows-x64.zip",
            "arch": "x64",
            "format": "zip",
            "sha256": None,
        },
        "linux": {
            "url": f"{base}/eph-{tag}-linux-x64.tar.gz",
            "arch": "x64",
            "format": "tar.gz",
            "sha256": None,
        },
        "macos": {
            "url": f"{base}/eph-{tag}-macos-universal.tar.gz",
            "arch": "universal",
            "format": "tar.gz",
            "sha256": None,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="latest.json", help="Path to write the metadata file")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="GitHub repository (owner/name)")
    parser.add_argument("--commit", help="Override commit SHA included in the metadata")
    parser.add_argument("--channel", default="stable", help="Release channel label")
    parser.add_argument("--notes-url", help="Override the release notes URL")
    args = parser.parse_args()

    version = read_project_version()
    tag = f"v{version}"
    commit = detect_commit(args.commit)
    generated_at = _dt.datetime.now(tz=_dt.timezone.utc).isoformat().replace("+00:00", "Z")
    notes_url = args.notes_url or f"https://github.com/{args.repo}/releases/tag/{tag}"

    metadata: Dict[str, Any] = {
        "version": version,
        "tag": tag,
        "commit": commit,
        "channel": args.channel,
        "generated_at": generated_at,
        "notes_url": notes_url,
        "downloads": build_downloads(args.repo, tag),
    }

    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pragma: no cover - surfacing errors in CI
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
