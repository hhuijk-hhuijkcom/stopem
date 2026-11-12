#!/usr/bin/env python3
"""Fetch Steam client binaries for pattern migration.

Polls CHANNEL_MANIFESTS, downloads steamclient64.dll + SteamUI.dll per
new channel build into <out>/<channel>/. Exit 0: new SHAs (publish);
exit 2: all SHAs already published (skip); exit 1: failure (atomic:
nothing is written).

Usage:
    python3 tools/fetch_client.py --out bins/ --published-shas sha1 sha2
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import NamedTuple

CHANNEL_MANIFESTS = {
    "stable": "https://client-update.fastly.steamstatic.com/steam_client_win64",
    "beta": "https://client-update.fastly.steamstatic.com/steam_client_publicbeta_win64",
}
BASE_URL = "https://client-update.fastly.steamstatic.com/"
TARGET_DLLS = ("steamclient64.dll", "SteamUI.dll")

_VERSION_RE = re.compile(r'"version"\s+"(\d+)"')
# Package blocks are indented; the root platform block ("win64"\n{) is not.
_BLOCK_RE = re.compile(r'\r?\n[ \t]+"([a-z0-9_]+)"[ \t]*\r?\n[ \t]*\{([^}]*)\}')
_FILE_RE = re.compile(r'"file"\s+"([^"]+)"')


class Package(NamedTuple):
    name: str
    filename: str


def needs_publish(new_shas: list[str], published_shas: list[str]) -> bool:
    return not set(new_shas) <= set(published_shas)


def resolve_known(
    version: str, versions: dict[str, dict[str, str]], published_shas: list[str]
) -> dict[str, str] | None:
    known = versions.get(version)
    if known is None:
        return None
    shas = {k: v for k, v in known.items() if k != "channel"}
    if set(shas.values()) <= set(published_shas):
        return shas
    return None


def extract_targets(data: bytes, names: tuple[str, ...]) -> dict[str, bytes] | None:
    found: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        entries: dict[str, str] = {}
        for info in z.infolist():
            entries.setdefault(info.filename.rsplit("/", 1)[-1], info.filename)
        for name in names:
            if name not in entries:
                return None
            with z.open(entries[name]) as f:
                found[name] = f.read()
    return found


def select_packages(packages: list[Package]) -> list[str]:
    """bins_win64 first, then other bins_* packages, then the rest."""
    ordered = sorted(
        packages,
        key=lambda p: (0 if p.name == "bins_win64" else 1 if p.name.startswith("bins_") else 2),
    )
    return list(dict.fromkeys(p.filename for p in ordered))


def parse_manifest(text: str) -> tuple[str, list[Package]]:
    """Parse a client manifest (VDF) into (version, packages)."""
    version = _VERSION_RE.search(text)
    if version is None:
        raise ValueError("manifest has no version")
    packages = []
    for block in _BLOCK_RE.finditer(text):
        name, body = block.group(1), block.group(2)
        if name in ("version", "ostype"):
            continue
        found = _FILE_RE.search(body)
        if found is not None:
            packages.append(Package(name, found.group(1)))
    return version.group(1), packages


def fetch_url(url: str) -> bytes:
    """Network adapter (untested seam boundary)."""
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--channels", nargs="*", default=sorted(CHANNEL_MANIFESTS))
    ap.add_argument("--base-url", default=BASE_URL)
    ap.add_argument("--published-shas", nargs="*", default=[])
    ap.add_argument("--versions-file", default=None)
    args = ap.parse_args()

    unknown = [c for c in args.channels if c not in CHANNEL_MANIFESTS]
    if unknown:
        print(f"unknown channels: {' '.join(unknown)}")
        return 1

    versions: dict[str, dict[str, str]] = {}
    if args.versions_file is not None and Path(args.versions_file).exists():
        versions = json.loads(Path(args.versions_file).read_text())

    fetched: list[tuple[str, str, dict[str, str], dict[str, bytes]]] = []
    try:
        for channel in args.channels:
            version, packages = parse_manifest(
                fetch_url(CHANNEL_MANIFESTS[channel]).decode("utf-8")
            )
            print(f"client version ({channel}): {version}")

            if resolve_known(version, versions, args.published_shas) is not None:
                print(f"version already published, skipping download ({channel})")
                continue

            dlls: dict[str, bytes] | None = None
            for filename in select_packages(packages):
                print(f"trying {filename} ({channel})")
                found = extract_targets(fetch_url(args.base_url + filename), TARGET_DLLS)
                if found is not None:
                    dlls = found
                    break
            if dlls is None:
                print("no package contained all of " + ", ".join(TARGET_DLLS) + f" ({channel})")
                return 1
            shas = {name: hashlib.sha256(data).hexdigest() for name, data in dlls.items()}
            fetched.append((channel, version, shas, dlls))
    except Exception as e:
        print(f"failed to fetch manifest or package: {e}")
        return 1

    for channel, version, shas, dlls in fetched:
        out = Path(args.out) / channel
        out.mkdir(parents=True, exist_ok=True)
        for name, data in dlls.items():
            (out / name).write_bytes(data)
        (out / "versions.json").write_text(
            json.dumps({"version": version, "channel": channel, **shas}, indent=2) + "\n"
        )
        if args.versions_file is not None:
            versions[version] = {"channel": channel, **shas}
    if args.versions_file is not None and fetched:
        versions_path = Path(args.versions_file)
        versions_path.parent.mkdir(parents=True, exist_ok=True)
        versions_path.write_text(json.dumps(versions, indent=2) + "\n")

    if not fetched:
        print("all versions already published")
        return 2
    new_shas = [s for _, _, shas, _ in fetched for s in shas.values()]
    if needs_publish(new_shas, args.published_shas):
        print("new SHAs: " + " ".join(new_shas))
        return 0
    print("all SHAs already published")
    return 2


if __name__ == "__main__":
    sys.exit(main())
