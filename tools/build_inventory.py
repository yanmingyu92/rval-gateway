#!/usr/bin/env python
"""build_inventory.py — generate config/inventory.json (Phase A).

Merges three package-name sources into one inventory:

  1. config/platform_baseline.json           (flat name list, source "baseline")
  2. the platform image Dockerfile            (install.packages(...) layers,
                                               source "dockerfile")
  3. ../platform/**/*.R                       (library(x) / require(x) scan,
                                               source "code")

Versions are resolved from a Posit Package Manager (P3M) snapshot PACKAGES
index (noble Linux binaries, default snapshot 2026-08-01 — the same snapshot
the platform image pins). Packages absent from the snapshot index get
version=null and a stderr warning; nothing is fabricated.

P3M gotcha (build failure 2026-09-03): the binary index is served only when
the request User-Agent matches R's own HTTPUserAgent format
("R/x.y.z R (...)"); any other UA silently gets the *source* index instead.
This script always sends the R-style UA.

Usage:
  python tools/build_inventory.py [--snapshot YYYY-MM-DD]
                                  [--packages-file PATH]   # offline / tests
                                  [--out PATH]
                                  [--baseline PATH] [--dockerfile PATH]
                                  [--platform-dir PATH]

stdlib only. Run from anywhere; paths default relative to the repo root.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

DEFAULT_SNAPSHOT = "2026-08-01"  # matches the platform image build arg
DEFAULT_BASELINE = REPO / "config" / "platform_baseline.json"
DEFAULT_DOCKERFILE = REPO.parent / "platform" / "docker" / "r-platform" / "Dockerfile"
DEFAULT_PLATFORM_DIR = REPO.parent / "platform"
DEFAULT_OUT = REPO / "config" / "inventory.json"

PACKAGES_URL = ("https://packagemanager.posit.co/cran/__linux__/noble/"
                "{snapshot}/src/contrib/PACKAGES.gz")
# R's own HTTPUserAgent format — required, or P3M serves the source index.
R_LINUX_UA = "R/4.5.3 R (4.5.3 x86_64-pc-linux-gnu x86_64 linux-gnu)"
TIMEOUT_S = 120

# Base/recommended packages ship with R — excluded from the code scan
# (they are never validation inventory items).
R_BASE_PACKAGES = {
    "base", "compiler", "datasets", "graphics", "grDevices", "grid",
    "methods", "parallel", "splines", "stats", "stats4", "tcltk", "tools",
    "utils",
}

SOURCE_ORDER = ("baseline", "dockerfile", "code")

# library(x), library("x"), require('x') — package name is word chars + dots.
_LIB_RE = re.compile(r"""\b(?:library|require)\s*\(\s*['"]?([A-Za-z0-9.]+)""")
_STR_RE = re.compile(r"""['"]([A-Za-z0-9.]+)['"]""")


def _strip_r_comment(line: str) -> str:
    """Drop the #-comment tail of an R line, honouring '...' / "..." strings
    (otherwise roxygen/prose like `# see library(foo)` yields phantom names)."""
    out = []
    quote = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
            out.append(c)
        elif c == "#":
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_baseline(path: Path) -> set[str]:
    """Source 1: the hand-maintained platform baseline (names only)."""
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    return {str(x) for x in d.get("packages", [])}


def _balanced_call(text: str, start: int) -> str:
    """Return the parenthesised call body starting at the '(' at text[start]."""
    depth = 0
    for i in range(start, len(text)):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
    return text[start + 1:]


def parse_dockerfile(path: Path) -> set[str]:
    """Source 2: package names out of install.packages(...) layers."""
    text = Path(path).read_text(encoding="utf-8")
    names = set()
    for m in re.finditer(r"install\.packages\s*\(", text):
        body = _balanced_call(text, m.end() - 1)
        names.update(_STR_RE.findall(body))
    return names - R_BASE_PACKAGES


def scan_r_code(root: Path) -> set[str]:
    """Source 3: recursive library()/require() scan of *.R under root
    (dotfiles included — launcher scripts are dotfiles)."""
    names = set()
    root = Path(root)
    if not root.is_dir():
        return names
    for f in sorted(root.rglob("*.R")):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            names.update(_LIB_RE.findall(_strip_r_comment(line)))
    return {n for n in names - R_BASE_PACKAGES if not n.startswith(".")}


def parse_packages_index(text: str) -> dict[str, str]:
    """Parse a Debian-control-format PACKAGES index → {name: version}."""
    versions = {}
    name = version = None
    for line in text.splitlines() + [""]:
        if line.startswith("Package:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
        elif line == "":
            if name:
                versions[name] = version
            name = version = None
    return versions


def fetch_packages_index(snapshot: str) -> str:
    """Fetch + gunzip the P3M snapshot PACKAGES index (R-style UA required)."""
    url = PACKAGES_URL.format(snapshot=snapshot)
    req = urllib.request.Request(url, headers={"User-Agent": R_LINUX_UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
        raw = resp.read()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return raw.decode("utf-8", errors="replace")


def build_inventory(baseline_path: Path, dockerfile_path: Path,
                    platform_dir: Path, index: dict[str, str],
                    snapshot: str) -> tuple[dict, list[str]]:
    """Merge sources, resolve versions. Returns (inventory, unresolved)."""
    by_name: dict[str, set[str]] = {}
    counts = {}
    for source, names in (("baseline", load_baseline(baseline_path)),
                          ("dockerfile", parse_dockerfile(dockerfile_path)),
                          ("code", scan_r_code(platform_dir))):
        counts[source] = len(names)
        for n in names:
            by_name.setdefault(n, set()).add(source)

    packages = []
    unresolved = []
    for name in sorted(by_name, key=str.lower):
        version = index.get(name)
        if version is None:
            unresolved.append(name)
        packages.append({
            "name": name,
            "version": version,
            "sources": [s for s in SOURCE_ORDER if s in by_name[name]],
        })

    inventory = {
        "schema": "rval-gateway inventory v1",
        "snapshot": snapshot,
        "generated_at": _now(),
        "source_counts": counts,
        "packages": packages,
    }
    return inventory, unresolved


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="build the package inventory")
    ap.add_argument("--snapshot", default=DEFAULT_SNAPSHOT,
                    help=f"P3M snapshot date (default {DEFAULT_SNAPSHOT})")
    ap.add_argument("--packages-file", default=None,
                    help="local PACKAGES index file (plain or .gz); skips the "
                         "network fetch (tests / offline)")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    ap.add_argument("--dockerfile", default=str(DEFAULT_DOCKERFILE))
    ap.add_argument("--platform-dir", default=str(DEFAULT_PLATFORM_DIR))
    args = ap.parse_args(argv)

    if args.packages_file:
        raw = Path(args.packages_file).read_bytes()
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        index_text = raw.decode("utf-8", errors="replace")
    else:
        print(f"[inventory] fetching P3M PACKAGES index, snapshot "
              f"{args.snapshot} …", file=sys.stderr)
        index_text = fetch_packages_index(args.snapshot)
    index = parse_packages_index(index_text)
    print(f"[inventory] snapshot index: {len(index)} packages", file=sys.stderr)

    inventory, unresolved = build_inventory(
        Path(args.baseline), Path(args.dockerfile), Path(args.platform_dir),
        index, args.snapshot)

    for name in unresolved:
        print(f"[inventory] WARNING: {name} not in snapshot index "
              f"-> version=null", file=sys.stderr)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")

    counts = inventory["source_counts"]
    print(f"[inventory] sources: baseline={counts['baseline']} "
          f"dockerfile={counts['dockerfile']} code={counts['code']}")
    print(f"[inventory] {len(inventory['packages'])} packages "
          f"({len(unresolved)} unresolved: "
          f"{', '.join(unresolved) if unresolved else 'none'}) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
