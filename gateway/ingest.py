"""ingest.py — resolve an input spec into a pinned package tarball + provenance.

Inputs (exactly one):
  - CRAN package name (+ optional version)
  - GitHub URL ``https://github.com/owner/repo`` (+ optional ref)
  - local / uploaded ``.tar.gz`` package source path

Every successful ingest returns a provenance dict and stores the tarball under
``data/tarballs/{pkg}/{version}/`` so assessments are reproducible and the
offline fallback can find cached pins.

Offline fallback: if a network fetch fails but a cached tarball for the exact
package+version exists in the store, it is used and provenance is marked
``collection_mode=offline-fallback``. Metadata is never fabricated: if nothing
usable exists, ingest raises ``IngestError``.

stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

UA = "rval-gateway/0.1 (R package validation gateway, phase-2 prototype)"
TIMEOUT_S = 30
CRAN_CONTRIB = "https://cran.r-project.org/src/contrib"
CRAN_PACKAGES_INDEX = "https://cran.r-project.org/src/contrib/PACKAGES"
GITHUB_URL_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class IngestError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _fetch(url: str, timeout: int = TIMEOUT_S) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


@dataclass
class IngestResult:
    package: str
    version: str
    origin: str  # cran | github | upload
    tarball_path: str
    sha256: str
    source_url: str | None
    ref: str | None = None  # github ref, when applicable
    collection_mode: str = "network"  # network | offline-fallback | local
    description: dict = field(default_factory=dict)
    ingested_at: str = ""
    provenance_path: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def parse_description(text: str) -> dict:
    """Parse a Debian-style DESCRIPTION file (continuation lines supported)."""
    out: dict[str, str] = {}
    key = None
    for line in text.splitlines():
        if line.startswith((" ", "\t")) and key is not None:
            out[key] += " " + line.strip()
        elif ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            out[key] = val.strip()
    return out


def read_description_from_tarball(tarball: Path) -> dict:
    """Extract and parse the top-level DESCRIPTION file of a package tarball."""
    with tarfile.open(tarball, "r:gz") as tf:
        for member in tf.getmembers():
            parts = Path(member.name).parts
            if len(parts) == 2 and parts[1] == "DESCRIPTION":
                fh = tf.extractfile(member)
                if fh is None:
                    break
                return parse_description(fh.read().decode("utf-8", "replace"))
    raise IngestError(f"no top-level DESCRIPTION found in {tarball}")


def _store_dir(data_dir: Path, pkg: str, version: str) -> Path:
    d = data_dir / "tarballs" / pkg / version
    d.mkdir(parents=True, exist_ok=True)
    return d


def _finalize(tarball: Path, store: Path, pkg: str, version: str, origin: str,
              source_url: str | None, ref: str | None, mode: str,
              description: dict | None) -> IngestResult:
    dest = store / tarball.name
    if tarball.resolve() != dest.resolve():
        dest.write_bytes(tarball.read_bytes())
    desc = description if description is not None else read_description_from_tarball(dest)
    res = IngestResult(
        package=pkg,
        version=version,
        origin=origin,
        tarball_path=str(dest),
        sha256=_sha256(dest),
        source_url=source_url,
        ref=ref,
        collection_mode=mode,
        description=desc,
        ingested_at=_now(),
    )
    prov_path = store / "provenance.json"
    prov_path.write_text(json.dumps(res.to_dict(), indent=2), encoding="utf-8")
    res.provenance_path = str(prov_path)
    return res


def _cached(data_dir: Path, pkg: str, version: str):
    store = data_dir / "tarballs" / pkg / version
    if not store.is_dir():
        return None
    for f in sorted(store.glob("*.tar.gz")):
        return store, f
    return None


def _cran_current_version(pkg: str) -> str:
    """Resolve the current CRAN version from the PACKAGES index."""
    text = _fetch(CRAN_PACKAGES_INDEX).decode("utf-8", "replace")
    cur = None
    for line in text.splitlines():
        if line.startswith("Package: "):
            cur = line.split(":", 1)[1].strip()
        elif line.startswith("Version: ") and cur == pkg:
            return line.split(":", 1)[1].strip()
    raise IngestError(f"package {pkg!r} not found in CRAN PACKAGES index")


def ingest_cran(pkg: str, version: str | None = None,
                data_dir: Path = DEFAULT_DATA_DIR) -> IngestResult:
    """Ingest a CRAN package; without a version, resolve the current one."""
    resolved_version = version
    if resolved_version is None:
        try:
            resolved_version = _cran_current_version(pkg)
        except Exception:
            # try to fall back to any cached version, newest directory last
            base = data_dir / "tarballs" / pkg
            cached_versions = sorted(p.name for p in base.iterdir()
                                     if p.is_dir()) if base.is_dir() else []
            if not cached_versions:
                raise IngestError(
                    f"cannot resolve current CRAN version for {pkg!r} "
                    "(network failed, no cached tarball)")
            resolved_version = cached_versions[-1]
            hit = _cached(data_dir, pkg, resolved_version)
            store, tarball = hit
            return _finalize(tarball, store, pkg, resolved_version, "cran",
                             None, None, "offline-fallback", None)

    fname = f"{pkg}_{resolved_version}.tar.gz"
    url_main = f"{CRAN_CONTRIB}/{fname}"
    url_arch = f"{CRAN_CONTRIB}/Archive/{pkg}/{fname}"
    data = None
    used_url = None
    errors = []
    for url in (url_main, url_arch):
        try:
            data = _fetch(url)
            used_url = url
            break
        except Exception as e:  # noqa: BLE001 — degrade explicitly
            errors.append(f"{type(e).__name__}: {e}")
    if data is None:
        hit = _cached(data_dir, pkg, resolved_version)
        if hit is None:
            raise IngestError(
                f"CRAN fetch failed for {pkg} {resolved_version} "
                f"({'; '.join(errors)}); no cached tarball")
        store, tarball = hit
        return _finalize(tarball, store, pkg, resolved_version, "cran",
                         None, None, "offline-fallback", None)
    store = _store_dir(data_dir, pkg, resolved_version)
    tmp = store / fname
    tmp.write_bytes(data)
    return _finalize(tmp, store, pkg, resolved_version, "cran",
                     used_url, None, "network", None)


def ingest_github(url: str, ref: str | None = None,
                  data_dir: Path = DEFAULT_DATA_DIR) -> IngestResult:
    """Ingest from a GitHub repo URL. ref defaults to HEAD (codeload default)."""
    m = GITHUB_URL_RE.match(url.strip())
    if not m:
        raise IngestError(f"not a GitHub repo URL: {url!r}")
    owner, repo = m.group(1), m.group(2)
    dl_url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{ref or 'HEAD'}"
    try:
        data = _fetch(dl_url)
    except Exception as e:  # noqa: BLE001
        raise IngestError(
            f"GitHub tarball fetch failed for {owner}/{repo}@{ref or 'HEAD'} "
            f"({type(e).__name__}: {e})") from e
    tmp_dir = data_dir / "tarballs" / "_staging"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp = tmp_dir / f"{repo}-{ref or 'HEAD'}.tar.gz"
    tmp.write_bytes(data)
    desc = read_description_from_tarball(tmp)
    pkg = desc.get("Package")
    version = desc.get("Version")
    if not pkg or not version:
        raise IngestError(
            f"DESCRIPTION in {owner}/{repo} lacks Package/Version fields")
    store = _store_dir(data_dir, pkg, version)
    dest = store / tmp.name
    tmp.replace(dest)
    return _finalize(dest, store, pkg, version, "github", dl_url,
                     ref or "HEAD", "network", desc)


def ingest_upload(path: str | Path,
                  data_dir: Path = DEFAULT_DATA_DIR) -> IngestResult:
    """Ingest a local/uploaded package source tarball."""
    src = Path(path)
    if not src.is_file():
        raise IngestError(f"uploaded tarball not found: {src}")
    desc = read_description_from_tarball(src)
    pkg = desc.get("Package")
    version = desc.get("Version")
    if not pkg or not version:
        raise IngestError(f"DESCRIPTION in {src} lacks Package/Version fields")
    store = _store_dir(data_dir, pkg, version)
    dest = store / src.name
    if src.resolve() != dest.resolve():
        dest.write_bytes(src.read_bytes())
    return _finalize(dest, store, pkg, version, "upload", None, None,
                     "local", desc)


def ingest(spec: dict, data_dir: Path = DEFAULT_DATA_DIR) -> IngestResult:
    """Dispatch on an input spec dict.

    spec keys (exactly one input selector):
      package (str), version (str|None)     — CRAN
      github_url (str), ref (str|None)      — GitHub
      upload_path (str)                     — local/uploaded tarball
    """
    if spec.get("package"):
        return ingest_cran(spec["package"], spec.get("version"), data_dir)
    if spec.get("github_url"):
        return ingest_github(spec["github_url"], spec.get("ref"), data_dir)
    if spec.get("upload_path"):
        return ingest_upload(spec["upload_path"], data_dir)
    raise IngestError("spec must contain one of: package, github_url, upload_path")
