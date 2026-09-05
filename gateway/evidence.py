"""evidence.py — deterministic evidence collection with evidence IDs.

Adapted from the E2 prototype (`s1_collect.py`): every fact collected becomes
an evidence entry with an ``evidence_id`` (EV-001...), metric name, value,
source URL, and collection timestamp. Network sources degrade silently per
source; the overall ``collection_mode`` records how much came from the
network. Facts from the {riskmetric} run are merged into the same register
(source marked as the riskmetric run + versions).

Sources attempted:
  1. https://crandb.r-pkg.org/{pkg}                          (CRAN metadata)
  2. https://cranlogs.r-pkg.org/downloads/total/last-month/{pkg}
  3. https://api.github.com/repos/{owner}/{repo}             (when origin is
     github, or when CRAN DESCRIPTION links a GitHub repo)
  4. the local tarball's DESCRIPTION + sha256 (always available)
  5. the riskmetric score JSON (always, when scoring succeeded)

No bundled/mined vendor facts here (E2-specific); nothing is fabricated.

stdlib only.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone

UA = "rval-gateway/0.1 (R package validation gateway, phase-2 prototype)"
TIMEOUT_S = 20

GITHUB_REPO_URL_RE = re.compile(
    r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fetch_json(url: str):
    headers = {"User-Agent": UA, "Accept": "application/json"}
    # optional GitHub API token via env only (never stored, never logged)
    token = os.environ.get("GITHUB_TOKEN")
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
        return json.loads(resp.read().decode("utf-8"))


class EvidenceRegister:
    def __init__(self):
        self.entries: list[dict] = []

    def add(self, metric, value, source, mode, unit=None, note=None):
        if value is None or value == "" or value == {}:
            return None  # a slot without a value is no evidence
        entry = {
            "evidence_id": f"EV-{len(self.entries) + 1:03d}",
            "metric": metric,
            "value": value,
            "source": source,
            "mode": mode,  # "network" | "local" | "riskmetric"
            "collected_at": _now(),
        }
        if unit:
            entry["unit"] = unit
        if note:
            entry["note"] = note
        self.entries.append(entry)
        return entry


class Collector:
    def __init__(self, pkg: str, ingest_result: dict):
        self.pkg = pkg
        self.ingest = ingest_result
        self.reg = EvidenceRegister()
        self.net_ok = 0
        self.net_fail: list[tuple[str, str, str]] = []

    # ---------- local collectors (always available) ----------

    def local_description(self):
        from pathlib import Path
        desc = self.ingest.get("description") or {}
        # basename only: absolute workstation paths must never appear in
        # evidence (they can contain internal identifiers)
        tb_name = Path(self.ingest.get("tarball_path") or "?").name
        src = f"local tarball DESCRIPTION ({tb_name})"
        for field, metric in (("Package", "description.package"),
                              ("Version", "description.version"),
                              ("Title", "description.title"),
                              ("License", "description.license"),
                              ("Maintainer", "description.maintainer"),
                              ("URL", "description.url"),
                              ("BugReports", "description.bug_reports")):
            self.reg.add(metric, desc.get(field), src, "local")
        self.reg.add("tarball.sha256", self.ingest.get("sha256"),
                     f"local sha256 of {tb_name}",
                     "local", unit="sha256 hex")
        self.reg.add("ingest.origin", self.ingest.get("origin"),
                     "gateway ingest provenance", "local")
        if self.ingest.get("source_url"):
            self.reg.add("ingest.source_url", self.ingest["source_url"],
                         "gateway ingest provenance", "local")

    # ---------- network collectors ----------

    def crandb(self):
        url = f"https://crandb.r-pkg.org/{self.pkg}"
        try:
            d = _fetch_json(url)
        except Exception as e:  # noqa: BLE001 — degrade explicitly
            self.net_fail.append(("crandb", url, f"{type(e).__name__}: {e}"))
            return None
        self.net_ok += 1
        self.reg.add("cran.version", d.get("Version"), url, "network")
        self.reg.add("cran.title", d.get("Title"), url, "network")
        self.reg.add("cran.publication_date", d.get("Date"), url, "network",
                     note="Date field of the current CRAN release.")
        self.reg.add("cran.maintainer", d.get("Maintainer"), url, "network")
        self.reg.add("cran.license", d.get("License"), url, "network")
        if d.get("URL"):
            self.reg.add("cran.url", d.get("URL"), url, "network")
        deps = d.get("Imports")
        if isinstance(deps, dict):
            self.reg.add("cran.imports_count",
                         len([k for k in deps if k.upper() != "R"]),
                         url, "network", unit="packages")
        return d

    def cranlogs(self):
        url = f"https://cranlogs.r-pkg.org/downloads/total/last-month/{self.pkg}"
        try:
            d = _fetch_json(url)
        except Exception as e:  # noqa: BLE001
            self.net_fail.append(("cranlogs", url, f"{type(e).__name__}: {e}"))
            return None
        self.net_ok += 1
        if isinstance(d, list) and d:
            row = d[0]
            self.reg.add(
                "downloads.last_month_total", row.get("downloads"), url,
                "network", unit="downloads",
                note=f"window {row.get('start')}..{row.get('end')} "
                     "(posit CRAN mirror logs)")
        return d

    def _github_repo_slug(self) -> str | None:
        """owner/repo when origin=github, else parsed from DESCRIPTION URLs."""
        if self.ingest.get("origin") == "github" and self.ingest.get("source_url"):
            m = re.search(r"codeload\.github\.com/([^/]+)/([^/]+)/",
                          self.ingest["source_url"])
            if m:
                return f"{m.group(1)}/{m.group(2)}"
        desc = self.ingest.get("description") or {}
        for field in ("URL", "BugReports"):
            m = GITHUB_REPO_URL_RE.search(desc.get(field) or "")
            if m:
                return f"{m.group(1)}/{m.group(2)}"
        return None

    def github(self):
        slug = self._github_repo_slug()
        if not slug:
            return None
        url = f"https://api.github.com/repos/{slug}"
        try:
            d = _fetch_json(url)
        except Exception as e:  # noqa: BLE001
            self.net_fail.append(("github", url, f"{type(e).__name__}: {e}"))
            return None
        self.net_ok += 1
        self.reg.add("github.repo", slug, url, "network")
        self.reg.add("github.stars", d.get("stargazers_count"), url,
                     "network", unit="stars")
        self.reg.add("github.forks", d.get("forks_count"), url,
                     "network", unit="forks")
        self.reg.add("github.open_issues", d.get("open_issues_count"), url,
                     "network", unit="issues")
        self.reg.add("github.last_push", d.get("pushed_at"), url, "network",
                     note="last push to default branch (UTC)")
        return d

    # ---------- riskmetric merge ----------

    def merge_riskmetric(self, score_json: dict):
        src = (f"riskmetric {score_json.get('riskmetric_version')} run via "
               f"gateway r_adapter ({score_json.get('r_version')})")
        self.reg.add("riskmetric.overall_score", score_json.get("overall_score"),
                     src, "riskmetric",
                     note="summarize_scores weighted mean, 0=low risk 1=high")
        for metric, val in sorted((score_json.get("metric_scores") or {}).items()):
            self.reg.add(f"riskmetric.score.{metric}", val, src, "riskmetric",
                         note="0=low risk 1=high; null = not measurable")
        for metric, raw in sorted((score_json.get("metric_raw") or {}).items()):
            self.reg.add(f"riskmetric.raw.{metric}", raw, src, "riskmetric")
        self.reg.add("riskmetric.excluded_metrics",
                     ", ".join(score_json.get("excluded_metrics") or []),
                     src, "riskmetric",
                     note="code-executing metrics disabled by policy; "
                          "assessed package code was not executed")


def collect(pkg: str, ingest_result: dict, score_json: dict | None = None) -> dict:
    """Collect all evidence for one assessment into a single register."""
    c = Collector(pkg, ingest_result)
    c.local_description()
    if ingest_result.get("origin") in ("cran", "upload"):
        c.crandb()
        c.cranlogs()
    c.github()
    if score_json is not None:
        c.merge_riskmetric(score_json)
    mode = "network" if c.net_ok > 0 else (
        "offline-fallback" if ingest_result.get("collection_mode")
        == "offline-fallback" else "local-only")
    return {
        "package": pkg,
        "version": ingest_result.get("version"),
        "collection_mode": mode,
        "collected_at": _now(),
        "network_sources_ok": c.net_ok,
        "network_sources_failed": [
            {"collector": n, "url": u, "error": err}
            for n, u, err in c.net_fail
        ],
        "entries": c.reg.entries,
    }
