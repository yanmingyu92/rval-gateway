"""dashboard.py — read-only data assembly + server-rendered HTML for the
package-validation dashboard (Phase B).

Everything here is a fast read-only path: it reads the audit log
(``data/audit/assessments.jsonl``), the run outputs under ``data/runs/``,
the repository manifest (``data/repo/manifest.json``) and the generated
package inventory (``config/inventory.json``). No subprocesses, no network.

Staleness and latest-assessment helpers are reused from ``run_inventory``
(the repo-root CLI module) — never duplicated. Old audit records without an
``actor`` field render as "—".

stdlib only.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from . import audit as audit_mod
from . import decision as decision_mod
from . import repo as repo_mod
from . import webui

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INVENTORY = REPO_ROOT / "config" / "inventory.json"

DECISIONS = ("GO", "GO-WITH-CONDITIONS", "NO-GO")
NO_ACTOR = "—"


def _run_inventory():
    """Import the repo-root CLI module lazily (it lives outside the
    package; the repo root is on sys.path whenever gateway is importable)."""
    import run_inventory
    return run_inventory


def read_audit_records(data_dir: Path) -> list[dict]:
    """All records of the audit log, in chain order; broken lines skipped."""
    path = Path(data_dir) / "audit" / "assessments.jsonl"
    records = []
    if not path.is_file():
        return records
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def chain_status(data_dir: Path) -> dict:
    """verify_chain() result of the audit log: {ok, records, ...}."""
    log = audit_mod.AuditLog(Path(data_dir) / "audit" / "assessments.jsonl")
    return log.verify_chain()


def assessments_tail(data_dir: Path, limit: int = 100) -> dict:
    """Tail of the audit log (all record types) + chain verification —
    the payload of GET /api/assessments."""
    limit = max(1, min(int(limit), 1000))
    records = read_audit_records(data_dir)
    chain = chain_status(data_dir)
    return {"schema": "rval-gateway assessments v1",
            "total": len(records),
            "limit": limit,
            "chain_ok": bool(chain["ok"]),
            "records": records[-limit:]}


def find_run_id(data_dir: Path, package: str, version: str | None) -> str | None:
    """Newest run dir name for package+version (run ids end with a UTC
    timestamp, so lexicographic max is the newest)."""
    if not version:
        return None
    runs = Path(data_dir) / "runs"
    if not runs.is_dir():
        return None
    prefix = f"{package}_{version}_"
    matches = sorted(d.name for d in runs.iterdir()
                     if d.is_dir() and d.name.startswith(prefix))
    return matches[-1] if matches else None


def _score_metrics(data_dir: Path, run_id: str | None) -> dict:
    """Per-metric scores from the run's score/score.json (empty when the
    run was un-scored or the file is absent)."""
    if not run_id:
        return {}
    p = Path(data_dir) / "runs" / run_id / "score" / "score.json"
    try:
        score = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return score.get("metric_scores") or {}


def _timeline(records: list[dict], package: str) -> list[dict]:
    """Approval timeline for one package, in chain order: assessment ->
    esign -> publish events with actor, timestamp and record-hash prefix.
    Thin wrapper over audit.package_timeline (shared with the report)."""
    return audit_mod.package_timeline(records, package)


def _load_inventory(inventory_path: Path) -> dict:
    try:
        return json.loads(Path(inventory_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema": "rval-gateway inventory v1", "snapshot": None,
                "packages": []}


def _join_rows(data_dir: Path, inventory: dict, config_sha256: str,
               details: bool) -> list[dict]:
    """Inventory x newest-assessment join. details=True additionally reads
    per-metric scores and builds the approval timeline (dashboard page);
    details=False stays file-light (JSON API)."""
    ri = _run_inventory()
    data_dir = Path(data_dir)
    latest = ri.latest_assessments(data_dir)
    manifest = repo_mod.load_manifest(data_dir)
    published = {a["package"]: a for a in manifest.get("artifacts", [])}
    records = read_audit_records(data_dir) if details else None
    rows = []
    for entry in inventory.get("packages", []):
        name = entry.get("name")
        rec = latest.get(name)
        stale, reason = ri.staleness(entry, rec, config_sha256)
        pub = published.get(name)
        pub_match = bool(pub and rec and pub.get("version")
                         == rec.get("version"))
        row = {
            "name": name,
            "version": entry.get("version"),
            "sources": entry.get("sources", []),
            "assessed": rec is not None,
            "tier": rec.get("tier") if rec else None,
            "overall_score": rec.get("overall_score") if rec else None,
            "decision": rec.get("decision") if rec else None,
            "actor": (rec.get("actor") or NO_ACTOR) if rec else NO_ACTOR,
            "assessed_at": rec.get("assessed_at") if rec else None,
            "stale": stale,
            "stale_reason": reason,
            "published": pub_match,
            "published_version": pub.get("version") if pub else None,
        }
        if details and rec:
            run_id = find_run_id(data_dir, name, rec.get("version"))
            row["run_id"] = run_id
            row["has_pdf"] = bool(
                run_id and (data_dir / "runs" / run_id / "report"
                            / "report.pdf").is_file())
            row["metrics"] = _score_metrics(data_dir, run_id)
            row["fired_rules"] = rec.get("fired_rules") or []
            row["conditions"] = rec.get("conditions") or []
            row["timeline"] = _timeline(records, name)
        rows.append(row)
    return rows


def inventory_join(data_dir: Path, inventory_path: Path = DEFAULT_INVENTORY,
                   config_sha256: str | None = None) -> dict:
    """Inventory x newest-assessment join — the payload of
    GET /api/inventory."""
    if config_sha256 is None:
        config_sha256 = decision_mod.RuleSet.load().sha256
    inventory = _load_inventory(inventory_path)
    rows = _join_rows(data_dir, inventory, config_sha256, details=False)
    return {"schema": "rval-gateway inventory status v1",
            "snapshot": inventory.get("snapshot"),
            "config_sha256": config_sha256,
            "totals": _totals(rows),
            "packages": rows}


def _totals(rows: list[dict]) -> dict:
    counts = {d: 0 for d in DECISIONS}
    for r in rows:
        if r.get("decision") in counts:
            counts[r["decision"]] += 1
    return {"packages": len(rows),
            "assessed": sum(1 for r in rows if r["assessed"]),
            "stale": sum(1 for r in rows if r["stale"]),
            "published": sum(1 for r in rows if r["published"]),
            **counts}


def collect(data_dir: Path, inventory_path: Path = DEFAULT_INVENTORY,
            config_sha256: str | None = None) -> dict:
    """Full dashboard dataset: stats, detailed rows, dependency gaps and
    the audit-chain verification result."""
    if config_sha256 is None:
        config_sha256 = decision_mod.RuleSet.load().sha256
    inventory = _load_inventory(inventory_path)
    rows = _join_rows(data_dir, inventory, config_sha256, details=True)
    manifest = repo_mod.load_manifest(data_dir)
    gaps = [{"package": a["package"], "version": a["version"],
             "missing": a.get("dependency_gaps", {}).get("missing", [])}
            for a in manifest.get("artifacts", [])
            if a.get("dependency_gaps", {}).get("missing")]
    return {"snapshot": inventory.get("snapshot"),
            "chain": chain_status(data_dir),
            "totals": _totals(rows),
            "rows": rows,
            "dependency_gaps": gaps}


# ---------------- HTML rendering ----------------

_DASH_JS = """
const q = document.getElementById('q');
const decFilter = document.getElementById('dec-filter');
const tbody = document.querySelector('#pkg-table tbody');
function pkgRows(){ return [...tbody.querySelectorAll('tr.pkg')]; }
function applyFilters(){
  const needle = q.value.toLowerCase();
  const d = decFilter.value;
  pkgRows().forEach(r => {
    const show = r.dataset.search.includes(needle) && (!d || r.dataset.decision === d);
    r.style.display = show ? '' : 'none';
    const det = document.getElementById(r.id + '-detail');
    if (det && !show) det.style.display = 'none';
  });
}
q.addEventListener('input', applyFilters);
decFilter.addEventListener('change', applyFilters);
function toggleRow(btn){
  const det = document.getElementById(btn.dataset.target);
  const open = (det.style.display === 'none' || det.style.display === '');
  det.style.display = open ? 'table-row' : 'none';
  btn.closest('tr').classList.toggle('expanded', open);
}
tbody.querySelectorAll('.gw-expander').forEach(b =>
  b.addEventListener('click', () => toggleRow(b)));
let sortState = {};
document.querySelectorAll('#pkg-table th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.cellIndex, numeric = th.dataset.sort === 'num';
    sortState[col] = !sortState[col];
    const asc = sortState[col];
    const pairs = pkgRows().map(r => [r, document.getElementById(r.id + '-detail')]);
    pairs.sort((a, b) => {
      const ca = a[0].children[col], cb = b[0].children[col];
      const av = ca.dataset.v !== undefined ? ca.dataset.v : ca.textContent.trim();
      const bv = cb.dataset.v !== undefined ? cb.dataset.v : cb.textContent.trim();
      let cmp = numeric ? (parseFloat(av) || -1) - (parseFloat(bv) || -1)
                        : String(av).localeCompare(String(bv));
      return asc ? cmp : -cmp;
    });
    pairs.forEach(p => { tbody.appendChild(p[0]); if (p[1]) tbody.appendChild(p[1]); });
  });
});
// shareable anchor: /dashboard#pkg=<name> expands + scrolls to the row
(function(){
  const m = location.hash.match(/[#&]pkg=([A-Za-z0-9_.-]+)/);
  if (!m) return;
  const row = document.getElementById('pkg-' + m[1]);
  if (!row) return;
  const btn = row.querySelector('.gw-expander');
  if (btn) toggleRow(btn);
  row.scrollIntoView({behavior: 'smooth', block: 'center'});
})();
"""


def _badge(decision: str | None) -> str:
    return webui.decision_badge(decision)


def _score_cell(score) -> str:
    return f"{score:.4f}" if isinstance(score, (int, float)) else NO_ACTOR


def _detail_html(row: dict, url) -> str:
    """Expanded-row content: per-metric scores, fired rules/conditions and
    the approval timeline from the audit chain."""
    parts = []
    metrics = row.get("metrics") or {}
    if metrics:
        mrows = "".join(
            f"<tr><td>{html.escape(str(k))}</td>"
            f"<td>{_score_cell(v)}</td></tr>"
            for k, v in sorted(metrics.items()))
        parts.append(f"<b>Per-metric scores</b><table class='gw-table "
                     f"metrics'><thead><tr><th>metric</th><th>score</th>"
                     f"</tr></thead><tbody>{mrows}</tbody></table>")
    else:
        parts.append("<p><em>No per-metric scores on record for this "
                     "assessment.</em></p>")
    fired = row.get("fired_rules") or []
    fired_html = ", ".join(f"<code>{html.escape(str(r))}</code>"
                           for r in fired) or "(none)"
    parts.append(f"<p><b>Fired rules:</b> {fired_html}</p>")
    conds = row.get("conditions") or []
    if conds:
        items = "".join(f"<li>{html.escape(str(c))}</li>" for c in conds)
        parts.append(f"<p><b>Conditions:</b></p><ul>{items}</ul>")
    timeline = row.get("timeline") or []
    if timeline:
        items = "".join(
            f"<li><b>{html.escape(e['event'])}</b> — "
            f"{html.escape(e['actor'])} · "
            f"{html.escape(str(e['timestamp'] or NO_ACTOR))} · "
            f"{html.escape(e['detail'])} · "
            f"<code>{html.escape(e['hash'])}…</code></li>"
            for e in timeline)
        parts.append(f"<p><b>Approval timeline</b> (from the audit chain):"
                     f"</p><ol class='gw-timeline'>{items}</ol>")
    else:
        parts.append("<p><em>No audit events for this package yet.</em></p>")
    return "".join(parts)


def render_html(data: dict, url, user: str | None = None) -> bytes:
    """Render the full dashboard page. ``url`` prefixes generated links with
    the configured base path (server.url)."""
    totals = data["totals"]
    chain = data["chain"]
    chain_ok = bool(chain["ok"])

    def card(label: str, value, cls: str = "") -> str:
        c = f" {cls}" if cls else ""
        return (f"<div class='gw-stat{c}'><div class='num'>{value}</div>"
                f"<div class='lbl'>{html.escape(label)}</div></div>")

    chain_card = card("audit chain", "✓ intact" if chain_ok else "✗ BROKEN",
                      "good" if chain_ok else "bad")
    stale_cls = "warn" if totals["stale"] else ""
    cards = "".join([
        card("inventory", totals["packages"]),
        card("assessed", totals["assessed"]),
        card("GO", totals["GO"], "good"),
        card("go-with-conditions", totals["GO-WITH-CONDITIONS"]),
        card("no-go", totals["NO-GO"], "bad" if totals["NO-GO"] else ""),
        card("stale", totals["stale"], stale_cls),
        chain_card,
    ])

    # staleness banner (Phase D): any stale inventory package -> prominent
    # banner with a per-reason breakdown; nothing when everything is current
    stale_rows = [r for r in data["rows"] if r.get("stale")]
    if stale_rows:
        reasons: dict[str, int] = {}
        for r in stale_rows:
            k = r.get("stale_reason") or "unknown"
            reasons[k] = reasons.get(k, 0) + 1
        breakdown = " · ".join(f"{html.escape(k)}: {n}"
                               for k, n in sorted(reasons.items()))
        n_stale = len(stale_rows)
        banner = (f"<div class='gw-banner' id='stale-banner'><b>{n_stale} "
                  f"package{'s' if n_stale != 1 else ''} "
                  f"{'are' if n_stale != 1 else 'is'} stale</b> "
                  "(version/config/snapshot drift) — rerun inventory "
                  "assessment (<code>python run_inventory.py</code>). "
                  f"Breakdown: {breakdown}.</div>")
    else:
        banner = ""

    dec_options = "".join(
        f"<option value='{d}'>{d}</option>" for d in DECISIONS)
    toolbar = (
        "<div class='gw-toolbar'>"
        "<input type='text' id='q' placeholder='Search packages…'>"
        "<select id='dec-filter'><option value=''>all decisions</option>"
        f"{dec_options}<option value='__none__'>unassessed</option></select>"
        "<span class='gw-note'>click a column header to sort; click a "
        "package name to expand its detail; the row URL "
        "(<code>#pkg=&lt;name&gt;</code>) is shareable</span></div>")

    ncols = 9
    rows_html = []
    for row in sorted(data["rows"], key=lambda r: r["name"].lower()):
        rid = f"pkg-{row['name']}"
        search = " ".join(str(x) for x in (
            row["name"], row["version"], row["decision"] or "unassessed",
            row["actor"])).lower()
        dec = row["decision"] or "__none__"
        run_id = row.get("run_id")
        if run_id:
            links = (f"<a href='{html.escape(url('/runs/' + run_id + '/report.html'))}'>HTML</a>")
            if row.get("has_pdf"):
                links += (f" · <a href='{html.escape(url('/report/' + run_id + '/report.pdf'))}'>PDF</a>")
        else:
            links = NO_ACTOR
        pub = ("<span class='gw-badge gw-badge-go'>published "
               f"{html.escape(str(row['published_version']))}</span>"
               if row["published"] else
               (f"published {html.escape(str(row['published_version']))} "
                "(other version)" if row["published_version"] else NO_ACTOR))
        score = row["overall_score"]
        score_v = str(score) if isinstance(score, (int, float)) else ""
        stale_mark = (" <span class='gw-badge gw-badge-cond'>stale: "
                      f"{html.escape(row['stale_reason'])}</span>"
                      if row["stale"] else "")
        stale_cls = " row-stale" if row["stale"] else ""
        rows_html.append(
            f"<tr class='pkg gw-anchor{stale_cls}' id='{html.escape(rid)}' "
            f"data-decision='{html.escape(dec)}' "
            f"data-search='{html.escape(search)}'>"
            f"<td><button class='gw-expander' data-target='{html.escape(rid)}-detail'>"
            f"{html.escape(row['name'])}</button>{stale_mark}</td>"
            f"<td>{html.escape(str(row['version'] or NO_ACTOR))}</td>"
            f"<td>{html.escape(str(row['tier'] or NO_ACTOR))}</td>"
            f"<td data-v='{html.escape(score_v)}'>{webui.score_bar(score)}</td>"
            f"<td data-v='{html.escape(dec)}'>{_badge(row['decision'])}</td>"
            f"<td>{html.escape(row['actor'])}</td>"
            f"<td>{html.escape(str(row['assessed_at'] or NO_ACTOR))}</td>"
            f"<td>{pub}</td>"
            f"<td>{links}</td></tr>")
        if row["assessed"]:
            detail = _detail_html(row, url)
            rows_html.append(
                f"<tr class='detail' id='{html.escape(rid)}-detail' "
                f"style='display:none'>"
                f"<td colspan='{ncols}'>{detail}</td></tr>")
    if rows_html:
        header = ("<tr><th data-sort='text'>Package</th>"
                  "<th data-sort='text'>Version</th>"
                  "<th data-sort='text'>Tier</th>"
                  "<th data-sort='num'>Score</th>"
                  "<th data-sort='text'>Decision</th>"
                  "<th data-sort='text'>Actor</th>"
                  "<th data-sort='text'>Assessed at</th>"
                  "<th data-sort='text'>Published</th>"
                  "<th>Report</th></tr>")
        table = (f"<div class='gw-table-wrap'><table id='pkg-table' "
                 f"class='gw-table'><thead>{header}</thead>"
                 f"<tbody>{''.join(rows_html)}</tbody></table></div>")
    else:
        table = ("<div class='gw-card gw-empty'><em>Inventory is empty — "
                 "generate config/inventory.json first.</em></div>")

    gaps = data["dependency_gaps"]
    if gaps:
        items = "".join(
            f"<li><code>{html.escape(g['package'])} "
            f"{html.escape(g['version'])}</code> — missing: "
            f"{html.escape(', '.join(g['missing']))}</li>"
            for g in gaps)
        gap_card = ("<div class='gw-banner' id='dependency-gaps'>"
                    "<b>Dependency gaps</b> — published packages whose "
                    "dependencies still need their own assessment + publish "
                    f"(chain gating):<ul>{items}</ul></div>")
    else:
        gap_card = ("<div class='gw-card' id='dependency-gaps'>"
                    "<b>Dependency gaps:</b> none among published "
                    "packages.</div>")

    body = (
        "<div class='gw-wrap'>"
        "<div class='gw-pagehead'>"
        "<h1>Package Validation Dashboard</h1>"
        f"<p class='gw-note'>Snapshot {html.escape(str(data['snapshot']))} · "
        f"{chain['records']} audit records · read-only view; assessments "
        "run via the intake form or the batch CLI.</p></div>"
        f"{banner}"
        f"<div class='gw-cards' id='stat-cards'>{cards}</div>"
        f"{toolbar}{table}{gap_card}"
        "</div>"
        f"<script>{_DASH_JS}</script>")
    return webui.page("Dashboard", body, url, active="dashboard",
                      user=user, chain=chain)
