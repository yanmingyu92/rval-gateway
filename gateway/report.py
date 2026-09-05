"""report.py — evidence-linked one-page report (HTML + LaTeX->PDF).

Hard rule (carried over from the E2 pipeline): no statement without an
evidence ID. Sections whose required evidence is missing render
"[NO EVIDENCE - SECTION SUPPRESSED]" instead of any statement.

HTML is self-contained (inline CSS, no external assets). PDF is rendered from
the LaTeX template via pdflatex; if pdflatex is unavailable or fails, the HTML
report is kept and the degradation is noted in the report footer and returned
in the result (never silently dropped).

Classification and sign-off always render as "PENDING HUMAN REVIEW" — the
tool never signs.

stdlib only.
"""

from __future__ import annotations

import html
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from . import __version__

HERE = Path(__file__).resolve().parent
TEMPLATE_HTML = HERE / "templates" / "report.html"
TEMPLATE_TEX = HERE / "templates" / "report.tex"

NO_EVIDENCE = "[NO EVIDENCE - SECTION SUPPRESSED]"
DECISION_CLASS = {"GO": "go", "GO-WITH-CONDITIONS": "conditions", "NO-GO": "nogo"}

# metric prefix -> report section for per-source sections
_CRAN_METRICS = ("cran.version", "cran.title", "cran.publication_date",
                 "cran.maintainer", "cran.license", "cran.url",
                 "cran.imports_count")
_COMMUNITY_METRICS = ("downloads.last_month_total", "github.repo",
                      "github.stars", "github.forks", "github.open_issues",
                      "github.last_push")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_index(evidence: dict) -> dict:
    return {e["metric"]: e for e in evidence.get("entries", [])}


def _fmt(v, maxlen: int = 300) -> str:
    if v is None:
        return ""
    if isinstance(v, float):
        s = f"{v:.4f}"
    elif isinstance(v, (dict, list)):
        s = str(v)
    else:
        s = str(v).replace("\n", " ").strip()
    return s if len(s) <= maxlen else s[: maxlen - 3] + "..."


def _evref(e: dict | None) -> str:
    return f'<span class="evid">[{e["evidence_id"]}]</span>' if e else ""


# ---------------------------------------------------------------- HTML

def _html_rules_table(decision_obj: dict) -> str:
    rows = ["<table><tr><th>Rule</th><th>Metric</th><th>Input</th>"
            "<th>Condition (op threshold)</th><th>Fired?</th><th>Severity</th></tr>"]
    for r in decision_obj.get("rules_evaluated", []):
        if "low_threshold" in r:  # score-range rule row
            cond = (f"score &lt; low ({r['low_threshold']}) → GO; "
                    f"&lt; high ({r['high_threshold']}) → conditions")
            inp = _fmt(r.get("input"))
            sev = "—"
        else:
            op = r.get("op", "")
            th = r.get("threshold")
            cond = f"{html.escape(str(op))} {html.escape(_fmt(th, 40))}".strip()
            inp = _fmt(r.get("input")) if r.get("applicable", True) else "(no input)"
            sev = r.get("severity", "—")
        fired = "FIRED" if r.get("fired") else "no"
        rows.append(
            f"<tr><td><code>{html.escape(str(r.get('id')))}</code></td>"
            f"<td>{html.escape(str(r.get('metric', '')))}</td>"
            f"<td>{html.escape(inp)}</td><td>{cond}</td>"
            f"<td><strong>{fired}</strong></td><td>{html.escape(str(sev))}</td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def _html_conditions(decision_obj: dict) -> str:
    conds = decision_obj.get("conditions") or []
    if not conds:
        return "<p>No conditions attached.</p>"
    items = "\n".join(f"<li>{html.escape(c)}</li>" for c in conds)
    return f"<ul>\n{items}\n</ul>"


def _html_metric_section(index: dict) -> str:
    rm = [e for m, e in index.items() if m.startswith("riskmetric.score.")]
    if not rm:
        return f'<p class="suppressed">{NO_EVIDENCE}</p>'
    rows = ["<table><tr><th>Metric</th><th>Risk (0–1)</th><th>Raw value</th>"
            "<th>Evidence</th></tr>"]
    for e in rm:
        metric = e["metric"][len("riskmetric.score."):]
        raw = index.get(f"riskmetric.raw.{metric}")
        rows.append(
            f"<tr><td>{html.escape(metric)}</td>"
            f"<td>{html.escape(_fmt(e['value'], 20) if e['value'] is not None else 'NA (not measurable)')}</td>"
            f"<td>{html.escape(_fmt(raw['value'], 120)) if raw else '—'}</td>"
            f"<td class='evid'>{e['evidence_id']}</td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def _html_simple_section(index: dict, metrics) -> str:
    entries = [index[m] for m in metrics if m in index]
    if not entries:
        return f'<p class="suppressed">{NO_EVIDENCE}</p>'
    rows = ["<table><tr><th>Field</th><th>Value</th><th>Evidence</th></tr>"]
    for e in entries:
        rows.append(f"<tr><td>{html.escape(e['metric'])}</td>"
                    f"<td>{html.escape(_fmt(e['value']))}</td>"
                    f"<td class='evid'>{e['evidence_id']}</td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def _html_evidence_table(evidence: dict) -> str:
    rows = ["<table><tr><th>ID</th><th>Metric</th><th>Value</th>"
            "<th>Mode</th><th>Source</th><th>Collected at</th></tr>"]
    for e in evidence.get("entries", []):
        rows.append(
            f"<tr><td class='evid'>{e['evidence_id']}</td>"
            f"<td>{html.escape(e['metric'])}</td>"
            f"<td>{html.escape(_fmt(e['value'], 120))}</td>"
            f"<td>{html.escape(e['mode'])}</td>"
            f"<td>{html.escape(_fmt(e['source'], 140))}</td>"
            f"<td>{html.escape(e['collected_at'])}</td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def _html_scoring_strategy(score: dict | None, index: dict) -> str:
    """Category subscores + full rubric disclosure (weights and metric
    membership). Display-only: the overall score algorithm is unchanged."""
    cats = (score or {}).get("category_scores")
    if not cats:
        return f'<p class="suppressed">{NO_EVIDENCE}</p>'
    rows = ["<table><tr><th>Category</th><th>Weight</th>"
            "<th>Subscore (0–1 risk)</th><th>Metrics scored</th></tr>"]
    for cat, c in cats.items():
        s = c.get("score")
        rows.append(
            f"<tr><td><strong>{html.escape(str(cat))}</strong></td>"
            f"<td>{html.escape(_fmt(c.get('weight'), 20))}</td>"
            f"<td>{html.escape(f'{s:.4f}') if isinstance(s, (int, float)) else 'NA (not measurable)'}</td>"
            f"<td>{c.get('scored', 0)} of {len(c.get('metrics') or [])}</td></tr>")
    rows.append("</table>")
    rubric = ["<p>Rubric: each category subscore is the equal-weighted mean of "
              "its member metrics' non-null riskmetric scores (0 = low risk, "
              "1 = high risk); category weights disclose the relative "
              "importance of each category in the assessment strategy. "
              "Category subscores are display-only — the overall score and "
              "the decision thresholds are unchanged. Metric membership and "
              "per-metric evidence:</p>"]
    for cat, c in cats.items():
        items = []
        for m in c.get("metrics") or []:
            e = index.get(f"riskmetric.score.{m}")
            val = (_fmt(e["value"], 20) if e and e["value"] is not None
                   else "NA")
            evid = f" [{e['evidence_id']}]" if e else ""
            items.append(f"<li><code>{html.escape(m)}</code>: "
                         f"{html.escape(val)}{html.escape(evid)}</li>")
        rubric.append(f"<p><strong>{html.escape(str(cat))}</strong> "
                      f"(weight {html.escape(_fmt(c.get('weight'), 20))})</p>"
                      f"<ul>{''.join(items)}</ul>")
    return "\n".join(rows) + "\n" + "\n".join(rubric)


def _html_classification(classification: dict | None, tier: str) -> str:
    """Intended-use classification block. Absent classification renders
    'not classified' (an honest statement), never a suppressed section."""
    cls = classification or {}
    iu = cls.get("intended_use")
    just = cls.get("justification")
    if not iu and not just:
        return ("<p><em>Not classified — no intended use or justification "
                "was recorded for this assessment.</em></p>")
    return ("<table>"
            f"<tr><th>Intended-use tier</th><td>{html.escape(str(tier))}</td></tr>"
            f"<tr><th>Intended use</th><td>{html.escape(str(iu or '—'))}</td></tr>"
            f"<tr><th>Justification</th><td>{html.escape(str(just or '—'))}</td></tr>"
            "</table>")


def _html_timeline(timeline) -> str:
    """Approval timeline from the audit chain (assessment -> esign ->
    publish), with actor, UTC timestamp and record-hash prefix."""
    events = timeline or []
    if not events:
        return ("<p><em>No audit-chain events recorded for this package "
                "yet.</em></p>")
    rows = ["<table><tr><th>Event</th><th>Actor</th><th>Timestamp (UTC)</th>"
            "<th>Detail</th><th>Record</th></tr>"]
    for e in events:
        rows.append(
            f"<tr><td><strong>{html.escape(str(e.get('event')))}</strong></td>"
            f"<td>{html.escape(str(e.get('actor') or '—'))}</td>"
            f"<td>{html.escape(str(e.get('timestamp') or '—'))}</td>"
            f"<td>{html.escape(str(e.get('detail') or ''))}</td>"
            f"<td class='evid'>{html.escape(str(e.get('hash') or ''))}…</td></tr>")
    rows.append("</table>")
    return "\n".join(rows)


def _html_system_info(common: dict, evidence: dict, score: dict | None,
                      generated_at: str) -> str:
    """Annex: system information — tool/R/riskmetric/config versions,
    collection mode, per-source success/failure summary, timestamps."""
    rows = ["<table>",
            f"<tr><th>Generator</th><td>rval-gateway {html.escape(common['TOOL_VERSION'])} (Python stdlib)</td></tr>",
            f"<tr><th>R version</th><td>{html.escape(common['R_VERSION'])}</td></tr>",
            f"<tr><th>{{riskmetric}} version</th><td>{html.escape(common['RISKMETRIC_VERSION'])}</td></tr>",
            f"<tr><th>Decision config</th><td>v{html.escape(common['CONFIG_VERSION'])}, "
            f"sha256 <code class='evid'>{html.escape(common['CONFIG_SHA256'])}</code> "
            f"(<code>{html.escape(common['CONFIG_PATH'])}</code>)</td></tr>",
            f"<tr><th>Evidence collection mode</th><td>{html.escape(common['COLLECTION_MODE'])}</td></tr>",
            f"<tr><th>Evidence collected at (UTC)</th><td>{html.escape(str(evidence.get('collected_at') or '—'))}</td></tr>",
            f"<tr><th>Assessment scored at (UTC)</th><td>{html.escape(str((score or {}).get('assessed_at') or '—'))}</td></tr>",
            f"<tr><th>Report generated at (UTC)</th><td>{html.escape(generated_at)}</td></tr>",
            "</table>"]
    n_ok = evidence.get("network_sources_ok", 0)
    failed = evidence.get("network_sources_failed") or []
    parts = ["\n".join(rows),
             f"<p>Source summary: local collectors (tarball DESCRIPTION, "
             f"sha256, ingest provenance) always ran; riskmetric merge "
             f"{'ran' if (score or {}).get('metric_scores') is not None else 'did not run (un-scored)'}; "
             f"network sources succeeded: {n_ok}, failed: {len(failed)}.</p>"]
    if failed:
        items = "".join(
            f"<li><code>{html.escape(str(f.get('collector')))}</code> — "
            f"{html.escape(_fmt(f.get('url'), 120))}: "
            f"{html.escape(_fmt(f.get('error'), 160))}</li>"
            for f in failed)
        parts.append(f"<p>Failed sources (degraded explicitly, never "
                     f"fabricated):</p><ul>{items}</ul>")
    return "\n".join(parts)


# ---------------------------------------------------------------- LaTeX

_TEX_SPECIALS = {
    "\\": r"\textbackslash{}",
    "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "_": r"\_",
    "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}",
}


def _tex(s) -> str:
    s = "" if s is None else str(s)
    return "".join(_TEX_SPECIALS.get(c, c) for c in s)


def _tex_rules_table(decision_obj: dict) -> str:
    lines = [r"\begin{longtable}{@{}p{4.2cm}p{4.6cm}p{2.2cm}p{3.4cm}@{}}",
             r"\toprule",
             r"\textbf{Rule} & \textbf{Input} & \textbf{Condition} & \textbf{Fired} \\",
             r"\midrule", r"\endhead"]
    for r in decision_obj.get("rules_evaluated", []):
        if "low_threshold" in r:
            cond = (f"score < {_fmt(r['low_threshold'])} / "
                    f"{_fmt(r['high_threshold'])}")
        else:
            cond = f"{r.get('op','')} {_fmt(r.get('threshold'), 30)}".strip()
        inp = _fmt(r.get("input"), 40) if r.get("applicable", True) else "(no input)"
        fired_tex = "\\textbf{FIRED}" if r.get("fired") else "no"
        lines.append(
            f"{_tex(r.get('id'))} & {_tex(inp)} & {_tex(cond)} & "
            f"{fired_tex} \\\\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{longtable}")
    return "\n".join(lines)


def _tex_conditions(decision_obj: dict) -> str:
    conds = decision_obj.get("conditions") or []
    if not conds:
        return "No conditions attached."
    items = "\n".join(f"  \\item {_tex(c)}" for c in conds)
    return "\\begin{itemize}\n" + items + "\n\\end{itemize}"


def _tex_metric_table(index: dict) -> str:
    rm = [e for m, e in index.items() if m.startswith("riskmetric.score.")]
    if not rm:
        return f"\\emph{{{_tex(NO_EVIDENCE)}}}"
    lines = [r"\begin{longtable}{@{}p{5cm}p{2.4cm}p{7.2cm}@{}}",
             r"\toprule",
             r"\textbf{Metric} & \textbf{Risk (0--1)} & \textbf{Evidence} \\",
             r"\midrule", r"\endhead"]
    for e in rm:
        metric = e["metric"][len("riskmetric.score."):]
        val = _fmt(e["value"], 20) if e["value"] is not None else "NA"
        lines.append(f"{_tex(metric)} & {_tex(val)} & {_tex(e['evidence_id'])} \\\\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{longtable}")
    return "\n".join(lines)


def _tex_evidence_rows(evidence: dict) -> str:
    lines = []
    for e in evidence.get("entries", []):
        lines.append(f"{_tex(e['evidence_id'])} & {_tex(e['metric'])} & "
                     f"{_tex(_fmt(e['value'], 60))} & {_tex(e['mode'])} \\\\")
    return "\n".join(lines)


def _tex_scoring_strategy(score: dict | None, index: dict) -> str:
    """Category subscores + rubric disclosure (display-only)."""
    cats = (score or {}).get("category_scores")
    if not cats:
        return f"\\emph{{{_tex(NO_EVIDENCE)}}}"
    lines = [r"\begin{longtable}{@{}p{3.6cm}p{1.8cm}p{3.2cm}p{6.4cm}@{}}",
             r"\toprule",
             r"\textbf{Category} & \textbf{Weight} & \textbf{Subscore (0--1 risk)} & \textbf{Member metrics} \\",
             r"\midrule", r"\endhead"]
    for cat, c in cats.items():
        s = c.get("score")
        s_txt = f"{s:.4f}" if isinstance(s, (int, float)) else "NA"
        members = []
        for m in c.get("metrics") or []:
            e = index.get(f"riskmetric.score.{m}")
            val = _fmt(e["value"], 20) if e and e["value"] is not None else "NA"
            evid = f" [{e['evidence_id']}]" if e else ""
            members.append(f"{m}: {val}{evid}")
        lines.append(f"{_tex(cat)} & {_tex(_fmt(c.get('weight'), 20))} & "
                     f"{_tex(s_txt)} & {{\\footnotesize {_tex(', '.join(members))}}} \\\\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{longtable}")
    lines.append("")
    lines.append("\\emph{Rubric: each category subscore is the equal-weighted "
                 "mean of its member metrics' non-null riskmetric scores "
                 "(0 = low risk, 1 = high risk); weights disclose the "
                 "relative importance of each category. Category subscores "
                 "are display-only --- the overall score and the decision "
                 "thresholds are unchanged.}")
    return "\n".join(lines)


def _tex_classification(classification: dict | None, tier: str) -> str:
    cls = classification or {}
    iu = cls.get("intended_use")
    just = cls.get("justification")
    if not iu and not just:
        return ("\\emph{Not classified --- no intended use or justification "
                "was recorded for this assessment.}")
    return ("\\begin{tabular}{@{}p{4cm}p{11cm}@{}}\n"
            f"\\textbf{{Intended-use tier}} & {_tex(tier)} \\\\\n"
            f"\\textbf{{Intended use}} & {_tex(iu or '---')} \\\\\n"
            f"\\textbf{{Justification}} & {_tex(just or '---')} \\\\\n"
            "\\end{tabular}")


def _tex_timeline(timeline) -> str:
    events = timeline or []
    if not events:
        return ("\\emph{No audit-chain events recorded for this package yet.}")
    lines = [r"\begin{longtable}{@{}p{2.6cm}p{3cm}p{3.4cm}p{5.6cm}@{}}",
             r"\toprule",
             r"\textbf{Event} & \textbf{Actor} & \textbf{Timestamp (UTC)} & \textbf{Detail / record} \\",
             r"\midrule", r"\endhead"]
    for e in events:
        detail = f"{e.get('detail') or ''} [{e.get('hash') or ''}]"
        lines.append(f"{_tex(e.get('event'))} & "
                     f"{_tex(e.get('actor') or '---')} & "
                     f"{{\\footnotesize {_tex(e.get('timestamp') or '---')}}} & "
                     f"{{\\footnotesize {_tex(detail)}}} \\\\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{longtable}")
    return "\n".join(lines)


def _tex_system_info(evidence: dict, score: dict | None) -> str:
    """Per-source success/failure summary lines (versions and config are
    already in the provenance footer and the header table)."""
    n_ok = evidence.get("network_sources_ok", 0)
    failed = evidence.get("network_sources_failed") or []
    lines = ["\\begin{tabular}{@{}p{5.4cm}p{9.6cm}@{}}",
             f"\\textbf{{Evidence collected at (UTC)}} & "
             f"{_tex(evidence.get('collected_at') or '---')} \\\\",
             f"\\textbf{{Assessment scored at (UTC)}} & "
             f"{_tex((score or {}).get('assessed_at') or '---')} \\\\",
             f"\\textbf{{Network sources ok / failed}} & {n_ok} / {len(failed)} \\\\",
             "\\end{tabular}"]
    if failed:
        items = "\n".join(
            f"  \\item \\texttt{{{_tex(str(f.get('collector')))}}} --- "
            f"{_tex(_fmt(f.get('error'), 120))}"
            for f in failed)
        lines.append("Failed sources (degraded explicitly, never fabricated):\n"
                     "\\begin{itemize}\n" + items + "\n\\end{itemize}")
    return "\n".join(lines)


def _display_path(p) -> str:
    """Render a config path without workstation-absolute prefixes."""
    if not p:
        return "config/decision_rules.yml"
    p = Path(str(p))
    try:
        return str(p.relative_to(HERE.parent))
    except ValueError:
        return p.name


# ---------------------------------------------------------------- render

def _fill(template: str, mapping: dict) -> str:
    def sub(m):
        key = m.group(1)
        if key not in mapping:
            raise KeyError(f"template slot {key} has no value")
        return mapping[key]
    return re.sub(r"\{\{([A-Z0-9_]+)\}\}", sub, template)


def render(assessment: dict, out_dir: str | Path) -> dict:
    """Render HTML (+ attempt PDF). assessment keys: spec, ingest, score,
    evidence, decision; optional: classification ({intended_use,
    justification}) and timeline (audit-chain events from
    audit.package_timeline). Returns paths and degradation notes."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ingest = assessment["ingest"]
    evidence = assessment["evidence"]
    decision_obj = assessment["decision"]
    score = assessment.get("score") or {}
    index = build_index(evidence)
    generated_at = assessment.get("generated_at") or _now()

    def ev(metric):
        e = index.get(metric)
        return e["evidence_id"] if e else "—"

    common = {
        "PKG_NAME": str(ingest.get("package")),
        "PKG_VERSION": str(ingest.get("version")),
        "PKG_VERSION_EV": ev("description.version"),
        "ORIGIN": str(ingest.get("origin")),
        "ORIGIN_EV": ev("ingest.origin"),
        "SHA256": str(ingest.get("sha256")),
        "SHA256_EV": ev("tarball.sha256"),
        "TIER": str(decision_obj.get("tier")),
        "GENERATED_AT": generated_at,
        "DECISION": str(decision_obj.get("decision")),
        "OVERALL_SCORE": _fmt(decision_obj.get("overall_score"), 20)
                         if decision_obj.get("overall_score") is not None else "NA",
        "OVERALL_EV": ev("riskmetric.overall_score"),
        "CONFIG_VERSION": str(decision_obj.get("config_version")),
        "CONFIG_SHA256": str(decision_obj.get("config_sha256")),
        "CONFIG_SHA256_SHORT": str(decision_obj.get("config_sha256", ""))[:12],
        "CONFIG_PATH": _display_path(decision_obj.get("config_path")),
        "COLLECTION_MODE": str(evidence.get("collection_mode")),
        "R_VERSION": str(score.get("r_version", "unknown")),
        "RISKMETRIC_VERSION": str(score.get("riskmetric_version", "unknown")),
        "TOOL_VERSION": __version__,
    }

    html_map = dict(common, **{
        "DECISION_CLASS": DECISION_CLASS.get(decision_obj.get("decision"), "nogo"),
        "SOURCE_URL": html.escape(str(ingest.get("source_url") or "—")),
        "RULES_TABLE": _html_rules_table(decision_obj),
        "CONDITIONS_BLOCK": _html_conditions(decision_obj),
        "METRIC_SECTION": _html_metric_section(index),
        "SCORING_STRATEGY": _html_scoring_strategy(score, index),
        "CRAN_SECTION": _html_simple_section(index, _CRAN_METRICS),
        "COMMUNITY_SECTION": _html_simple_section(index, _COMMUNITY_METRICS),
        "CLASSIFICATION_BLOCK": _html_classification(
            assessment.get("classification"), str(decision_obj.get("tier"))),
        "TIMELINE_BLOCK": _html_timeline(assessment.get("timeline")),
        "SYSTEM_INFO": _html_system_info(common, evidence, score,
                                         generated_at),
        "EVIDENCE_TABLE": _html_evidence_table(evidence),
        "PDF_NOTE": "",  # filled after PDF attempt
    })

    pdf_path = out / "report.pdf"
    pdf_ok, pdf_note = _render_pdf(common, decision_obj, index, evidence, out,
                                   assessment=assessment, score=score)
    html_map["PDF_NOTE"] = (
        "" if pdf_ok else
        f"PDF rendering degraded: {html.escape(pdf_note)}; HTML is the authoritative copy.")

    html_path = out / "report.html"
    html_path.write_text(_fill(TEMPLATE_HTML.read_text(encoding="utf-8"),
                               html_map), encoding="utf-8")
    return {"html": str(html_path),
            "pdf": str(pdf_path) if pdf_ok else None,
            "pdf_note": None if pdf_ok else pdf_note}


def _render_pdf(common, decision_obj, index, evidence, out: Path,
                assessment: dict | None = None, score: dict | None = None):
    pdflatex = shutil.which("pdflatex")
    if not pdflatex:
        return False, "pdflatex not on PATH"
    assessment = assessment or {}
    tex_map = dict(common, **{
        k: _tex(v) for k, v in common.items()
        if k not in ("RULES_TABLE", "CONDITIONS_BLOCK")
    })
    tex_map.update({
        "RULES_TABLE": _tex_rules_table(decision_obj),
        "CONDITIONS_BLOCK": _tex_conditions(decision_obj),
        "METRIC_TABLE": _tex_metric_table(index),
        "SCORING_STRATEGY": _tex_scoring_strategy(score, index),
        "CLASSIFICATION_BLOCK": _tex_classification(
            assessment.get("classification"),
            str(decision_obj.get("tier"))),
        "TIMELINE_BLOCK": _tex_timeline(assessment.get("timeline")),
        "SYSTEM_INFO": _tex_system_info(evidence, score),
        "EVIDENCE_ROWS": _tex_evidence_rows(evidence),
    })
    tex_src = _fill(TEMPLATE_TEX.read_text(encoding="utf-8"), tex_map)
    tex_path = out / "report.tex"
    tex_path.write_text(tex_src, encoding="utf-8")
    try:
        proc = subprocess.run(
            [pdflatex, "-interaction=nonstopmode", "-halt-on-error",
             "report.tex"],
            cwd=out, capture_output=True, text=True, timeout=180)
    except Exception as e:  # noqa: BLE001
        return False, f"pdflatex invocation failed: {type(e).__name__}: {e}"
    if proc.returncode != 0 or not (out / "report.pdf").is_file():
        tail = (proc.stdout or "")[-600:].replace("\n", " ")
        return False, f"pdflatex exit {proc.returncode}: {tail}"
    # clean intermediate files, keep report.tex for auditability
    for ext in (".aux", ".log", ".out"):
        f = out / f"report{ext}"
        if f.exists():
            f.unlink()
    return True, None
