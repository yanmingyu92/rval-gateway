"""server.py — stdlib http.server web UI for the gateway.

Endpoints:

  GET  /          intake form (CRAN name | GitHub URL | tarball upload; tier)
  POST /assess    enqueue an assessment job -> 202 + job_id (the pipeline
                  runs on a background thread; see gateway/jobs.py)
  GET  /jobs/<job_id>        job status page (waiting spinner -> report
                  summary with publish/remediation actions)
  GET  /api/jobs/<job_id>    job state machine as JSON
                  {status: queued|running|done|failed, run_id?, error?};
                  unknown id -> 404 {status: lost}
  POST /publish   publish an assessed package into the approved repository
                  (gxp-critical publishes require two distinct signers)
  POST /remediate attach a remediation note to a NO-GO assessment
  GET  /dashboard server-rendered package-validation dashboard (read-only)
  GET  /api/assessments?limit=N   audit-log tail + chain status (JSON)
  GET  /api/inventory             inventory x latest-assessment join (JSON)
  GET  /static/<file>         vendored UI assets (bootstrap, icons,
                  gateway.css, favicon) — whitelisted names only, gated
  GET  /runs/<run_id>/<file>      read-only run outputs, whitelisted files
                  only: report.html, decision.json, evidence.json,
                  score/score.json (path-safe, like /report/)
  GET  /repo-view repository manifest + dependency gaps (authenticated)
  GET  /repo/...  approved-package repository, read-only static, NO auth —
                  image builds cannot perform SSO; the repo only ever
                  contains approved artifacts; the port is localhost-bound
                  behind the platform proxy
  GET  /health    JSON {status, tool_version, ...} — no auth (healthcheck)
  GET  /report/<run_id>/report.pdf   serve a generated PDF (path-safe)

Auth: when RVAL_PLATFORM_API_URL is set, every path except /health and /repo/*
requires platform authentication (see gateway/platform_auth.py — fail
closed). When unset, auth is disabled with a prominent startup warning
(local development only).

Base path: GATEWAY_BASE_PATH (default "/") prefixes every URL the server
GENERATES (form action, report/PDF/repo links), so the UI works behind a
prefix-stripping reverse proxy (e.g. /rval-gateway/). Incoming requests
arrive prefix-stripped; only generated URLs carry the prefix.

Run: python -m gateway.server [--port 8788]
Bind address/port resolution order: CLI args > GATEWAY_HOST / GATEWAY_PORT
env vars > defaults (127.0.0.1:8788). The default binds localhost only; set
GATEWAY_HOST=0.0.0.0 ONLY inside a container whose compose file maps the port
back to 127.0.0.1 on the host (see docker-compose.yml).
stdlib only.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from . import audit as audit_mod
from . import dashboard as dash_mod
from . import decision as decision_mod
from . import jobs as jobs_mod
from . import pipeline, platform_auth, r_adapter, repo as repo_mod
from . import webui

DEFAULT_PORT = 8788
BIND_HOST = "127.0.0.1"

# /runs/<run_id>/<file> whitelist: URL suffix -> (path inside the run dir,
# content type). report.html is self-contained (no external references), so
# it renders standalone.
_RUN_FILE_WHITELIST = {
    "report.html": ("report/report.html", "text/html; charset=utf-8"),
    "decision.json": ("decision.json", "application/json"),
    "evidence.json": ("evidence.json", "application/json"),
    "score/score.json": ("score/score.json", "application/json"),
}

STATIC_DIR = Path(__file__).resolve().parent / "static"

# /static/<file> whitelist: vendored UI assets only (name -> content type).
_STATIC_WHITELIST = {
    "bootstrap.min.css": "text/css",
    "bootstrap-icons.css": "text/css",
    "gateway.css": "text/css",
    "favicon.svg": "image/svg+xml",
    "fonts/bootstrap-icons.woff": "font/woff",
    "fonts/bootstrap-icons.woff2": "font/woff2",
}


def base_path() -> str:
    """URL prefix for generated links (env GATEWAY_BASE_PATH, default '/')."""
    bp = os.environ.get("GATEWAY_BASE_PATH", "/")
    if not bp.startswith("/"):
        bp = "/" + bp
    if not bp.endswith("/"):
        bp += "/"
    return bp


def url(path: str) -> str:
    """Prefix a server path with the configured base path."""
    return base_path() + path.lstrip("/")


def page(title: str, body: str, **kw) -> bytes:
    """Shared page skeleton (see webui.page); kept as a thin wrapper so
    existing callers and tests keep working."""
    return webui.page(title, body, url, **kw)


_TIER_CARDS = (
    ("exploratory", "bi-compass", "exploratory",
     "Non-GxP exploration and feasibility work. Screening is advisory; "
     "results inform but do not gate regulated use."),
    ("gxp-support", "bi-shield", "gxp-support",
     "Supports GxP workflows (e.g. internal tooling around regulated "
     "analyses). A NO-GO escalates to Tier 2 full validation."),
    ("gxp-critical", "bi-shield-lock", "gxp-critical",
     "On the critical path of a regulated decision. Requires a recorded "
     "intended use and justification; publishing needs dual electronic "
     "sign-off (two distinct signers)."),
)

_INTAKE_JS = """
const panes = {cran: 'pane-cran', github: 'pane-github', upload: 'pane-upload'};
let source = 'cran';
const form = document.getElementById('intake-form');
const resultBox = document.getElementById('assess-result');
const submitBtn = document.getElementById('submit-btn');

function setSource(name){
  source = name;
  document.querySelectorAll('.gw-tab').forEach(t =>
    t.classList.toggle('active', t.dataset.source === name));
  Object.entries(panes).forEach(([k, id]) =>
    document.getElementById(id).classList.toggle('active', k === name));
  // clear the fields of inactive panes so only one source is submitted
  Object.entries(panes).forEach(([k, id]) => {
    if (k === name) return;
    document.getElementById(id).querySelectorAll('input').forEach(i => i.value = '');
  });
}
document.querySelectorAll('.gw-tab').forEach(t =>
  t.addEventListener('click', () => setSource(t.dataset.source)));

const tierCards = document.querySelectorAll('.gw-tier');
function syncTier(){
  const t = form.querySelector('input[name=tier]:checked').value;
  tierCards.forEach(c => c.classList.toggle('selected',
    c.querySelector('input').value === t));
  const crit = (t === 'gxp-critical');
  document.getElementById('classification-card').style.display =
    crit ? '' : 'none';
  ['intended_use', 'justification'].forEach(n =>
    form.elements[n].required = crit);
}
tierCards.forEach(c => c.addEventListener('click', () => {
  c.querySelector('input').checked = true;
  syncTier();
}));
syncTier();

function markInvalid(name, on){
  const el = form.elements[name];
  if (el) el.classList.toggle('is-invalid', !!on);
}
function validate(){
  let ok = true;
  if (source === 'cran'){
    const v = form.elements.pkg.value.trim();
    const good = /^[A-Za-z][A-Za-z0-9.]*[A-Za-z0-9]$/.test(v);
    markInvalid('pkg', !good); ok = ok && good;
  } else if (source === 'github'){
    const v = form.elements.github.value.trim();
    const good = /^https?:\\/\\/github\\.com\\/[A-Za-z0-9_.-]+\\/[A-Za-z0-9_.-]+/.test(v);
    markInvalid('github', !good); ok = ok && good;
  } else {
    const f = form.elements.tarball;
    const good = f.files.length > 0 && /\\.tar\\.gz$|\\.tgz$/.test(f.files[0].name);
    markInvalid('tarball', !good); ok = ok && good;
  }
  if (form.querySelector('input[name=tier]:checked').value === 'gxp-critical'){
    ['intended_use', 'justification'].forEach(n => {
      const bad = !form.elements[n].value.trim();
      markInvalid(n, bad); ok = ok && !bad;
    });
  }
  return ok;
}

function showError(msg){
  resultBox.innerHTML = '<div class="gw-card"><div class="gw-err"><b>' +
    'Assessment could not be started.</b><br>' + msg + '</div></div>';
  resultBox.scrollIntoView({behavior: 'smooth'});
}
async function poll(statusUrl, fragmentUrl){
  try {
    const r = await fetch(statusUrl, {headers: {'Accept': 'application/json'}});
    if (r.status === 404){
      showError('Job lost (server restarted). Please resubmit the assessment.');
      submitBtn.disabled = false;
      return;
    }
    const j = await r.json();
    if (j.status === 'done'){
      const f = await fetch(fragmentUrl, {headers: {'Accept': 'text/html'}});
      resultBox.innerHTML = await f.text();
      resultBox.scrollIntoView({behavior: 'smooth'});
      submitBtn.disabled = false;
      return;
    }
    if (j.status === 'failed'){
      showError('Assessment failed: ' + (j.error || 'unknown error'));
      submitBtn.disabled = false;
      return;
    }
    setTimeout(() => poll(statusUrl, fragmentUrl), 2000);
  } catch (e) {
    showError('Lost contact with the server while polling: ' + e);
    submitBtn.disabled = false;
  }
}
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!validate()) return;
  submitBtn.disabled = true;
  resultBox.innerHTML = '<div class="gw-card"><span class="gw-spinner"></span>' +
    ' <b>Assessment running…</b> <span class="gw-note">R subprocess scoring ' +
    'plus evidence collection typically takes 10–60 seconds; this page polls ' +
    'the job and renders the report summary in place.</span></div>';
  const fd = new FormData(form);
  let r;
  try {
    r = await fetch(form.action, {method: 'POST', body: fd,
                                  headers: {'Accept': 'application/json'}});
  } catch (err) {
    showError('Could not reach the server: ' + err);
    submitBtn.disabled = false;
    return;
  }
  if (r.status === 429){
    showError('The server is busy (too many assessments running). ' +
              'Wait for one to finish and resubmit.');
    submitBtn.disabled = false;
    return;
  }
  if (r.status === 400){
    showError(await r.text());
    submitBtn.disabled = false;
    return;
  }
  if (!r.ok){ showError('Unexpected response: HTTP ' + r.status);
    submitBtn.disabled = false; return; }
  const j = await r.json();
  poll(j.status_url, j.page_url + '?fragment=1');
});
"""


def _tier_cards_html() -> str:
    cards = []
    for value, icon, label, desc in _TIER_CARDS:
        checked = " checked" if value == "exploratory" else ""
        cards.append(
            f"<label class='gw-tier'><input type='radio' name='tier' "
            f"value='{value}'{checked}>"
            f"<span class='t'><i class='bi {icon}'></i> {label}</span>"
            f"<span class='d'>{desc}</span></label>")
    return "".join(cards)


def _form_html(user: str | None = None, chain: dict | None = None) -> bytes:
    body = f"""
<div class="gw-wrap gw-wrap-narrow">
 <div class="gw-pagehead">
  <h1>New package assessment</h1>
  <p class="gw-note">Tier-1 screening: risk score + config-driven
  GO / GO-WITH-CONDITIONS / NO-GO decision + evidence-linked report.
  The tool never signs off; classification and sign-off stay with human QA.</p>
 </div>
 <form method="post" action="{html.escape(url('/assess'))}"
       enctype="multipart/form-data" id="intake-form" novalidate>
 <div class="gw-card">
  <h5 class="mt-0">Package source</h5>
  <div class="gw-tabs">
   <button type="button" class="gw-tab active" data-source="cran">
    <span class="t"><i class="bi bi-box-seam"></i> CRAN</span>
    <span class="d">name + optional version (default: current CRAN)</span>
   </button>
   <button type="button" class="gw-tab" data-source="github">
    <span class="t"><i class="bi bi-github"></i> GitHub</span>
    <span class="d">repository URL + optional ref (default: HEAD)</span>
   </button>
   <button type="button" class="gw-tab" data-source="upload">
    <span class="t"><i class="bi bi-upload"></i> Tarball upload</span>
    <span class="d">package source tarball (.tar.gz)</span>
   </button>
  </div>
  <div class="gw-tabpane active" id="pane-cran">
   <div class="gw-field">
    <label for="f-pkg">CRAN package name</label>
    <input type="text" id="f-pkg" name="pkg" placeholder="e.g. abind">
    <div class="invalid">A CRAN package name starts with a letter and uses
    only letters, digits and dots (min. 2 characters).</div>
   </div>
   <div class="gw-field">
    <label for="f-ver">Version <span class="gw-muted">(optional)</span></label>
    <input type="text" id="f-ver" name="version" placeholder="e.g. 1.4-8">
   </div>
  </div>
  <div class="gw-tabpane" id="pane-github">
   <div class="gw-field">
    <label for="f-gh">GitHub URL</label>
    <input type="text" id="f-gh" name="github"
           placeholder="https://github.com/owner/repo">
    <div class="invalid">Expected a GitHub URL like
    https://github.com/owner/repo.</div>
   </div>
   <div class="gw-field">
    <label for="f-ref">Ref <span class="gw-muted">(optional)</span></label>
    <input type="text" id="f-ref" name="ref" placeholder="default: HEAD">
   </div>
  </div>
  <div class="gw-tabpane" id="pane-upload">
   <div class="gw-field">
    <label for="f-tar">Package source tarball</label>
    <input type="file" id="f-tar" name="tarball" accept=".tar.gz,.tgz"
           class="form-control">
    <div class="invalid">Choose a .tar.gz package tarball.</div>
   </div>
  </div>
 </div>
 <div class="gw-card">
  <h5 class="mt-0">Intended-use tier</h5>
  <div class="gw-tiers">{_tier_cards_html()}</div>
 </div>
 <div class="gw-card" id="classification-card" style="display:none">
  <h5 class="mt-0">Classification <span class="gw-badge gw-badge-nogo">
  required for gxp-critical</span></h5>
  <div class="gw-field">
   <label for="f-iu">Intended use</label>
   <input type="text" id="f-iu" name="intended_use"
          placeholder="e.g. exploratory analysis outputs for study planning">
   <div class="invalid">Intended use is required for gxp-critical.</div>
  </div>
  <div class="gw-field">
   <label for="f-just">Justification</label>
   <textarea id="f-just" name="justification" rows="3"
             placeholder="why this package is appropriate for the intended use"></textarea>
   <div class="invalid">Justification is required for gxp-critical.</div>
  </div>
 </div>
 <button type="submit" class="gw-btn gw-btn-primary" id="submit-btn">
 <i class="bi bi-play-circle"></i> Assess</button>
 </form>
 <div id="assess-result" class="mt-3"></div>
 <p class="gw-note mt-3">Assessments run as background jobs (10–60&nbsp;s):
 the page polls and renders the report summary in place. Read-only views:
 <a href="{html.escape(url('/dashboard'))}">Dashboard</a> ·
 <a href="{html.escape(url('/repo-view'))}">Approved-package repository</a>.</p>
</div>
<script>{_INTAKE_JS}</script>
"""
    return page("Intake", body, active="intake", user=user, chain=chain)


def _parse_multipart(body: bytes, content_type: str) -> dict:
    """Minimal multipart/form-data parser (stdlib-only; cgi is removed in 3.13).

    Returns {field: (filename|None, bytes)}.
    """
    m = re.search(r"boundary=(.+)$", content_type)
    if not m:
        return {}
    boundary = m.group(1).strip().strip('"').encode()
    parts = {}
    for chunk in body.split(b"--" + boundary):
        chunk = chunk.strip(b"\r\n")
        if not chunk or chunk == b"--":
            continue
        header, _, value = chunk.partition(b"\r\n\r\n")
        htxt = header.decode("utf-8", "replace")
        name_m = re.search(r'name="([^"]+)"', htxt)
        if not name_m:
            continue
        fname_m = re.search(r'filename="([^"]*)"', htxt)
        value = value.rstrip(b"\r\n")
        if value.endswith(b"--"):
            value = value[:-2]
        parts[name_m.group(1)] = (
            fname_m.group(1) if fname_m else None, value)
    return parts


def _signature_fieldset(suffix: str, label: str) -> str:
    """One signer/password pair for the publish form (re-authentication at
    signing time, 21 CFR Part 11)."""
    return (
        f"<fieldset class='gw-card'><legend><b>{html.escape(label)}</b>"
        "</legend>"
        f"<div class='gw-field'><input type='text' name='esign_signer{suffix}' "
        "placeholder='signer user id' required></div>"
        f"<div class='gw-field'><input type='password' "
        f"name='esign_password{suffix}' "
        "placeholder='re-enter password to sign' required autocomplete="
        "'off'></div>"
        "<div class='gw-note'>Signing meaning: <b>approved</b> — the "
        "password is re-verified against the platform login API at signing "
        "time.</div></fieldset>")


def _publish_form(pkg: str, ver: str, tier: str) -> str:
    """Post-assessment publish form. Tier gxp-critical requires dual
    approval: two distinct signers, each re-authenticated; the form says so
    plainly and collects both signatures in one submit."""
    dual = tier == "gxp-critical"
    if dual:
        sig_blocks = (_signature_fieldset("", "First signature "
                                          "(21 CFR Part 11)")
                      + _signature_fieldset("2", "Second signature — "
                                            "distinct signer"))
        dual_note = (
            "<p class='gw-note'><b>Dual approval required:</b> this "
            "assessment is tier <code>gxp-critical</code>, so publishing "
            "needs valid electronic signatures from <b>two distinct "
            "signers</b>. A single sign-off will be refused.</p>")
    else:
        sig_blocks = _signature_fieldset("", "Electronic signature "
                                         "(21 CFR Part 11)")
        dual_note = ""
    return (
        f"<form method='post' action='{html.escape(url('/publish'))}'>"
        f"<input type='hidden' name='package' value='{pkg}'>"
        f"<input type='hidden' name='version' value='{ver}'>"
        "<input type='hidden' name='esign_meaning' value='approved'>"
        "<div class='gw-field'><label><input type='checkbox' name='binary' "
        "value='1'> prefer Linux binary flavor (P3M noble)</label></div>"
        f"{dual_note}{sig_blocks}"
        "<button type='submit' class='gw-btn gw-btn-primary'>"
        "<i class='bi bi-pen'></i> Sign &amp; publish to approved "
        "repository</button>"
        "</form>")


def _remediation_form(pkg: str, ver: str, record_hash: str) -> str:
    """NO-GO remediation-note form: appends a remediation record to the
    audit chain, linked to the NO-GO assessment by its record_hash."""
    return (
        f"<form method='post' action='{html.escape(url('/remediate'))}'>"
        f"<input type='hidden' name='package' value='{pkg}'>"
        f"<input type='hidden' name='version' value='{ver}'>"
        f"<input type='hidden' name='assessment_record_hash' "
        f"value='{html.escape(record_hash)}'>"
        "<fieldset class='gw-card'><legend><b>NO-GO remediation note "
        "(optional)</b></legend>"
        "<div class='gw-field'><textarea name='note' rows='3' required "
        "placeholder='what will be done about this NO-GO (e.g. pin an older "
        "version, escalate to Tier 2 full validation, replace the package)'>"
        "</textarea></div>"
        "<div class='gw-note'>Appended to the audit chain, linked to this "
        "assessment; shown in the dashboard and the report approval "
        "timeline when the package is re-assessed. Notes are "
        "append-only.</div><br>"
        "<button type='submit' class='gw-btn gw-btn-secondary'>Record "
        "remediation note</button>"
        "</fieldset></form>")


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = f"rval-gateway/{__version__}"

    def _send(self, code: int, body: bytes, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # keep console noise low but visible
        sys.stderr.write("[gateway] %s %s\n" % (self.address_string(),
                                                fmt % args))

    # ---------------- auth gate ----------------

    def _actor_name(self) -> str | None:
        """Display name for the nav user chip: the authenticated user id,
        or an honest dev-mode marker when auth is disabled."""
        actor = getattr(self, "_auth_result", None)
        if actor is not None:
            return actor.user_id
        if not platform_auth.auth_enabled():
            return "dev mode (auth off)"
        return None

    def _chain(self) -> dict | None:
        try:
            return dash_mod.chain_status(pipeline.DEFAULT_DATA_DIR)
        except Exception:  # noqa: BLE001 — footer must never break a page
            return None

    def _gate(self) -> bool:
        """Returns True if the request may proceed; otherwise responds and
        returns False. /health and /repo/* are public by design. On success
        the AuthResult is stashed on self._auth_result so downstream
        handlers can record the authenticated actor."""
        self._auth_result = None
        path = urlparse(self.path).path
        if platform_auth.is_public_path(path):
            return True
        query = parse_qs(urlparse(self.path).query)
        res = platform_auth.authenticate(self.headers, query)
        if res.ok:
            self._auth_result = res
            return True
        if res.status == 401:
            body = ("<h2 style='margin-top:0'>Authentication required</h2>"
                    f"<div class='err'>{html.escape(res.detail)}</div>"
                    "<p><a href='/portal/'>Sign in via the platform "
                    "portal</a>, then reopen this page.</p>")
        else:
            body = (f"<h2 style='margin-top:0'>{res.status}</h2>"
                    f"<div class='err'>{html.escape(res.detail)}</div>"
                    f"<p><a href='{html.escape(url('/'))}'>back</a></p>")
        self._send(res.status, page(f"{res.status}", body, public=True))
        return False

    # ---------------- GET ----------------

    def do_HEAD(self):
        """HEAD support (monitors/liveness probes): /health answers 200 with
        the same auth-free semantics as GET; everything else goes through
        the gate and answers with headers only."""
        path = urlparse(self.path).path
        if path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            return
        if path.startswith("/repo/") or path == "/repo":
            # static repo: existence check via directory walk is cheap
            self.send_response(200)
            self.end_headers()
            return
        if not self._gate():
            return  # _gate already sent the error status
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            env = r_adapter.environment_info()
            cfg = decision_mod.RuleSet.load()
            payload = {
                "status": "ok",
                "tool_version": __version__,
                "r_version": env.get("r_version"),
                "riskmetric_version": env.get("riskmetric_version"),
                "config_version": cfg.version,
                "auth_enabled": platform_auth.auth_enabled(),
                "base_path": base_path(),
            }
            self._send(200, json.dumps(payload).encode(), "application/json")
            return
        if path.startswith("/repo/") or path == "/repo":
            self._serve_repo(path)
            return
        if not self._gate():
            return
        if path == "/":
            self._send(200, _form_html(user=self._actor_name(),
                                       chain=self._chain()))
        elif path == "/dashboard":
            self._dashboard()
        elif path == "/api/assessments":
            self._api_assessments()
        elif path == "/api/inventory":
            self._api_inventory()
        elif path.startswith("/api/jobs/"):
            self._api_job(path)
        elif path.startswith("/jobs/"):
            self._job_page(path)
        elif path.startswith("/static/"):
            self._serve_static(path)
        elif path.startswith("/runs/"):
            self._serve_run_file(path)
        elif path == "/repo-view":
            self._repo_view()
        elif path == "/how-it-works":
            self._how_it_works()
        elif path.startswith("/report/") and path.endswith("/report.pdf"):
            self._serve_pdf(path)
        else:
            self._not_found(path)

    def _not_found(self, path: str):
        body = (f"<h2 style='margin-top:0'>404 — not found</h2>"
                f"<p>No route matches <code>{html.escape(path)}</code>.</p>"
                f"<p><a href='{html.escape(url('/'))}'>back to intake</a></p>")
        self._send(404, page("404", body, user=self._actor_name(),
                             chain=self._chain()))

    def _serve_pdf(self, path: str):
        m = re.fullmatch(r"/report/([A-Za-z0-9_.-]+)/report\.pdf", path)
        if not m:
            self._send(400, b"bad path", "text/plain")
            return
        pdf = pipeline.DEFAULT_DATA_DIR / "runs" / m.group(1) / "report" / "report.pdf"
        runs_root = (pipeline.DEFAULT_DATA_DIR / "runs").resolve()
        try:
            resolved = pdf.resolve()
            if runs_root not in resolved.parents or not resolved.is_file():
                raise ValueError
        except (OSError, ValueError):
            self._send(404, b"not found", "text/plain")
            return
        self._send(200, resolved.read_bytes(), "application/pdf")

    def _serve_static(self, path: str):
        """Vendored UI assets. Whitelisted file names only, with the same
        path-traversal containment check as /runs/ and /report/."""
        m = re.fullmatch(r"/static/([A-Za-z0-9_./-]+)", path)
        if not m or m.group(1) not in _STATIC_WHITELIST:
            self._send(404, b"not found", "text/plain")
            return
        root = STATIC_DIR.resolve()
        target = (root / m.group(1)).resolve()
        try:
            if root not in target.parents or not target.is_file():
                raise ValueError
        except (OSError, ValueError):
            self._send(404, b"not found", "text/plain")
            return
        ctype = _STATIC_WHITELIST[m.group(1)]
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        body = target.read_bytes()
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(body)

    # ---------------- dashboard + read-only JSON API (Phase B) ----------------

    def _dashboard(self):
        data = dash_mod.collect(pipeline.DEFAULT_DATA_DIR,
                                dash_mod.DEFAULT_INVENTORY)
        self._send(200, dash_mod.render_html(data, url,
                                             user=self._actor_name()))

    def _api_assessments(self):
        query = parse_qs(urlparse(self.path).query)
        try:
            limit = int(query.get("limit", ["100"])[0])
        except ValueError:
            limit = 100
        payload = dash_mod.assessments_tail(pipeline.DEFAULT_DATA_DIR, limit)
        self._send(200, json.dumps(payload, ensure_ascii=False).encode(),
                   "application/json")

    def _api_inventory(self):
        payload = dash_mod.inventory_join(pipeline.DEFAULT_DATA_DIR,
                                          dash_mod.DEFAULT_INVENTORY)
        self._send(200, json.dumps(payload, ensure_ascii=False).encode(),
                   "application/json")

    # ---------------- assessment jobs (async /assess) ----------------

    def _api_job(self, path: str):
        m = re.fullmatch(r"/api/jobs/([A-Za-z0-9_-]+)", path)
        job = jobs_mod.status(m.group(1)) if m else None
        if job is None:
            self._send(404, json.dumps(
                {"status": "lost",
                 "detail": "unknown job id — job state is in-memory only; "
                           "if the server restarted, please resubmit"}
            ).encode(), "application/json")
            return
        self._send(200, json.dumps(job, ensure_ascii=False).encode(),
                   "application/json")

    def _job_page(self, path: str):
        """Human-facing job page. Running jobs auto-refresh (meta refresh,
        no JS required); finished jobs render the report summary. With
        ?fragment=1 only the summary/result fragment is returned (the intake
        page's polling JS injects it in place)."""
        query = parse_qs(urlparse(self.path).query)
        fragment = query.get("fragment", [""])[0] == "1"
        m = re.fullmatch(r"/jobs/([A-Za-z0-9_-]+)", path)
        job = jobs_mod.status(m.group(1)) if m else None
        if job is None:
            body = ("<div class='gw-card'><div class='gw-err'><b>Job lost, "
                    "please resubmit.</b><br>Job state is kept in memory "
                    "only; a server restart clears it.</div>"
                    f"<p><a href='{html.escape(url('/'))}'>back to "
                    "intake</a></p></div>")
            if fragment:
                self._send(404, body.encode())
            else:
                self._send(404, page("job lost", f"<div class='gw-wrap "
                                     f"gw-wrap-narrow'>{body}</div>",
                                     active="intake",
                                     user=self._actor_name(),
                                     chain=self._chain()))
            return
        if job["status"] in ("queued", "running"):
            if fragment:
                self._send(202, b"<div class='gw-card'><span "
                                b"class='gw-spinner'></span> <b>Assessment "
                                b"running&hellip;</b></div>")
                return
            body = (f"<div class='gw-wrap gw-wrap-narrow'><div class='gw-card "
                    f"gw-empty'><span class='gw-spinner'></span> "
                    f"<h2>Assessment running&hellip;</h2>"
                    f"<p class='gw-note'>job <code>{job['job_id']}</code> — "
                    "R subprocess scoring plus evidence collection typically "
                    "takes 10–60 seconds. This page refreshes itself."
                    "</p></div></div>")
            self._send(202, page("assessment running", body, active="intake",
                                 user=self._actor_name(),
                                 chain=self._chain(),
                                 head_extra="<meta http-equiv='refresh' "
                                            "content='4'>"))
            return
        if job["status"] == "failed":
            body = (f"<div class='gw-card'><h2 style='margin-top:0'>"
                    f"Assessment failed</h2><div class='gw-err'><pre>"
                    f"{html.escape(job.get('error') or 'unknown error')}"
                    f"</pre></div>"
                    f"<p><a href='{html.escape(url('/'))}'>new assessment"
                    "</a></p></div>")
            if fragment:
                self._send(200, body.encode())
            else:
                self._send(200, page("assessment failed",
                                     f"<div class='gw-wrap gw-wrap-narrow'>"
                                     f"{body}</div>", active="intake",
                                     user=self._actor_name(),
                                     chain=self._chain()))
            return
        # done
        frag = self._job_result_fragment(job)
        if fragment:
            self._send(200, frag.encode())
        else:
            self._send(200, page("assessment result",
                                 f"<div class='gw-wrap gw-wrap-narrow'>"
                                 f"<div class='gw-pagehead'><h1>Assessment "
                                 f"result</h1></div>{frag}</div>",
                                 active="intake", user=self._actor_name(),
                                 chain=self._chain()))

    def _job_result_fragment(self, job: dict) -> str:
        """Report summary for a finished job: decision badge, subscores,
        report links and the publish / remediation action — the same content
        the old synchronous /assess rendered, now served per job."""
        run_id = job.get("run_id") or ""
        run_dir = pipeline.DEFAULT_DATA_DIR / "runs" / run_id
        try:
            decision_obj = json.loads(
                (run_dir / "decision.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            decision_obj = {}
        cats = {}
        try:
            score = json.loads(
                (run_dir / "score" / "score.json").read_text(
                    encoding="utf-8"))
            cats = score.get("category_scores") or {}
        except (OSError, json.JSONDecodeError):
            pass
        decision = decision_obj.get("decision")
        pkg = html.escape(str(job.get("package")))
        ver = html.escape(str(job.get("version")))
        tier = decision_obj.get("tier")

        head = (f"<div class='gw-card'><h2 style='margin-top:0'>"
                f"{pkg} {ver}</h2>"
                f"<p>{webui.decision_badge(decision)} &nbsp; "
                f"tier <code>{html.escape(str(tier))}</code> &nbsp; "
                f"overall risk score "
                f"{webui.score_bar(decision_obj.get('overall_score'))}</p>")
        if decision_obj.get("score_error"):
            head += (f"<p class='gw-note'>scoring degraded: "
                     f"{html.escape(str(decision_obj['score_error']))}</p>")
        head += "</div>"

        subscores = ""
        if cats:
            rows = "".join(
                f"<tr><td><b>{html.escape(str(c))}</b></td>"
                f"<td>{webui.score_bar(v.get('score'))}</td>"
                f"<td class='gw-note'>{v.get('scored', 0)} of "
                f"{len(v.get('metrics') or [])} metrics · weight "
                f"{html.escape(str(v.get('weight')))}</td></tr>"
                for c, v in cats.items())
            subscores = (f"<div class='gw-card'><h5 class='mt-0'>Category "
                         f"subscores</h5><table class='gw-table'>{rows}"
                         f"</table></div>")

        links = [f"<a href='{html.escape(url('/runs/' + run_id + '/report.html'))}'>"
                 "Full HTML report</a>"]
        if job.get("has_pdf"):
            links.append(
                f"<a href='{html.escape(url('/report/' + run_id + '/report.pdf'))}'>"
                "PDF report</a>")
        elif job.get("pdf_note"):
            links.append(f"<em>PDF not generated: "
                         f"{html.escape(str(job['pdf_note']))}</em>")
        links.append(f"<a href='{html.escape(url('/dashboard'))}'>Dashboard</a>")
        links_card = ("<div class='gw-card'><p>" + " · ".join(links) +
                      "</p></div>")

        # publish only when the decision permits (GO / CONDITIONS); gxp-
        # critical needs dual approval. NO-GO gets the remediation loop.
        if decision in ("GO", "GO-WITH-CONDITIONS"):
            action = ("<div class='gw-card'><h5 class='mt-0'>Publish to the "
                      "approved repository</h5>"
                      + _publish_form(pkg, ver, tier) + "</div>")
        else:
            action = (
                f"<div class='gw-card'><p><em>Publish unavailable: decision "
                f"{html.escape(str(decision))} does not permit repository "
                "publication (NO-GO escalates to Tier 2).</em></p>"
                + _remediation_form(pkg, ver, job.get("record_hash") or "")
                + "</div>")
        return head + subscores + links_card + action

    def _serve_run_file(self, path: str):
        """Read-only static serving of whitelisted run outputs. Same
        path-traversal protection as _serve_pdf."""
        m = re.fullmatch(r"/runs/([A-Za-z0-9_.-]+)/([A-Za-z0-9_./-]+)", path)
        if not m:
            self._send(400, b"bad path", "text/plain")
            return
        entry = _RUN_FILE_WHITELIST.get(m.group(2))
        if entry is None:
            self._send(404, b"not found", "text/plain")
            return
        rel, ctype = entry
        runs_root = (pipeline.DEFAULT_DATA_DIR / "runs").resolve()
        target = (runs_root / m.group(1) / rel).resolve()
        try:
            if runs_root not in target.parents or not target.is_file():
                raise ValueError
        except (OSError, ValueError):
            self._send(404, b"not found", "text/plain")
            return
        self._send(200, target.read_bytes(), ctype)

    def _serve_repo(self, path: str):
        """Read-only static serving of data/repo. No auth by design (see
        module docstring). Path-traversal safe."""
        rel = path[len("/repo"):].lstrip("/")
        root = repo_mod.repo_dir(pipeline.DEFAULT_DATA_DIR).resolve()
        target = (root / rel).resolve()
        if root != target and root not in target.parents:
            self._send(400, b"bad path", "text/plain")
            return
        if target.is_dir():
            target = target / "PACKAGES" if (target / "PACKAGES").is_file() \
                else target
            if target.is_dir():
                self._send(404, b"not found", "text/plain")
                return
        if not target.is_file():
            self._send(404, b"not found", "text/plain")
            return
        ctype = ("application/gzip" if target.name.endswith(".gz")
                 else "text/plain" if target.suffix in ("", ".json", ".md")
                 else "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    def _repo_view(self):
        m = repo_mod.list_repo(pipeline.DEFAULT_DATA_DIR)
        rows = []
        for a in m.get("artifacts", []):
            gaps = a.get("dependency_gaps", {})
            missing = ", ".join(gaps.get("missing", [])) or "—"
            rows.append(
                f"<tr><td><b>{html.escape(a['package'])}</b></td>"
                f"<td>{html.escape(a['version'])}</td>"
                f"<td>{html.escape(a['flavor'])}</td>"
                f"<td><code>{a['sha256'][:12]}…</code></td>"
                f"<td>{webui.decision_badge(a.get('assessment_decision') or None)}</td>"
                f"<td>{html.escape(missing)}</td>"
                f"<td>{html.escape(a.get('published_at', ''))}</td></tr>")
        table = ("<div class='gw-table-wrap'><table class='gw-table'>"
                 "<thead><tr><th>Package</th><th>Version</th><th>Flavor</th>"
                 "<th>sha256</th><th>Gating decision</th>"
                 "<th>Missing deps (need own assessment)</th>"
                 "<th>Published</th></tr></thead><tbody>"
                 + "\n".join(rows) + "</tbody></table></div>"
                 if rows else
                 "<div class='gw-card gw-empty'><em>Repository is empty — "
                 "publish a passing assessment first.</em></div>")
        body = (f"<div class='gw-wrap'><div class='gw-pagehead'>"
                f"<h1>Approved-package repository</h1>"
                f"<p class='gw-note'>Only packages with a GO / "
                f"GO-WITH-CONDITIONS assessment on record can be published. "
                f"Artifacts are served read-only at "
                f"<code>{html.escape(url('/repo/'))}</code> "
                f"(unauthenticated: image builds cannot perform SSO; the "
                f"repo contains approved artifacts only).</p></div>"
                f"{table}</div>")
        self._send(200, page("repository", body, active="repository",
                             user=self._actor_name(), chain=self._chain()))

    # ---------------- how it works ----------------

    def _how_it_works(self):
        cfg = decision_mod.RuleSet.load()
        e = html.escape

        steps = [
            ("Ingest", "CRAN name, GitHub URL or uploaded source tarball; "
             "versions resolve against the pinned CRAN snapshot and every "
             "tarball is sha256-fingerprinted."),
            ("Score", "An R subprocess runs {riskmetric} 0.2.7 (17 risk "
             "metrics). Two-process pattern: the gateway never executes "
             "assessed package code — coverage and R CMD check metrics are "
             "deliberately excluded."),
            ("Evidence", "Every collected value — CRAN metadata, community "
             "signals, scores — is bound to an evidence ID. Network source "
             "failures degrade explicitly, never silently."),
            ("Decide", "A versioned, sha256-recorded rule config maps the "
             "overall score to GO / GO-WITH-CONDITIONS / NO-GO per "
             "intended-use tier, plus per-metric rules that attach "
             "conditions. Every rule, fired or not, is shown in the report."),
            ("Report", "Evidence-linked HTML + PDF: no statement without an "
             "evidence ID; sections lacking evidence render suppressed "
             "instead of fabricated."),
            ("Audit", "Every assessment, signature, publish and remediation "
             "joins an append-only, hash-chained audit log; the dashboard "
             "verifies the chain on every view."),
        ]
        steps_html = "".join(
            f"<div class='gw-step'><span class='n'>{i}</span>"
            f"<div class='t'>{e(t)}</div><div class='d'>{e(d)}</div></div>"
            for i, (t, d) in enumerate(steps, 1))

        tier_rows = []
        tier_blurb = {
            "exploratory": "research / non-GxP work",
            "gxp-support": "output feeds GxP workflows but is not itself "
                           "the record of truth",
            "gxp-critical": "on the critical path of a regulated decision — "
                            "GO is unreachable by design (human gate)",
        }
        for tier in ("exploratory", "gxp-support", "gxp-critical"):
            th = cfg.tiers.get(tier) or {}
            low = th.get("low")
            tier_rows.append(
                f"<tr><td><code>{e(tier)}</code></td>"
                f"<td>{e(tier_blurb.get(tier, ''))}</td>"
                f"<td>GO below <b>{low if low is not None else '—'}</b></td>"
                f"<td>NO-GO at/above <b>{th.get('high')}</b></td></tr>")
        tier_table = (
            "<table class='gw-table'><thead><tr><th>Tier</th><th>Meaning</th>"
            "<th>GO band (overall risk)</th><th>NO-GO threshold</th></tr>"
            f"</thead><tbody>{''.join(tier_rows)}</tbody></table>")

        cat_rows = "".join(
            f"<tr><td><b>{e(cat)}</b></td><td>{e(str(c.get('weight')))}</td>"
            f"<td>{e(str(len(c.get('metrics') or [])))} metrics "
            f"<span class='gw-note'>({e(', '.join(c.get('metrics') or []))}"
            f")</span></td></tr>"
            for cat, c in cfg.category_weights.items())
        cat_table = (
            "<table class='gw-table'><thead><tr><th>Category</th>"
            "<th>Strategy weight</th><th>Member metrics</th></tr></thead>"
            f"<tbody>{cat_rows}</tbody></table>")

        n_rules = len(cfg.metric_rules)
        n_crit = sum(1 for r in cfg.metric_rules
                     if r.get("severity") == "critical")

        body = f"""
<div class="gw-wrap">
 <div class="gw-pagehead">
  <h1>How the gateway works</h1>
  <p class="gw-note">Tier-1 screening for R packages under a two-tier
  validation strategy: this tool screens everything, Tier 2 (full
  validation) receives only what fails or is business-critical.</p>
 </div>

 <div class="gw-card">
  <h5 class="mt-0">The assessment pipeline</h5>
  <div class="gw-steps">{steps_html}</div>
 </div>

 <div class="gw-card">
  <h5 class="mt-0">How the score is built</h5>
  <p>The overall risk score (0 = low risk, 1 = high risk) is
  <code>{{riskmetric}}</code>'s weighted mean of 17 per-metric scores,
  computed in an isolated R subprocess. For transparency the report also
  discloses category subscores — each the equal-weighted mean of its member
  metrics — with the rubric's strategy weights (config v{e(cfg.version)},
  sha256 <code class='evid'>{e(cfg.sha256[:12])}…</code>):</p>
  {cat_table}
  <p class="gw-note">Category subscores are display-only disclosure; the
  overall score and the tier thresholds are the decision inputs.</p>
 </div>

 <div class="gw-card">
  <h5 class="mt-0">Decisions are tier-relative, never black-box</h5>
  {tier_table}
  <p>On top of the score bands, {n_rules} per-metric rules
  ({n_crit} critical severity) attach conditions or force escalation — e.g.
  unresolved bug trackers, missing source control, non-standard licenses,
  low community usage. Any non-GO outcome in
  <code>gxp-critical</code> additionally carries the mandatory human-gate
  conditions (independent verification, double programming).</p>
 </div>

 <div class="gw-card">
  <h5 class="mt-0">Governance muscle (GxP)</h5>
  <ul>
   <li><b>Evidence-bound reporting</b> — no statement without an evidence
   ID; missing evidence suppresses the section rather than fabricating.</li>
   <li><b>Tamper-evident audit chain</b> — append-only, hash-chained;
   verification status is on every page footer and the dashboard.</li>
   <li><b>21 CFR Part 11 e-signatures</b> — publishing requires
   re-authentication at signing time; <code>gxp-critical</code> requires two
   distinct signers (dual approval).</li>
   <li><b>Approved-package repository</b> — platform image builds can only
   install packages with a passing assessment; dependency gaps need their
   own assessments (chain gating).</li>
   <li><b>Staleness detection</b> — version/config/snapshot drift flags
   packages for re-assessment on the dashboard.</li>
  </ul>
 </div>

 <div class="gw-card">
  <h5 class="mt-0">Why this helps the team — and how it compares to vendor
  validation</h5>
  <p>Vendor offerings such as Atorus <b>OpenVal</b>, Appsilon
  <b>Axon.R</b> and Jumping Rivers <b>Litmus</b> sell per-package
  validation: deep, service-delivered qualification of individual packages,
  priced per engagement. They answer "is <em>this</em> package validated?"
  one package at a time.</p>
  <p>This gateway answers the portfolio question continuously and in-house:
  <em>every</em> package in the platform inventory gets the same
  evidence-bound screen, a tamper-evident audit trail, and a governed
  path into the approved repository. That changes the economics and the
  inspection posture:</p>
  <ul>
   <li><b>Coverage</b> — the whole inventory is screened on every snapshot,
   not just the packages someone remembered to submit.</li>
   <li><b>Targeting</b> — Tier-2 effort (internal PQ or a vendor engagement)
   goes only to NO-GO and gxp-critical packages, with the screening evidence
   already assembled.</li>
   <li><b>Enforcement</b> — unassessed packages physically cannot enter
   platform images, so process compliance does not depend on discipline
   alone.</li>
   <li><b>Inspection readiness</b> — one dashboard answers the three
   questions an inspector asks: which packages, what risk, and who approved
   what when on which evidence.</li>
  </ul>
  <p class="gw-note">This tool never signs off and does not replace Tier-2
  full validation; it makes that effort targeted, repeatable and auditable.
  Classification and sign-off stay with human QA.</p>
 </div>
</div>
"""
        self._send(200, page("How it works", body, active="about",
                             user=self._actor_name(), chain=self._chain()))

    # ---------------- POST ----------------

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/assess", "/publish", "/remediate"):
            self._send(404, b"not found", "text/plain")
            return
        if not self._gate():
            return
        if path == "/assess":
            self._do_assess()
        elif path == "/publish":
            self._do_publish()
        else:
            self._do_remediate()

    def _read_fields(self):
        ctype = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        if ctype.startswith("multipart/form-data"):
            fields = _parse_multipart(body, ctype)
            get = lambda k: (fields.get(k) or (None, b""))[1].decode(
                "utf-8", "replace").strip()
            return get, fields.get("tarball")
        q = parse_qs(body.decode("utf-8", "replace"))
        return (lambda k: q.get(k, [""])[0].strip()), None

    def _do_assess(self):
        """Validate, enqueue and answer 202 — the pipeline runs on a
        background thread (jobs.py); the client polls /api/jobs/<job_id>
        (or lands on the self-refreshing /jobs/<job_id> page)."""
        get, upload = self._read_fields()
        tier = get("tier") or "exploratory"
        if tier not in decision_mod.TIERS:
            tier = "exploratory"

        intended_use = get("intended_use")
        justification = get("justification")
        if tier == "gxp-critical" and not (intended_use and justification):
            self._send(400, page(
                "classification required",
                "<h2 style='margin-top:0'>400 — classification required</h2>"
                "<div class='gw-err'>tier <code>gxp-critical</code> "
                "requires both <code>intended_use</code> and "
                "<code>justification</code>: a package on the critical path "
                "of a regulated decision must carry a recorded intended use "
                "and its justification.</div>"
                f"<p><a href='{html.escape(url('/'))}'>back</a></p>",
                active="intake", user=self._actor_name(),
                chain=self._chain()))
            return
        classification = None
        if intended_use or justification:
            classification = {"intended_use": intended_use or None,
                              "justification": justification or None}

        try:
            if upload and upload[0]:
                tmp = Path(tempfile.mkdtemp(prefix="rval_upload_"))
                safe_name = Path(upload[0]).name
                if not safe_name.endswith((".tar.gz", ".tgz")):
                    raise ValueError("upload must be a .tar.gz package "
                                     "tarball")
                tmp_upload = tmp / safe_name
                tmp_upload.write_bytes(upload[1])
                spec = {"upload_path": str(tmp_upload)}
            elif get("pkg"):
                spec = {"package": get("pkg"),
                        "version": get("version") or None}
            elif get("github"):
                spec = {"github_url": get("github"),
                        "ref": get("ref") or None}
            else:
                self._send(400, b"no package source given", "text/plain")
                return
            spec = {k: v for k, v in spec.items() if v}
        except ValueError as e:
            self._send(400, page(
                "bad request",
                f"<h2 style='margin-top:0'>400</h2><div class='gw-err'>"
                f"{html.escape(str(e))}</div>"
                f"<p><a href='{html.escape(url('/'))}'>back</a></p>",
                active="intake", user=self._actor_name(),
                chain=self._chain()))
            return

        actor = getattr(self, "_auth_result", None)
        try:
            job = jobs_mod.submit(spec, tier,
                                  actor.user_id if actor else None,
                                  classification, pipeline.run_assessment)
        except jobs_mod.BusyError:
            body = ("<h2 style='margin-top:0'>429 — server busy</h2>"
                    f"<div class='gw-err'>at most {jobs_mod.MAX_CONCURRENT} "
                    "assessments run concurrently; wait for one to finish "
                    "and resubmit.</div>"
                    f"<p><a href='{html.escape(url('/'))}'>back</a></p>")
            if "application/json" in self.headers.get("Accept", ""):
                self._send(429, json.dumps(
                    {"status": "busy",
                     "detail": f"at most {jobs_mod.MAX_CONCURRENT} "
                               "concurrent assessments"}).encode(),
                    "application/json")
            else:
                self._send(429, page("server busy", body, active="intake",
                                     user=self._actor_name(),
                                     chain=self._chain()))
            return

        payload = {"job_id": job["job_id"], "status": job["status"],
                   "status_url": url(f"/api/jobs/{job['job_id']}"),
                   "page_url": url(f"/jobs/{job['job_id']}")}
        if "application/json" in self.headers.get("Accept", ""):
            self._send(202, json.dumps(payload).encode(), "application/json")
            return
        # no-JS browsers land on the self-refreshing job page
        wait = (f"<div class='gw-wrap gw-wrap-narrow'><div class='gw-card "
                f"gw-empty'><span class='gw-spinner'></span> "
                f"<h2>Assessment queued&hellip;</h2>"
                f"<p class='gw-note'>job <code>{job['job_id']}</code> — this "
                f"page forwards to the self-refreshing job page.</p>"
                f"<p><a href='{html.escape(payload['page_url'])}'>job status"
                f" page</a></p></div></div>")
        self._send(202, page("assessment queued", wait, active="intake",
                             user=self._actor_name(), chain=self._chain(),
                             head_extra=(
                                 "<meta http-equiv='refresh' content='2; url="
                                 f"{html.escape(payload['page_url'])}'>")))

    def _do_publish(self):
        get, _ = self._read_fields()
        package, version = get("package"), get("version")
        binary = get("binary") in ("1", "on", "true")
        signers = []
        for suffix in ("", "2"):
            s, p = get(f"esign_signer{suffix}"), get(f"esign_password{suffix}")
            if s:
                signers.append((s, p))
        if not package or not version:
            self._send(400, page("publish",
                                 "<h2 style='margin-top:0'>400</h2>"
                                 "<p>package and version are required.</p>",
                                 user=self._actor_name(),
                                 chain=self._chain()))
            return
        try:
            res = repo_mod.publish(package, version, binary=binary,
                                   data_dir=pipeline.DEFAULT_DATA_DIR,
                                   signers=signers)
        except repo_mod.RepoError as e:
            body = (f"<h2 style='margin-top:0'>Publish refused</h2>"
                    f"<div class='gw-err'>{html.escape(str(e))}</div>"
                    f"<p><a href='{html.escape(url('/repo-view'))}'>repository</a> · "
                    f"<a href='{html.escape(url('/'))}'>new assessment</a></p>")
            self._send(403, page("publish refused", body,
                                 user=self._actor_name(),
                                 chain=self._chain()))
            return
        gaps = res["dependency_gaps"]
        missing = "".join(f"<li><code>{html.escape(d)}</code> — needs its own "
                          "assessment + publish (chain gating)</li>"
                          for d in gaps["missing"]) or "<li>none</li>"
        fallback = (f"<p><em>{html.escape(res['binary_fallback'])}</em></p>"
                    if res.get("binary_fallback") else "")
        sig_items = "".join(
            f"<li>signed by <b>{html.escape(s['signer_id'])}</b>, "
            f"signature record <code>{s['record_hash'][:16]}…</code></li>"
            for s in res["esign_signatures"])
        body = (f"<div class='gw-wrap gw-wrap-narrow'><div class='gw-pagehead'>"
                f"<h1>Published</h1></div><div class='gw-card'><div class='gw-ok'>"
                f"{html.escape(package)} {html.escape(version)} "
                f"({res['flavor']}) is now served at "
                f"<code>{html.escape(url('/repo/src/contrib/'))}</code>"
                f"</div>{fallback}"
                f"<p>Artifact sha256: <code>{res['sha256'][:16]}…</code>; "
                f"audit record <code>{res['audit_record_hash'][:16]}…</code>; "
                f"index stanzas: {res['index_stanzas']}.</p>"
                f"<p><b>Electronic signature(s)</b> (21 CFR Part 11): "
                f"meaning <b>{html.escape(res.get('esign_meaning') or 'approved')}</b>, "
                "each signer re-authenticated at signing time:</p>"
                f"<ul>{sig_items}</ul>"
                f"<h5>Dependency gaps</h5><ul>{missing}</ul>"
                f"<p><a href='{html.escape(url('/repo-view'))}'>repository view</a> · "
                f"<a href='{html.escape(url('/'))}'>new assessment</a></p>"
                f"</div></div>")
        self._send(200, page("published", body, user=self._actor_name(),
                             chain=self._chain()))

    def _do_remediate(self):
        """Attach a free-text remediation note to a NO-GO assessment. The
        note joins the audit chain (record_type ``remediation``) linked to
        the assessment by its record_hash; notes are append-only."""
        get, _ = self._read_fields()
        package, version = get("package"), get("version")
        ref, note = get("assessment_record_hash"), get("note")
        if not (package and ref and note):
            self._send(400, page("remediation",
                                 "<h2 style='margin-top:0'>400</h2>"
                                 "<p>package, assessment_record_hash and a "
                                 "non-empty note are required.</p>",
                                 user=self._actor_name(),
                                 chain=self._chain()))
            return
        records = dash_mod.read_audit_records(pipeline.DEFAULT_DATA_DIR)
        target = next((r for r in records
                       if r.get("record_hash") == ref), None)
        if (target is None or target.get("record_type") != "assessment"
                or target.get("package") != package
                or (version and target.get("version") != version)):
            body = ("<h2 style='margin-top:0'>Remediation refused</h2>"
                    "<div class='gw-err'>the referenced assessment record "
                    "was not found in the audit chain for this "
                    "package/version.</div>"
                    f"<p><a href='{html.escape(url('/'))}'>back</a></p>")
            self._send(403, page("remediation refused", body,
                                 user=self._actor_name(),
                                 chain=self._chain()))
            return
        if target.get("decision") != "NO-GO":
            body = ("<h2 style='margin-top:0'>Remediation refused</h2>"
                    "<div class='gw-err'>remediation notes attach to NO-GO "
                    "assessments only; the referenced assessment's decision "
                    f"is {html.escape(str(target.get('decision')))}.</div>"
                    f"<p><a href='{html.escape(url('/'))}'>back</a></p>")
            self._send(403, page("remediation refused", body,
                                 user=self._actor_name(),
                                 chain=self._chain()))
            return
        actor = getattr(self, "_auth_result", None)
        log = audit_mod.AuditLog(pipeline.DEFAULT_DATA_DIR / "audit"
                                 / "assessments.jsonl")
        rec = log.append(audit_mod.make_remediation_record(
            package=package, version=target.get("version") or version,
            assessment_record_hash=ref, note=note,
            actor=actor.user_id if actor else None))
        body = (f"<div class='gw-wrap gw-wrap-narrow'><div class='gw-pagehead'>"
                f"<h1>Remediation recorded</h1></div><div class='gw-card'>"
                f"<div class='gw-ok'>note appended to the audit chain for "
                f"<code>{html.escape(package)} "
                f"{html.escape(str(target.get('version') or version))}</code>, "
                f"linked to NO-GO assessment <code>{ref[:16]}…</code>; "
                f"record <code>{rec['record_hash'][:16]}…</code>.</div>"
                f"<p>{html.escape(note)}</p>"
                f"<p><a href='{html.escape(url('/dashboard'))}'>dashboard</a> · "
                f"<a href='{html.escape(url('/'))}'>new assessment</a></p>"
                f"</div></div>")
        self._send(200, page("remediation recorded", body,
                             user=self._actor_name(), chain=self._chain()))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="R Package Validation Gateway server")
    ap.add_argument("--host", default=os.environ.get("GATEWAY_HOST", BIND_HOST),
                    help="bind address (default 127.0.0.1; env GATEWAY_HOST)")
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("GATEWAY_PORT", DEFAULT_PORT)),
                    help="port (default 8788; env GATEWAY_PORT)")
    args = ap.parse_args(argv)
    warn = platform_auth.dev_mode_warning()
    if warn:
        print(f"[gateway] *** WARNING: {warn} ***", file=sys.stderr)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[gateway] WARNING: binding {args.host} exposes the service "
              "beyond localhost — intended only inside a container with a "
              "localhost-mapped port", file=sys.stderr)
    srv = ThreadingHTTPServer((args.host, args.port), GatewayHandler)
    print(f"[gateway] serving on http://{args.host}:{args.port} "
          f"(base path {base_path()}, auth "
          f"{'on' if platform_auth.auth_enabled() else 'OFF (dev)'})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
