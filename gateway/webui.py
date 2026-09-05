"""webui.py — shared page skeleton + visual components for the gateway UI.

Every server-rendered page (server.py routes, dashboard.py) uses the same
skeleton: sticky top navigation (brand + Intake/Dashboard/Repository + the
authenticated user), a content area, and a footer with the tool version and
audit-chain status. Styling comes from the vendored assets under the gated
/static/ route (bootstrap + bootstrap-icons + gateway.css design tokens).

public=True pages (authentication errors) cannot load the gated /static/
assets — the request was refused, after all — so they get a compact inline
subset of the design tokens instead. Everything else stays external-CSS-only:
no inline style strings in route handlers.

stdlib only.
"""

from __future__ import annotations

import html

from . import __version__

TOOL_NAME = "R Package Validation Gateway"

_NAV_ITEMS = (("intake", "/", "Intake"),
              ("dashboard", "/dashboard", "Dashboard"),
              ("repository", "/repo-view", "Repository"),
              ("about", "/how-it-works", "How it works"))

# Compact inline fallback for public (unauthenticated) error pages — the
# gated /static/ assets are unreachable there. Tokens mirror gateway.css.
_PUBLIC_CSS = """
 body { font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto,
        Arial, sans-serif; background: #f4f3f0; color: #2d2926; margin: 0;
        display: flex; min-height: 100vh; align-items: center;
        justify-content: center; }
 .box { background: #fff; border: 1px solid #d8d5d0; border-radius: 16px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.06); max-width: 560px;
        padding: 2em 2.4em; margin: 1em; }
 h1 { font-family: Georgia, 'Times New Roman', serif; color: #8B002E;
      font-size: 1.4em; margin: 0 0 .4em; }
 .err { background: #fbe3e3; border: 1px solid #f0b4b4;
        border-left: 4px solid #b91c1c; padding: 12px 16px;
        border-radius: 12px; margin: 1em 0; }
 a { color: #C4004A; }
 .note { font-size: .85em; color: #6b6560; }
 code { background: #edecea; padding: 0 4px; border-radius: 4px; }
"""


def _esc(s) -> str:
    return html.escape(str(s))


def _static_url(url, name: str) -> str:
    """Versioned static URL: the ?v= query busts the 1h cache on deploys."""
    return f"{url('/static/' + name)}?v={__version__}"


def page(title: str, body: str, url, *, active: str = "", user=None,
         chain: dict | None = None, public: bool = False,
         head_extra: str = "") -> bytes:
    """Wrap ``body`` in the shared skeleton. ``url`` prefixes generated
    links with the configured base path (server.url)."""
    full_title = f"{TOOL_NAME} — {title}" if title else TOOL_NAME
    if public:
        doc = ("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
               "<meta name='viewport' content='width=device-width, "
               "initial-scale=1'>"
               f"<title>{_esc(full_title)}</title><style>{_PUBLIC_CSS}</style>"
               "</head><body><div class='box'>"
               f"<h1>{_esc(TOOL_NAME)}</h1>{body}</div></body></html>")
        return doc.encode("utf-8")

    nav = "".join(
        f"<a href='{_esc(url(path))}'{' class=active' if key == active else ''}"
        f">{_esc(label)}</a>"
        for key, path, label in _NAV_ITEMS)
    user_chip = ("<span class='gw-user'><i class='bi bi-person-circle'></i>"
                 f"{_esc(user)}</span>" if user else "")
    if chain is None:
        chain_html = "audit chain: <em>unavailable</em>"
    elif chain.get("ok"):
        chain_html = (f"audit chain: <span class='gw-badge gw-badge-go'>"
                      f"intact</span> {int(chain.get('records', 0))} records")
    else:
        chain_html = ("audit chain: <span class='gw-badge gw-badge-nogo'>"
                      "BROKEN</span>")
    footer = (f"<footer class='gw-footer'><span>rval-gateway "
              f"{_esc(__version__)} (Python stdlib)</span>"
              f"<span>{chain_html}</span>"
              "<span>Tier-1 screening — classification and sign-off stay "
              "with human QA.</span></footer>")
    doc = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{_esc(full_title)}</title>"
        f"<link rel='icon' type='image/svg+xml' href='{_esc(_static_url(url, 'favicon.svg'))}'>"
        f"<link rel='stylesheet' href='{_esc(_static_url(url, 'bootstrap.min.css'))}'>"
        f"<link rel='stylesheet' href='{_esc(_static_url(url, 'bootstrap-icons.css'))}'>"
        f"<link rel='stylesheet' href='{_esc(_static_url(url, 'gateway.css'))}'>"
        f"{head_extra}</head><body>"
        f"<nav class='gw-topnav'><span class='gw-brand'>"
        f"<img src='{_esc(_static_url(url, 'favicon.svg'))}' alt=''>"
        f"{_esc(TOOL_NAME)}</span>"
        f"<span class='gw-nav'>{nav}</span>{user_chip}</nav>"
        f"{body}{footer}</body></html>")
    return doc.encode("utf-8")


def decision_badge(decision: str | None) -> str:
    if decision == "GO":
        return "<span class='gw-badge gw-badge-go'>GO</span>"
    if decision == "GO-WITH-CONDITIONS":
        return ("<span class='gw-badge gw-badge-cond'>"
                "GO-WITH-CONDITIONS</span>")
    if decision == "NO-GO":
        return "<span class='gw-badge gw-badge-nogo'>NO-GO</span>"
    return "<span class='gw-badge gw-badge-none'>unassessed</span>"


def score_bar(score, low: float = 0.4, high: float = 0.7) -> str:
    """Small CSS risk bar: 0 = low risk (green) .. 1 = high risk (red).
    Neutral banding only — decision thresholds stay config-driven."""
    if not isinstance(score, (int, float)):
        return "<span class='gw-muted'>—</span>"
    pct = max(0.0, min(1.0, float(score))) * 100
    cls = "low" if score <= low else "mid" if score <= high else "high"
    return (f"<span class='gw-score'><span class='track'>"
            f"<span class='fill {cls}' style='width:{pct:.1f}%'></span>"
            f"</span><span class='val'>{score:.4f}</span></span>")
