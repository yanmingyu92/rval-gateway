"""decision.py — config-driven GO / GO-WITH-CONDITIONS / NO-GO decision engine.

Config model adopted from {riskassessment}'s db-config pattern (score-range
rules per decision category + per-metric expression rules), extended with
intended-use tiers (exploratory / gxp-support / gxp-critical). The config is
YAML (parsed by gateway.miniyaml) and versioned (``config_version`` + sha256
of the file recorded in every output).

Semantics per tier (see config/decision_rules.yml header for the rationale):

- exploratory: GO if overall < low; GO-WITH-CONDITIONS if overall < high
  (conditions from fired metric rules); else NO-GO.
- gxp-support: stricter thresholds; any fired critical metric rule forces at
  least GO-WITH-CONDITIONS; overall >= high -> NO-GO (escalate to Tier 2).
- gxp-critical: NEVER auto-GO. Best outcome is GO-WITH-CONDITIONS with the
  mandatory human-gate conditions from the config; overall >= high -> NO-GO
  (escalate to Tier 2 full validation).

The output lists every rule evaluated — fired or not — with its input value
and threshold. No black-box verdicts.

stdlib only.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from . import miniyaml

DECISIONS = ("GO", "GO-WITH-CONDITIONS", "NO-GO")
TIERS = ("exploratory", "gxp-support", "gxp-critical")

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config" / "decision_rules.yml"


class DecisionError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_OPS = {
    "<": lambda v, t: v < t,
    "<=": lambda v, t: v <= t,
    ">": lambda v, t: v > t,
    ">=": lambda v, t: v >= t,
    "==": lambda v, t: v == t,
}


class RuleSet:
    def __init__(self, config: dict, config_sha256: str, config_path: str):
        self.config = config
        self.sha256 = config_sha256
        self.path = config_path
        self.version = str(config.get("config_version", "unknown"))
        self.tiers = config.get("tiers") or {}
        self.metric_rules = config.get("metric_rules") or []
        self.critical_tier_conditions = config.get("critical_tier_conditions") or []
        self.category_weights = config.get("category_weights") or {}

    @classmethod
    def load(cls, path: str | Path = DEFAULT_CONFIG) -> "RuleSet":
        p = Path(path)
        raw = p.read_bytes()
        config = miniyaml.load(raw.decode("utf-8"))
        if not isinstance(config, dict) or "tiers" not in config:
            raise DecisionError(f"invalid decision-rule config: {p}")
        for tier in TIERS:
            if tier not in config["tiers"]:
                raise DecisionError(f"config missing tier {tier!r}")
        return cls(config, hashlib.sha256(raw).hexdigest(), str(p))


def _build_index(evidence: dict) -> dict:
    return {e["metric"]: e.get("value") for e in evidence.get("entries", [])}


def category_scores(metric_scores: dict | None, category_weights: dict) -> dict:
    """Per-category subscores (display-only; never feed the decision).

    ``category_weights`` maps category name -> {weight, metrics: [names]}
    (the ``category_weights`` section of the decision-rule config). Each
    subscore is the equal-weighted mean of the member metrics' non-null
    riskmetric scores; a category with no measurable members gets None.
    Returns {category: {weight, score, metrics, scored}} in config order.
    """
    metric_scores = metric_scores or {}
    out = {}
    for cat, cspec in (category_weights or {}).items():
        if not isinstance(cspec, dict):
            continue
        members = [str(m) for m in (cspec.get("metrics") or [])]
        vals = [metric_scores[m] for m in members
                if isinstance(metric_scores.get(m), (int, float))]
        out[cat] = {
            "weight": cspec.get("weight"),
            "score": (sum(vals) / len(vals)) if vals else None,
            "metrics": members,
            "scored": len(vals),
        }
    return out


def evaluate_metric_rules(ruleset: RuleSet, index: dict) -> list[dict]:
    """Evaluate every metric rule; each result carries its inputs."""
    out = []
    for rule in ruleset.metric_rules:
        rid = rule.get("id", "?")
        metric = rule.get("metric")
        op = rule.get("op")
        threshold = rule.get("value")
        value = index.get(metric)
        fired = False
        applicable = True
        if op == "is_na":
            fired = metric not in index or value is None
        elif op == "not_na":
            fired = metric in index and value is not None
        elif op in _OPS:
            if value is None or not isinstance(value, (int, float)):
                applicable = False  # no input -> rule cannot fire, still shown
            else:
                fired = bool(_OPS[op](value, threshold))
        else:
            raise DecisionError(f"rule {rid!r}: unsupported op {op!r}")
        out.append({
            "id": rid,
            "metric": metric,
            "op": op,
            "threshold": threshold,
            "input": value,
            "applicable": applicable,
            "fired": fired,
            "severity": rule.get("severity", "warn"),
            "condition": rule.get("condition", ""),
        })
    return out


def decide(overall_score, tier: str, evidence: dict,
           ruleset: RuleSet | None = None) -> dict:
    """Produce the decision object for one assessment."""
    ruleset = ruleset or RuleSet.load()
    if tier not in TIERS:
        raise DecisionError(f"unknown tier {tier!r}; expected one of {TIERS}")
    band = ruleset.tiers[tier]
    low = band.get("low")
    high = band.get("high")
    if high is None:
        raise DecisionError(f"tier {tier!r} must define a 'high' threshold")

    index = _build_index(evidence)
    rule_results = evaluate_metric_rules(ruleset, index)
    fired = [r for r in rule_results if r["fired"]]
    fired_critical = [r for r in fired if r["severity"] == "critical"]
    conditions = [r["condition"] for r in fired if r.get("condition")]

    score_ok = overall_score is not None

    threshold_rule = None
    if not score_ok:
        decision = "NO-GO"
        threshold_rule = {
            "id": "overall_score_available",
            "metric": "riskmetric.overall_score",
            "op": "not_na",
            "threshold": None,
            "input": overall_score,
            "fired": True,
            "severity": "critical",
            "condition": "No overall risk score could be computed — cannot screen.",
        }
        conditions.append(threshold_rule["condition"])
    elif tier == "exploratory":
        if overall_score < low:
            decision = "GO"
        elif overall_score < high:
            decision = "GO-WITH-CONDITIONS"
        else:
            decision = "NO-GO"
    elif tier == "gxp-support":
        if overall_score >= high:
            decision = "NO-GO"
        elif overall_score < low and not fired_critical:
            decision = "GO"
        else:
            # in the middle band, or a critical metric rule fired
            decision = "GO-WITH-CONDITIONS"
    else:  # gxp-critical — NEVER auto-GO
        if overall_score >= high:
            decision = "NO-GO"
        else:
            decision = "GO-WITH-CONDITIONS"
        conditions = list(ruleset.critical_tier_conditions) + conditions

    if decision == "NO-GO":
        conditions.append(
            "Escalate to Tier 2 full validation (vendor-style qualification) "
            "before any use in this intended-use tier.")

    threshold_eval = {
        "id": "overall_score_threshold",
        "metric": "riskmetric.overall_score",
        "tier": tier,
        "input": overall_score,
        "low_threshold": low,
        "high_threshold": high,
        "fired": decision != "GO" if tier != "gxp-critical" else True,
        "note": ("gxp-critical never auto-GOs; best outcome is "
                 "GO-WITH-CONDITIONS with human gate" if tier == "gxp-critical"
                 else "score-range rule per tier band"),
    }

    return {
        "decision": decision,
        "tier": tier,
        "overall_score": overall_score,
        "rules_evaluated": ([threshold_rule] if threshold_rule else [])
                           + [threshold_eval] + rule_results,
        "fired_rules": [r["id"] for r in fired],
        "conditions": conditions,
        "config_version": ruleset.version,
        "config_sha256": ruleset.sha256,
        "config_path": ruleset.path,
        "decided_at": _now(),
    }
