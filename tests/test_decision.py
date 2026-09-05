"""Tests for gateway.decision — fully offline."""

import unittest

from gateway import decision
from gateway.decision import RuleSet


def make_evidence(overall=None, metrics=None):
    entries = []
    if overall is not None:
        entries.append({"evidence_id": "EV-001", "metric": "riskmetric.overall_score",
                        "value": overall, "source": "test", "mode": "riskmetric",
                        "collected_at": "t"})
    for i, (m, v) in enumerate((metrics or {}).items(), start=2):
        # keys already containing a dot-path collector prefix are used as-is
        metric = m if "." in m else f"riskmetric.score.{m}"
        entries.append({"evidence_id": f"EV-{i:03d}", "metric": metric,
                        "value": v, "source": "test", "mode": "riskmetric",
                        "collected_at": "t"})
    return {"entries": entries}


class TestConfigLoad(unittest.TestCase):
    def test_default_config_loads(self):
        rs = RuleSet.load()
        self.assertRegex(rs.version, r"^\d+\.\d+\.\d+$")
        self.assertEqual(len(rs.sha256), 64)
        for tier in decision.TIERS:
            self.assertIn(tier, rs.tiers)

    def test_sha256_changes_with_content(self):
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as td:
            p1 = pathlib.Path(td) / "a.yml"
            p1.write_text("config_version: \"1.0.0\"\ntiers:\n  exploratory:\n    low: 0.1\n    high: 0.2\n  gxp-support:\n    low: 0.1\n    high: 0.2\n  gxp-critical:\n    low: null\n    high: 0.2\n")
            p2 = pathlib.Path(td) / "b.yml"
            p2.write_text(p1.read_text() + "\n# comment\n")
            self.assertNotEqual(RuleSet.load(p1).sha256, RuleSet.load(p2).sha256)


class TestTiers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rs = RuleSet.load()

    def test_exploratory_boundaries(self):
        low = self.rs.tiers["exploratory"]["low"]
        high = self.rs.tiers["exploratory"]["high"]
        d = decision.decide(low - 0.01, "exploratory", make_evidence(low - 0.01), self.rs)
        self.assertEqual(d["decision"], "GO")
        # exact equality with low -> NOT GO (rule is strict <)
        d = decision.decide(low, "exploratory", make_evidence(low), self.rs)
        self.assertEqual(d["decision"], "GO-WITH-CONDITIONS")
        d = decision.decide(high - 0.001, "exploratory", make_evidence(), self.rs)
        self.assertEqual(d["decision"], "GO-WITH-CONDITIONS")
        d = decision.decide(high, "exploratory", make_evidence(), self.rs)
        self.assertEqual(d["decision"], "NO-GO")

    def test_gxp_support_stricter(self):
        low = self.rs.tiers["gxp-support"]["low"]
        ev = make_evidence(metrics={"github.repo": "acme/widgets"})
        d = decision.decide(low - 0.01, "gxp-support", ev, self.rs)
        self.assertEqual(d["decision"], "GO")
        # same score in exploratory band but above gxp-support low -> conditions
        d = decision.decide(low + 0.05, "gxp-support", make_evidence(), self.rs)
        self.assertEqual(d["decision"], "GO-WITH-CONDITIONS")

    def test_gxp_support_critical_rule_blocks_go(self):
        low = self.rs.tiers["gxp-support"]["low"]
        # bugs_status > 0.5 fires bugs_mostly_open; no github.repo evidence
        # fires no_source_control (both critical) -> GO blocked
        ev = make_evidence(metrics={"bugs_status": 0.9})
        d = decision.decide(low - 0.01, "gxp-support", ev, self.rs)
        self.assertEqual(d["decision"], "GO-WITH-CONDITIONS")
        self.assertIn("bugs_mostly_open", d["fired_rules"])
        self.assertIn("no_source_control", d["fired_rules"])

    def test_gxp_support_critical_rules_absent_allows_go(self):
        low = self.rs.tiers["gxp-support"]["low"]
        ev = make_evidence(metrics={"bugs_status": 0.1,
                                    "github.repo": "acme/widgets"})
        d = decision.decide(low - 0.01, "gxp-support", ev, self.rs)
        self.assertEqual(d["decision"], "GO")

    def test_gxp_critical_never_go(self):
        for score in (0.0, 0.05, 0.1, 0.29):
            d = decision.decide(score, "gxp-critical", make_evidence(), self.rs)
            self.assertNotEqual(d["decision"], "GO")
        d = decision.decide(0.0, "gxp-critical", make_evidence(), self.rs)
        self.assertEqual(d["decision"], "GO-WITH-CONDITIONS")
        # mandatory human-gate conditions present
        joined = " ".join(d["conditions"])
        self.assertIn("Independent verification", joined)
        self.assertIn("Double programming", joined)

    def test_gxp_critical_high_score_no_go(self):
        high = self.rs.tiers["gxp-critical"]["high"]
        d = decision.decide(high, "gxp-critical", make_evidence(), self.rs)
        self.assertEqual(d["decision"], "NO-GO")
        self.assertTrue(any("Tier 2" in c for c in d["conditions"]))

    def test_missing_score_is_no_go(self):
        d = decision.decide(None, "exploratory", make_evidence(), self.rs)
        self.assertEqual(d["decision"], "NO-GO")


class TestRuleEvaluationTransparency(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rs = RuleSet.load()

    def test_all_rules_listed_with_inputs(self):
        ev = make_evidence(overall=0.25, metrics={"news_current": 0.9})
        d = decision.decide(0.25, "exploratory", ev, self.rs)
        ids = [r["id"] for r in d["rules_evaluated"]]
        self.assertIn("overall_score_threshold", ids)
        self.assertIn("news_missing", ids)
        news = next(r for r in d["rules_evaluated"] if r["id"] == "news_missing")
        self.assertEqual(news["input"], 0.9)
        self.assertEqual(news["threshold"], 0.5)
        self.assertTrue(news["fired"])
        # non-fired rules are still shown with their inputs
        not_fired = [r for r in d["rules_evaluated"]
                     if r["id"] not in ("overall_score_threshold",) and not r["fired"]]
        self.assertTrue(not_fired)
        self.assertIn("config_sha256", d)
        self.assertEqual(d["config_sha256"], self.rs.sha256)

    def test_na_rule_fires_on_missing_metric(self):
        d = decision.decide(0.1, "exploratory", make_evidence(), self.rs)
        na_rule = next(r for r in d["rules_evaluated"]
                       if r["id"] == "news_not_measurable")
        self.assertTrue(na_rule["fired"])

    def test_conditions_from_fired_rules(self):
        # low_downloads keys on the deterministic cranlogs metric
        ev = make_evidence(metrics={"downloads.last_month_total": 500})
        d = decision.decide(0.45, "exploratory", ev, self.rs)
        self.assertEqual(d["decision"], "GO-WITH-CONDITIONS")
        self.assertTrue(any("community usage" in c for c in d["conditions"]))
        # and it does not fire when downloads are healthy
        ev2 = make_evidence(metrics={"downloads.last_month_total": 500000})
        d2 = decision.decide(0.45, "exploratory", ev2, self.rs)
        self.assertNotIn("low_downloads", d2["fired_rules"])

    def test_unknown_tier_rejected(self):
        with self.assertRaises(decision.DecisionError):
            decision.decide(0.1, "production", make_evidence(), self.rs)


if __name__ == "__main__":
    unittest.main()
