"""Tests for gateway.miniyaml — the YAML-subset parser."""

import unittest

from gateway.miniyaml import MiniYamlError, load


class TestScalars(unittest.TestCase):
    def test_int_float_bool_null(self):
        doc = load("a: 1\nb: 2.5\nc: true\nd: false\ne: null\nf: ~\ng: -3\nh: 0.25\n")
        self.assertEqual(doc, {"a": 1, "b": 2.5, "c": True, "d": False,
                               "e": None, "f": None, "g": -3, "h": 0.25})

    def test_quoted_strings(self):
        doc = load('a: "hello # not a comment"\nb: \'it\'\'s\'\nc: "esc \\"q\\" \\\\"\n')
        self.assertEqual(doc["a"], "hello # not a comment")
        self.assertEqual(doc["b"], "it's")
        self.assertEqual(doc["c"], 'esc "q" \\')

    def test_plain_string_and_inline_comment(self):
        doc = load("a: plain value  # trailing comment\nb: url https://x.example/#frag\n")
        self.assertEqual(doc["a"], "plain value")
        self.assertEqual(doc["b"], "url https://x.example/#frag")

    def test_unquoted_colon_value(self):
        # value containing ':' after the key separator stays a plain string
        doc = load("note: condition: pin version")
        self.assertEqual(doc["note"], "condition: pin version")


class TestNestedMaps(unittest.TestCase):
    def test_nested_map(self):
        doc = load("outer:\n  inner: 1\n  deep:\n    leaf: yes\nsibling: 2\n")
        self.assertEqual(doc, {"outer": {"inner": 1, "deep": {"leaf": True}},
                               "sibling": 2})

    def test_empty_key_is_none(self):
        doc = load("a:\nb: 1\n")
        self.assertEqual(doc, {"a": None, "b": 1})


class TestSequences(unittest.TestCase):
    def test_scalar_list_same_indent_as_key(self):
        doc = load("items:\n- a\n- b\n- 3\n")
        self.assertEqual(doc, {"items": ["a", "b", 3]})

    def test_scalar_list_indented(self):
        doc = load("items:\n  - a\n  - b\n")
        self.assertEqual(doc, {"items": ["a", "b"]})

    def test_list_of_maps(self):
        doc = load(
            "rules:\n"
            "  - name: low\n"
            "    max: 0.3\n"
            "  - name: high\n"
            "    min: 0.7\n"
            "    note: \"watch it\"\n"
        )
        self.assertEqual(doc["rules"], [
            {"name": "low", "max": 0.3},
            {"name": "high", "min": 0.7, "note": "watch it"},
        ])

    def test_list_of_maps_with_nested_list(self):
        doc = load(
            "rules:\n"
            "  - name: r1\n"
            "    conditions:\n"
            "      - pin version\n"
            "      - re-check on update\n"
        )
        self.assertEqual(doc["rules"][0]["conditions"],
                         ["pin version", "re-check on update"])

    def test_nested_map_value_in_list_item(self):
        doc = load("tiers:\n  - id: t1\n    range:\n      low: 0.2\n      high: 0.5\n")
        self.assertEqual(doc["tiers"][0]["range"], {"low": 0.2, "high": 0.5})


class TestEdgeCases(unittest.TestCase):
    def test_blank_and_comment_only(self):
        self.assertIsNone(load("\n# just a comment\n\n"))

    def test_tabs_rejected(self):
        with self.assertRaises(MiniYamlError):
            load("a:\n\tb: 1")

    def test_flow_collection_rejected(self):
        with self.assertRaises(MiniYamlError):
            load("a: [1, 2]")

    def test_anchor_rejected(self):
        with self.assertRaises(MiniYamlError):
            load("a: &x 1")

    def test_duplicate_key_rejected(self):
        with self.assertRaises(MiniYamlError):
            load("a: 1\na: 2\n")

    def test_bad_line_rejected(self):
        with self.assertRaises(MiniYamlError):
            load("not a mapping line")

    def test_round_trip_real_config_shape(self):
        doc = load(
            "config_version: \"1.0.0\"\n"
            "tiers:\n"
            "  exploratory:\n"
            "    low: 0.3\n"
            "    high: 0.6\n"
            "metric_rules:\n"
            "  - id: news_missing\n"
            "    metric: has_news\n"
            "    severity: warn\n"
            "    when: \"< 1.0\"\n"
            "    condition: pin version and re-check on update\n"
        )
        self.assertEqual(doc["config_version"], "1.0.0")
        self.assertEqual(doc["tiers"]["exploratory"]["low"], 0.3)
        self.assertEqual(doc["metric_rules"][0]["severity"], "warn")


if __name__ == "__main__":
    unittest.main()
