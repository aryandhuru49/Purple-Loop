"""Unit tests for the safety checks in scripts/convert_rules.py.

These checks decide whether generated SecOps output can be trusted, so they are
tested directly against known-good and known-bad expressions.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from convert_rules import fix_yaral_rule_name, top_level_operators  # noqa: E402


def test_mixed_and_or_without_parentheses_is_detected():
    # The real bug seen in the SecOps YARA-L output for the regsvr32 rule.
    expr = "$e.path = /a/ AND $e.cmd = / -i:/ OR $e.cmd = / \\/i:/ AND $e.cmd = /scrobj/"
    assert top_level_operators(expr) == {"AND", "OR"}


def test_parenthesized_or_group_is_fine():
    expr = "$e.path = /a/ AND ($e.cmd = / -i:/ OR $e.cmd = / \\/i:/) AND $e.cmd = /scrobj/"
    assert top_level_operators(expr) == {"AND"}


def test_operators_inside_strings_and_regexes_are_ignored():
    expr = '$e.cmd = /x AND y OR z/ nocase AND $e.title = "a OR b (c"'
    assert top_level_operators(expr) == {"AND"}


def test_escaped_slash_inside_regex_does_not_end_it():
    expr = "$e.cmd = /http:\\/\\/ OR / AND $e.x = 1"
    assert top_level_operators(expr) == {"AND"}


def test_yaral_rule_name_is_made_valid():
    text = "rule regsvr32_via_scrobj.dll_(squiblydoo) {\n  meta:\n"
    assert fix_yaral_rule_name(text).startswith("rule regsvr32_via_scrobj_dll_squiblydoo {")
