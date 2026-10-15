"""Structural lint for the hand-written YARA-L 2.0 rules in rules/yara_l/.

Google SecOps is a paid platform, so these rules cannot be compiled or executed in CI.
This lint catches the mistakes that are checkable offline: section order, unbalanced
brackets, invalid rule names, missing metadata, event variables never used in the
condition, and ATT&CK IDs that don't exist. Real validation still needs a tenant
(see docs/yara_l.md).
"""

import re
from pathlib import Path

import pytest
from sigma.data.mitre_attack import mitre_attack_techniques

RULE_FILES = sorted((Path(__file__).resolve().parent.parent / "rules" / "yara_l").glob("*.yaral"))

# Order defined by Google's YARA-L 2.0 syntax reference. meta, events, condition are required.
SECTION_ORDER = ["meta", "events", "match", "outcome", "condition", "options"]
REQUIRED_SECTIONS = {"meta", "events", "condition"}
REQUIRED_META = {"author", "description", "severity", "mitre_attack_id", "false_positives"}


def strip_comments_and_literals(text: str) -> str:
    """Remove // comments and blank out "strings" and `raw regexes` so brackets and
    keywords inside them are ignored. Keeps line structure intact."""
    out, i = [], 0
    while i < len(text):
        if text.startswith("//", i):
            while i < len(text) and text[i] != "\n":
                i += 1
        elif text[i] in '"`':
            quote = text[i]
            out.append(quote)
            i += 1
            while i < len(text) and text[i] != quote:
                i += 2 if text[i] == "\\" and quote == '"' else 1
            out.append(quote)
            i += 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def sections(code: str) -> dict[str, str]:
    """Split the rule body into {section name: section text}."""
    pattern = re.compile(r"^\s*(" + "|".join(SECTION_ORDER) + r"):\s*$", re.MULTILINE)
    found = list(pattern.finditer(code))
    return {
        m.group(1): code[m.end() : found[n + 1].start() if n + 1 < len(found) else len(code)]
        for n, m in enumerate(found)
    }


@pytest.fixture(params=RULE_FILES, ids=lambda p: p.name)
def rule(request):
    raw = request.param.read_text("utf-8")
    return raw, strip_comments_and_literals(raw)


def test_rules_exist():
    assert len(RULE_FILES) >= 3


def test_states_it_is_not_executed(rule):
    raw, _ = rule
    assert "NOT executed" in raw, "say clearly that this rule is reviewed but not run"


def test_single_rule_with_valid_name(rule):
    _, code = rule
    names = re.findall(r"^rule\s+(\S+)\s*\{", code, re.MULTILINE)
    assert len(names) == 1
    assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", names[0]), f"invalid rule name {names[0]}"


def test_brackets_balance(rule):
    _, code = rule
    for opener, closer in ("{}", "()", "[]"):
        depth = 0
        for char in code:
            depth += (char == opener) - (char == closer)
            assert depth >= 0, f"unexpected {closer}"
        assert depth == 0, f"unbalanced {opener}{closer}"


def test_sections_present_and_ordered(rule):
    _, code = rule
    present = list(sections(code))
    assert REQUIRED_SECTIONS <= set(present)
    assert present == sorted(present, key=SECTION_ORDER.index), f"section order: {present}"


def test_meta_complete_and_attack_ids_exist(rule):
    raw, code = rule
    meta_keys = set(re.findall(r"^\s*(\w+)\s*=", sections(code)["meta"], re.MULTILINE))
    assert REQUIRED_META <= meta_keys, f"missing meta: {REQUIRED_META - meta_keys}"
    ids = re.search(r'mitre_attack_id\s*=\s*"([^"]+)"', raw).group(1)
    for technique in (t.strip() for t in ids.split(",")):
        assert technique in mitre_attack_techniques, f"{technique} not in current ATT&CK"


def test_every_event_variable_is_used_in_condition(rule):
    _, code = rule
    parts = sections(code)
    event_vars = set(re.findall(r"\$(\w+)\.", parts["events"]))
    condition_vars = set(re.findall(r"\$(\w+)", parts["condition"]))
    assert event_vars <= condition_vars, f"not in condition: {event_vars - condition_vars}"


def test_multi_event_rules_have_match_and_outcome(rule):
    _, code = rule
    parts = sections(code)
    if "match" in parts:
        # Rules with a match window are aggregations; Google requires aggregated outcomes.
        assert "outcome" in parts
        assert re.search(r"\b(count|count_distinct|array_distinct|max|min|sum)\(", parts["outcome"])
