"""Detection tests: every Sigma rule against every labeled sample.

Each rule must detect all events in tests/data/malicious/<rule name>/ and fire on
no event in tests/data/benign/. The harness logic lives in scripts/sigma_harness.py
so the CLI table (scripts/run_sigma_tests.py) and these tests can never disagree.
"""

import sys
from pathlib import Path

import pytest
from sigma.rule import SigmaRule

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from sigma_harness import Harness, rule_files  # noqa: E402


@pytest.fixture(scope="module")
def harness() -> Harness:
    return Harness()


@pytest.mark.parametrize("path", rule_files(), ids=lambda p: p.stem)
def test_rule_detects_malicious_and_ignores_benign(harness, path):
    result = harness.evaluate(SigmaRule.from_yaml(path.read_text("utf-8")), path.stem)

    assert result.malicious_total > 0, "no malicious samples for this rule"
    assert not result.missed, f"missed malicious events: {result.missed}"
    assert not result.false_positives, f"fired on benign events: {result.false_positives}"
    assert result.benign_in_scope > 0, "no benign events of this log type were tested"


# ---------------------------------------------------------------------------
# Self-tests: prove the harness reports failures instead of always passing.
# ---------------------------------------------------------------------------

LSASS_RULE = "proc_access_win_lsass_credential_dump_access"


def _rule(detection: dict) -> SigmaRule:
    return SigmaRule.from_dict(
        {
            "title": "Harness self-test",
            "logsource": {"product": "windows", "category": "process_access"},
            "detection": detection,
        }
    )


def test_harness_reports_missed_detections(harness):
    # A rule that can never match: the harness must report every malicious event as missed.
    broken = _rule(
        {"selection": {"TargetImage|endswith": r"\not_lsass.exe"}, "condition": "selection"}
    )
    result = harness.evaluate(broken, LSASS_RULE)
    assert not result.passed
    assert len(result.missed) == result.malicious_total > 0


def test_harness_reports_false_positives(harness):
    # A rule that matches every LSASS access, including svchost's routine 0x1000 handles.
    noisy = _rule({"selection": {"TargetImage|endswith": r"\lsass.exe"}, "condition": "selection"})
    result = harness.evaluate(noisy, LSASS_RULE)
    assert not result.passed
    assert result.false_positives, "the svchost near-misses should have been flagged"


def test_harness_matching_is_case_insensitive(harness):
    # Sigma matching is case-insensitive; SQLite '=' is not unless the column is NOCASE.
    upper = _rule({"selection": {"GrantedAccess": "0X1FFFFF"}, "condition": "selection"})
    assert harness.evaluate(upper, LSASS_RULE).malicious_detected > 0
