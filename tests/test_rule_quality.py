"""Quality gates for every Sigma rule, beyond what `sigma check` validates.

A rule is only allowed in the repo if it is documented well enough for an
analyst to act on (description, false positives, severity, ATT&CK mapping)
and if it has malicious test data to prove it works.
"""

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULE_FILES = sorted((REPO_ROOT / "rules" / "sigma").rglob("*.yml"))
MALICIOUS_DIR = REPO_ROOT / "tests" / "data" / "malicious"

TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text("utf-8"))


def test_rules_exist():
    assert len(RULE_FILES) >= 8


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_is_documented(path):
    rule = load(path)
    for field in ("title", "id", "status", "description", "author", "date", "references"):
        assert rule.get(field), f"missing {field}"
    assert rule["level"] in VALID_LEVELS
    assert rule.get("falsepositives"), "document at least one false positive scenario"
    # An unquoted "text: more text" item silently becomes a YAML mapping, which breaks
    # backends that copy false positives into their output (this happened once).
    assert all(isinstance(fp, str) for fp in rule["falsepositives"]), "quote false positives"
    assert len(rule["description"].split()) >= 25, "description too short to explain the detection"


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_has_attack_technique(path):
    tags = load(path).get("tags", [])
    assert any(TECHNIQUE_TAG.match(t) for t in tags), "needs at least one attack.tXXXX tag"


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_has_malicious_samples(path):
    folder = MALICIOUS_DIR / path.stem
    assert any(folder.glob("*.jsonl")), f"no malicious samples in {folder.relative_to(REPO_ROOT)}"


def test_rule_ids_are_unique():
    ids = [load(p)["id"] for p in RULE_FILES]
    assert len(ids) == len(set(ids))


def test_every_malicious_folder_has_a_rule():
    rule_names = {p.stem for p in RULE_FILES}
    folders = {p.name for p in MALICIOUS_DIR.iterdir() if p.is_dir()}
    assert folders - rule_names == set(), "malicious sample folders without a matching rule"
