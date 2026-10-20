"""Test every Sigma rule against labeled malicious and benign log samples.

How it works:
  1. Load every JSONL sample under tests/data into an in-memory SQLite table.
     Each row remembers which file it came from and whether it is malicious or benign.
  2. Convert each Sigma rule to SQL with pySigma's SQLite backend. The "sysmon" and
     "windows-logsources" pipelines turn the rule's logsource into real conditions
     (e.g. process_creation -> Channel='Microsoft-Windows-Sysmon/Operational' AND EventID=1).
  3. Run the SQL and compare the matched rows with the labels:
       detection  every event in tests/data/malicious/<rule name>/ must match
       precision  no event in tests/data/benign/ may match
       coverage   at least one benign event must share the rule's log type, otherwise
                  "zero false positives" would be meaningless (nothing was tested)

Usage:
    uv run python scripts/run_sigma_tests.py
"""

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins
from sigma.rule import SigmaRule

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules" / "sigma"
DATA_DIR = REPO_ROOT / "tests" / "data"

# Pipelines that map generic Sigma log sources onto the events we store: Windows/Sysmon
# (installed pySigma pipelines) and GCP Cloud Audit Logs (this repo's pipelines/ folder).
PIPELINES = [
    "sysmon",
    "windows-logsources",
    str(REPO_ROOT / "pipelines" / "gcp_audit_logsource.yml"),
]

# Columns the harness adds to every row; underscore-prefixed so they can't clash with log fields.
META_COLUMNS = ["_row", "_file", "_label"]


@dataclass
class RuleResult:
    name: str
    title: str
    level: str
    techniques: list[str]
    malicious_total: int
    malicious_detected: int
    benign_in_scope: int
    false_positives: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    sql: str = ""

    @property
    def passed(self) -> bool:
        return (
            self.malicious_total > 0
            and self.malicious_detected == self.malicious_total
            and not self.false_positives
            and self.benign_in_scope > 0
        )


# ---------------------------------------------------------------------------
# Loading samples into SQLite
# ---------------------------------------------------------------------------


def load_samples() -> list[dict]:
    """Read every sample event and tag it with its file and label."""
    rows = []
    for path in sorted(DATA_DIR.rglob("*.jsonl")):
        rel = path.relative_to(DATA_DIR).as_posix()
        label = rel.split("/")[0]  # "malicious" or "benign" (enforced by test_data_manifest)
        for line_no, line in enumerate(path.read_text("utf-8").splitlines(), start=1):
            event = json.loads(line)
            event.update(_row=len(rows), _file=f"{rel}:{line_no}", _label=label)
            rows.append(event)
    return rows


def build_database(rows: list[dict]) -> sqlite3.Connection:
    """Create one table with a column for every field seen in any event.

    COLLATE NOCASE makes '=' comparisons case-insensitive, matching the Sigma
    specification (SQLite's default '=' is case-sensitive; LIKE already is not).
    """
    fields = sorted({k for row in rows for k in row} - set(META_COLUMNS))
    db = sqlite3.connect(":memory:")
    columns = ["_row INTEGER", "_file TEXT", "_label TEXT"] + [
        f'"{f}" INTEGER' if f == "EventID" else f'"{f}" TEXT COLLATE NOCASE' for f in fields
    ]
    db.execute(f"CREATE TABLE logs ({', '.join(columns)})")
    all_columns = META_COLUMNS + fields
    placeholders = ", ".join("?" for _ in all_columns)
    db.executemany(
        f"INSERT INTO logs VALUES ({placeholders})",
        [[_sql_value(row.get(c)) for c in all_columns] for row in rows],
    )
    return db


def _sql_value(value):
    if value is None or isinstance(value, int | float | str):
        return value
    return json.dumps(value)  # nested structures are stored as JSON text


# ---------------------------------------------------------------------------
# Running rules
# ---------------------------------------------------------------------------

MISSING_COLUMN = re.compile(r"no such column: (\S+)")


def run_query(db: sqlite3.Connection, sql: str) -> set[int]:
    """Run a converted rule and return matched row ids.

    A rule may reference a field that no sample contains (e.g. OriginalFileName in
    older Sysmon logs). Real SIEMs treat that as "field absent", so we add the
    column (all NULL) instead of failing, and retry.
    """
    sql = sql.replace("SELECT * FROM <TABLE_NAME>", "SELECT _row FROM logs")
    for _ in range(50):
        try:
            return {row[0] for row in db.execute(sql)}
        except sqlite3.OperationalError as error:
            match = MISSING_COLUMN.search(str(error))
            if not match:
                raise
            db.execute(f'ALTER TABLE logs ADD COLUMN "{match.group(1)}" TEXT COLLATE NOCASE')
    raise RuntimeError("too many missing columns")


def logsource_only_query(backend: sqliteBackend, rule: SigmaRule) -> str:
    """SQL that selects every event of the rule's log type, ignoring its detection logic.

    Used to count how many benign events actually exercised the rule.
    """
    scope_rule = {
        "title": "scope",
        "logsource": rule.logsource.to_dict(),
        "detection": {"selection": {"_row|gte": 0}, "condition": "selection"},
    }
    return backend.convert(SigmaCollection.from_dicts([scope_rule]))[0]


class Harness:
    """Holds the loaded samples and the configured backend; evaluates rules against them."""

    def __init__(self) -> None:
        self.rows = load_samples()
        self.db = build_database(self.rows)
        resolver = InstalledSigmaPlugins.autodiscover().get_pipeline_resolver()
        self.backend = sqliteBackend(resolver.resolve(PIPELINES))

    def evaluate(self, rule: SigmaRule, name: str) -> RuleResult:
        """Test one rule. `name` selects its samples in tests/data/malicious/<name>/."""
        sql = self.backend.convert(SigmaCollection([rule]))[0]
        matched = run_query(self.db, sql)
        in_scope = run_query(self.db, logsource_only_query(self.backend, rule))

        own = [r for r in self.rows if r["_file"].startswith(f"malicious/{name}/")]
        benign = [r for r in self.rows if r["_label"] == "benign"]
        return RuleResult(
            name=name,
            title=rule.title,
            level=rule.level.name.lower() if rule.level else "",
            techniques=[
                t.name.upper() for t in rule.tags if t.namespace == "attack" and t.name[0] == "t"
            ],
            malicious_total=len(own),
            malicious_detected=sum(1 for r in own if r["_row"] in matched),
            benign_in_scope=sum(1 for r in benign if r["_row"] in in_scope),
            false_positives=[r["_file"] for r in benign if r["_row"] in matched],
            missed=[r["_file"] for r in own if r["_row"] not in matched],
            sql=sql,
        )


def rule_files() -> list[Path]:
    return sorted(RULES_DIR.rglob("*.yml"))


def run_all() -> list[RuleResult]:
    harness = Harness()
    return [
        harness.evaluate(SigmaRule.from_yaml(path.read_text("utf-8")), path.stem)
        for path in rule_files()
    ]
