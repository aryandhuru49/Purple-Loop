"""The Logica hunts compile, run on DuckDB, and surface the known attacks.

Hunts return leads rather than verdicts, so these tests only assert that the
attack activity in the Phase 1 data is visible in each hunt's output.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from run_hunts import HUNTS_DIR, compile_hunt, load_logs  # noqa: E402


@pytest.fixture(scope="module")
def db():
    return load_logs()


def run(db, name: str) -> list[dict]:
    cursor = db.execute(compile_hunt(HUNTS_DIR / f"{name}.l"))
    columns = [c[0] for c in cursor.description]
    return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]


def test_rare_pairs_include_script_host_spawning_powershell(db):
    pairs = {(r["parent"], r["child"]) for r in run(db, "rare_parent_child_pairs")}
    assert (
        r"c:\windows\system32\wscript.exe",
        r"c:\windows\system32\windowspowershell\v1.0\powershell.exe",
    ) in pairs


def test_kerberoasting_account_is_the_top_outlier(db):
    rows = sorted(run(db, "kerberos_ticket_spread"), key=lambda r: -r["distinct_services"])
    top = rows[0]
    assert top["account"].startswith("Administrator")
    assert top["distinct_services"] == top["rc4_tickets"] == 30


def test_lsass_inventory_shows_mimikatz_style_access(db):
    rows = run(db, "lsass_access_inventory")
    assert any(
        r["process"].lower().endswith(r"\powershell.exe") and r["access"] == "0x1010" for r in rows
    )
