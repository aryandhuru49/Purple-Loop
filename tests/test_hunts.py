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


def test_logging_hunt_shows_the_sink_edit_the_rule_skips(db):
    rows = run(db, "gcp_logging_config_changes")
    found = {(r["method"].rsplit(".", 1)[-1], r["resource"].rsplit("/", 1)[-1]) for r in rows}
    # The real sink's filter edit by Terraform: routine, so the rule ignores it,
    # but it belongs in the analyst's list of logging changes.
    assert ("UpdateSink", "purple-loop-lab-to-bigquery") in found
    assert ("DeleteSink", "purple-loop-sim-sink") in found


def test_rare_methods_hunt_surfaces_a_one_off_key_creation(db):
    rows = run(db, "gcp_rare_principal_methods")
    assert any(r["method"] == "google.iam.admin.v1.CreateServiceAccountKey" for r in rows)
    # Google-managed service agents are excluded.
    assert not any("system.gserviceaccount.com" in (r["principal"] or "") for r in rows)


def test_gcp_hunts_also_compile_for_bigquery():
    for path in sorted(HUNTS_DIR.glob("gcp_*.l")):
        sql = compile_hunt(path, "bigquery")
        assert "`purple_loop_lab_logs.audit_events`" in sql
