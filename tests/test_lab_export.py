"""Tests for the lab export path: Ops Agent raw XML -> flat event -> tests/data.

The GCP lab can't run in CI, so these tests feed hand-written event XML (same
structure the Ops Agent stores in jsonPayload.raw_xml) through the parser and
the export helpers. No BigQuery access is needed.
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from export_lab_logs import ensure_manifest_entry, manifest_entry, normalize_events  # noqa: E402
from normalize import parse_windows_event_xml  # noqa: E402

NS = "http://schemas.microsoft.com/win/2004/08/events/event"

SYSMON_PROCESS_CREATE = f"""<Event xmlns="{NS}">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-10-15T09:12:03.1234567Z"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>ws01.lab.purpleloop.local</Computer>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="Image">C:\\Windows\\System32\\svchost.exe</Data>
    <Data Name="CommandLine">C:\\Windows\\system32\\svchost.exe -k netsvcs -p</Data>
    <Data Name="ParentImage">C:\\Windows\\System32\\services.exe</Data>
    <Data Name="Description"></Data>
  </EventData>
</Event>"""

LOG_CLEARED = f"""<Event xmlns="{NS}">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog"/>
    <EventID>1102</EventID>
    <TimeCreated SystemTime="2026-10-15T09:30:00Z"/>
    <Channel>security</Channel>
    <Computer>dc01.lab.purpleloop.local</Computer>
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserName>Administrator</SubjectUserName>
      <SubjectDomainName>PLLAB</SubjectDomainName>
    </LogFileCleared>
  </UserData>
</Event>"""


def test_eventdata_fields_keep_native_names():
    event = parse_windows_event_xml(SYSMON_PROCESS_CREATE)
    assert event["EventID"] == 1
    assert event["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert event["Provider_Name"] == "Microsoft-Windows-Sysmon"
    assert event["Hostname"] == "ws01.lab.purpleloop.local"
    assert event["Image"] == "C:\\Windows\\System32\\svchost.exe"
    assert event["ParentImage"].endswith("services.exe")
    # Same millisecond UTC format as the public dataset samples.
    assert event["@timestamp"] == "2026-10-15T09:12:03.123Z"
    # Empty <Data> elements are dropped, like every other source.
    assert "Description" not in event


def test_userdata_events_are_flattened_and_channel_canonicalized():
    event = parse_windows_event_xml(LOG_CLEARED)
    assert event["EventID"] == 1102
    assert event["Channel"] == "Security"
    assert event["SubjectUserName"] == "Administrator"
    assert event["@timestamp"] == "2026-10-15T09:30:00.000Z"


def test_non_event_xml_is_rejected():
    with pytest.raises(ValueError):
        parse_windows_event_xml("<NotAnEvent/>")


def test_normalize_events_filters_dedupes_and_counts_failures():
    raw = [SYSMON_PROCESS_CREATE, SYSMON_PROCESS_CREATE, LOG_CLEARED]

    # One bad row is skipped and counted; it doesn't abort the export.
    events, failed = normalize_events(raw + ["<broken", "<NotAnEvent/>"], [])
    assert failed == 2
    assert len(events) == 2  # duplicate resend dropped

    events, _ = normalize_events(raw, [1102])
    assert [e["EventID"] for e in events] == [1102]

    events, _ = normalize_events(raw, [], host="WS01")
    assert [e["Hostname"] for e in events] == ["ws01.lab.purpleloop.local"]


def test_manifest_entry_is_appended_once_and_stays_valid(tmp_path):
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text("# comment kept\nsamples:\n  - output: benign/x.jsonl\n", "utf-8")
    entry = manifest_entry(
        "benign/lab_baseline.jsonl", "Baseline: DC and member server.", "a", "b", 42
    )

    assert ensure_manifest_entry(manifest, entry, "benign/lab_baseline.jsonl")
    assert not ensure_manifest_entry(manifest, entry, "benign/lab_baseline.jsonl")

    text = manifest.read_text("utf-8")
    assert text.startswith("# comment kept")
    samples = yaml.safe_load(text)["samples"]
    added = samples[-1]
    assert added["output"] == "benign/lab_baseline.jsonl"
    assert added["label"] == "benign"
    assert added["origin"] == "self-generated"
    assert added["exported"]["events"] == 42
