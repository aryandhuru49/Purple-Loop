"""Turn raw public datasets into one flat, consistent JSON event schema.

Different log shippers produce the same Windows event in different shapes:
  * OTRF Security-Datasets: JSON lines written by nxlog/logstash, with extra
    shipping metadata, string or integer EventIDs, and inconsistent channel
    casing ("Security" vs "security").
  * Splunk attack_data: Splunk's classic multi-line "key=value" WinEventLog
    text, where event fields are human-readable labels ("Ticket Encryption Type").
  * The Purple Loop GCP lab: the Ops Agent stores each event's original XML,
    exported from BigQuery by scripts/export_lab_logs.py.
  * Google Cloud Audit Logs: nested LogEntry JSON, flattened to dotted native
    paths by flatten_log_entry (exported by scripts/export_audit_logs.py).

Detection rules should not care about any of that. Every event that leaves this
module uses the native Windows/Sysmon field names that Sigma rules are written
against (EventID, Channel, Image, CommandLine, TicketEncryptionType, ...).
Cloud audit events keep their native LogEntry paths (protoPayload.methodName, ...).
"""

import json
import re
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Shared clean-up
# ---------------------------------------------------------------------------

# Canonical channel names. OTRF sometimes lower-cases them, which would break
# exact-match rule conditions like Channel = 'Security'.
CANONICAL_CHANNELS = {
    "security": "Security",
    "system": "System",
    "microsoft-windows-sysmon/operational": "Microsoft-Windows-Sysmon/Operational",
    "windows powershell": "Windows PowerShell",
    "microsoft-windows-powershell/operational": "Microsoft-Windows-PowerShell/Operational",
}

# Fields added by the log pipeline (nxlog/logstash), not by Windows itself.
# They are dropped so samples stay small and rules can't accidentally rely on them.
SHIPPER_FIELDS = {
    "@version", "tags", "port", "host", "EventReceivedTime", "SourceModuleName",
    "SourceModuleType", "Message", "Keywords", "Severity", "SeverityValue",
    "ExecutionProcessID", "ThreadID", "RecordNumber", "Opcode", "OpcodeValue",
    "Task", "Category", "Version", "ProviderGuid", "EventTypeOrignal", "AccountType",
    "UserID", "Domain", "AccountName", "Level", "EventTime", "TimeCreated",
}  # fmt: skip


def clean_event(event: dict) -> dict:
    """Apply the shared normalization rules to one event."""
    out = {k: v for k, v in event.items() if k not in SHIPPER_FIELDS and v not in (None, "")}
    # nxlog calls the event provider "SourceName"; Sigma rules use "Provider_Name".
    if "SourceName" in out:
        out["Provider_Name"] = out.pop("SourceName")
    out["EventID"] = int(out["EventID"])
    channel = str(out.get("Channel", ""))
    out["Channel"] = CANONICAL_CHANNELS.get(channel.lower(), channel)
    return out


# ---------------------------------------------------------------------------
# OTRF: zip file containing one JSON event per line
# ---------------------------------------------------------------------------


def read_otrf_zip(path: Path) -> Iterator[dict]:
    with zipfile.ZipFile(path) as archive:
        members = [n for n in archive.namelist() if not n.endswith("/")]
        if len(members) != 1:
            raise ValueError(f"{path.name}: expected one file in the zip, found {members}")
        text = archive.read(members[0]).decode("utf-8", errors="replace")

    for line in text.splitlines():
        if line.strip():
            yield clean_event(json.loads(line))


# ---------------------------------------------------------------------------
# Splunk: multi-line "key=value" WinEventLog text
# ---------------------------------------------------------------------------

# Every event starts with a timestamp line like "02/11/2022 07:29:07 PM".
SPLUNK_EVENT_START = re.compile(r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M$")

# Human-readable message labels -> native Windows XML field names, per EventID.
# Only the events our rules and benign corpus use are mapped; the rest of the
# message body is ignored rather than guessed at.
SPLUNK_LABELS = {
    4769: {  # A Kerberos service ticket was requested
        "Account Name": "TargetUserName",
        "Account Domain": "TargetDomainName",
        "Logon GUID": "LogonGuid",
        "Service Name": "ServiceName",
        "Service ID": "ServiceSid",
        "Client Address": "IpAddress",
        "Client Port": "IpPort",
        "Ticket Options": "TicketOptions",
        "Ticket Encryption Type": "TicketEncryptionType",
        "Failure Code": "Status",
        "Transited Services": "TransmittedServices",
    },
    4688: {  # A new process has been created
        "New Process Name": "NewProcessName",
        "Process Command Line": "CommandLine",
        "Creator Process Name": "ParentProcessName",
    },
}

LABEL_LINE = re.compile(r"^\t?([A-Za-z][A-Za-z ]+):\t+(.*)$")


def _parse_splunk_block(lines: list[str]) -> dict | None:
    # Splunk exports don't state a timezone; Attack Range hosts log in UTC.
    timestamp = datetime.strptime(lines[0], "%m/%d/%Y %I:%M:%S %p")
    header: dict[str, str] = {}
    body: list[str] = []
    for line in lines[1:]:
        if not body and "=" in line and not line.startswith("Message="):
            key, _, value = line.partition("=")
            header[key] = value
        else:
            body.append(line)

    event_id = int(header["EventCode"])
    event = {
        "EventID": event_id,
        "Channel": header.get("LogName", ""),
        "Provider_Name": header.get("SourceName"),
        "Hostname": header.get("ComputerName"),
        "@timestamp": timestamp.isoformat() + "Z",
    }

    labels = SPLUNK_LABELS.get(event_id, {})
    for line in body:
        match = LABEL_LINE.match(line)
        if match and match.group(1) in labels:
            field = labels[match.group(1)]
            # Labels repeat in some events (e.g. Subject vs Target account); keep the first.
            event.setdefault(field, match.group(2).strip())
    return clean_event(event)


def read_wineventlog_text(path: Path) -> Iterator[dict]:
    block: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if SPLUNK_EVENT_START.match(line) and block:
            yield _parse_splunk_block(block)
            block = []
        block.append(line)
    if block:
        yield _parse_splunk_block(block)


# ---------------------------------------------------------------------------
# Purple Loop GCP lab: Ops Agent windows_event_log receiver with render_as_xml
# ---------------------------------------------------------------------------

# Every Windows event is stored in BigQuery with its original XML in
# jsonPayload.raw_xml. The XML already uses the native field names
# (<Data Name="CommandLine">), so no label mapping is needed.
EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def parse_windows_event_xml(raw_xml: str) -> dict:
    """Turn one rendered Windows event (<Event> XML) into a flat event dict."""
    root = ET.fromstring(raw_xml)
    system = root.find(f"{EVENT_NS}System")
    if system is None:
        raise ValueError("not a Windows event: no <System> element")

    def text(tag: str) -> str | None:
        element = system.find(f"{EVENT_NS}{tag}")
        return element.text if element is not None else None

    provider = system.find(f"{EVENT_NS}Provider")
    created = system.find(f"{EVENT_NS}TimeCreated")
    event: dict = {
        "EventID": text("EventID"),
        "Channel": text("Channel"),
        "Hostname": text("Computer"),
        "Provider_Name": provider.get("Name") if provider is not None else None,
    }
    if created is not None and created.get("SystemTime"):
        # SystemTime is UTC with up to 7 fractional digits; keep milliseconds
        # to match the timestamps of the public datasets.
        stamp = created.get("SystemTime").rstrip("Z")
        whole, _, fraction = stamp.partition(".")
        event["@timestamp"] = f"{whole}.{(fraction + '000')[:3]}Z"

    # Most events: <EventData><Data Name="Field">value</Data>...</EventData>
    for data in root.iterfind(f"{EVENT_NS}EventData/{EVENT_NS}Data"):
        if data.get("Name"):
            event.setdefault(data.get("Name"), data.text)

    # Some events (e.g. 1102 log cleared) use <UserData><SomeType><Field>value</Field>.
    user_data = root.find(f"{EVENT_NS}UserData")
    if user_data is not None:
        for container in user_data:
            for field in container:
                event.setdefault(field.tag.split("}")[-1], field.text)

    return clean_event(event)


# ---------------------------------------------------------------------------
# Google Cloud Audit Logs (Cloud Logging LogEntry JSON)
# ---------------------------------------------------------------------------


def flatten_log_entry(entry: dict) -> dict:
    """Flatten a Cloud Logging LogEntry into one level of dotted field names.

    Field names stay the native LogEntry paths, as the Windows events keep their
    native names:
        {"protoPayload": {"methodName": "SetIamPolicy"}}
            -> {"protoPayload.methodName": "SetIamPolicy"}

    Arrays use the "name[]" notation from Google's SecOps parser documentation and
    hold every value found inside them, so a rule can ask "does any binding delta
    grant roles/owner?":
        {"bindingDeltas": [{"action": "ADD", "role": "roles/owner"}]}
            -> {"...bindingDeltas[].action": ["ADD"], "...bindingDeltas[].role": ["roles/owner"]}

    Trade-off: values from different array items are no longer paired, so a single
    change that removes Owner and adds Viewer has both "REMOVE"/"ADD" and "roles/owner".
    Splunk's multivalue fields behave the same way; the IAM rule documents it.
    """
    flat: dict = {}

    def walk(value, path: str, in_array: bool) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, f"{path}.{key}" if path else key, in_array)
        elif isinstance(value, list):
            for item in value:
                walk(item, f"{path}[]", True)
        elif value is not None and value != "":
            if in_array:
                flat.setdefault(path, []).append(value)
            else:
                flat[path] = value

    walk(entry, "", False)
    return flat


# ---------------------------------------------------------------------------

READERS = {
    "otrf-json-zip": read_otrf_zip,
    "wineventlog-text": read_wineventlog_text,
}


def read_source(path: Path, fmt: str) -> Iterator[dict]:
    """Yield normalized events from a downloaded dataset file."""
    return READERS[fmt](path)
