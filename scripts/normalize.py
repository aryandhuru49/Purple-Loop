"""Turn raw public datasets into one flat, consistent JSON event schema.

Different log shippers produce the same Windows event in different shapes:
  * OTRF Security-Datasets: JSON lines written by nxlog/logstash, with extra
    shipping metadata, string or integer EventIDs, and inconsistent channel
    casing ("Security" vs "security").
  * Splunk attack_data: Splunk's classic multi-line "key=value" WinEventLog
    text, where event fields are human-readable labels ("Ticket Encryption Type").

Detection rules should not care about any of that. Every event that leaves this
module uses the native Windows/Sysmon field names that Sigma rules are written
against (EventID, Channel, Image, CommandLine, TicketEncryptionType, ...).
"""

import json
import re
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

READERS = {
    "otrf-json-zip": read_otrf_zip,
    "wineventlog-text": read_wineventlog_text,
}


def read_source(path: Path, fmt: str) -> Iterator[dict]:
    """Yield normalized events from a downloaded dataset file."""
    return READERS[fmt](path)
