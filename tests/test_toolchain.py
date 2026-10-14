"""Smoke tests for the Sigma toolchain.

These run before any real rules exist. They prove that the pinned pySigma
version and the three backends we depend on (SQLite for testing, Splunk and
Google SecOps for conversion) install together and can convert a rule.
If a dependency upgrade breaks compatibility, these fail first with a clear message.
"""

from sigma.backends.secops import SecOpsBackend
from sigma.backends.splunk import SplunkBackend
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.secops import secops_udm_pipeline
from sigma.pipelines.splunk import splunk_windows_pipeline

# A minimal throwaway rule, used only to exercise each backend.
SAMPLE_RULE = """
title: Toolchain Smoke Test
id: 00000000-0000-0000-0000-000000000001
status: test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\whoami.exe'
    condition: selection
level: low
"""


def _rule() -> SigmaCollection:
    return SigmaCollection.from_yaml(SAMPLE_RULE)


def test_sqlite_backend_converts():
    queries = sqliteBackend().convert(_rule())
    assert len(queries) == 1
    assert "whoami.exe" in queries[0]


def test_splunk_backend_converts():
    queries = SplunkBackend(splunk_windows_pipeline()).convert(_rule())
    assert len(queries) == 1
    assert "whoami.exe" in queries[0]


def test_secops_backend_converts():
    queries = SecOpsBackend(secops_udm_pipeline()).convert(_rule())
    assert len(queries) == 1
    # The SecOps backend turns `endswith` into a regex (whoami\.exe$), so check
    # for the bare name plus the UDM field the pipeline should map Image onto.
    assert "whoami" in queries[0]
    assert "target.process.file.full_path" in queries[0]
