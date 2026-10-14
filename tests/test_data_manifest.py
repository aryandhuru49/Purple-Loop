"""Keep the test data honest.

Every JSONL file under tests/data must be described in manifest.yaml with a
label (malicious or benign) and an origin (where the events came from), and
must trace back to a source with a recorded license. These checks need no
network access, so they run on every CI build.
"""

import json
from pathlib import Path

import pytest
import yaml

DATA_DIR = Path(__file__).parent / "data"
MANIFEST = yaml.safe_load((DATA_DIR / "manifest.yaml").read_text("utf-8"))["samples"]
SOURCES = {
    s["id"]: s for s in yaml.safe_load((DATA_DIR / "sources.yaml").read_text("utf-8"))["sources"]
}

VALID_LABELS = {"malicious", "benign"}
VALID_ORIGINS = {"public-dataset", "self-generated", "synthetic"}


def test_every_sample_file_is_in_the_manifest():
    on_disk = {p.relative_to(DATA_DIR).as_posix() for p in DATA_DIR.rglob("*.jsonl")}
    in_manifest = {s["output"] for s in MANIFEST}
    assert on_disk - in_manifest == set(), "sample files missing from manifest.yaml"
    assert in_manifest - on_disk == set(), "manifest entries with no file on disk"


@pytest.mark.parametrize("sample", MANIFEST, ids=lambda s: s["output"])
def test_manifest_entry_is_complete(sample):
    assert sample["label"] in VALID_LABELS
    assert sample["origin"] in VALID_ORIGINS
    # The folder must agree with the label, so a sample can't be mislabeled.
    assert sample["output"].split("/")[0] == sample["label"]
    if sample["origin"] == "public-dataset":
        source = SOURCES[sample["source"]]
        assert source["license"], f"{source['id']} has no license recorded"
        assert source["sha256"], f"{source['id']} has no pinned hash"
    if sample["label"] == "malicious":
        assert sample["technique"].startswith("T"), "malicious samples need an ATT&CK technique"


@pytest.mark.parametrize("path", sorted(DATA_DIR.rglob("*.jsonl")), ids=lambda p: p.name)
def test_sample_files_are_valid_jsonl(path):
    lines = path.read_text("utf-8").splitlines()
    assert lines, f"{path} is empty"
    for line in lines:
        event = json.loads(line)
        assert isinstance(event["EventID"], int)
        assert event["Channel"]
