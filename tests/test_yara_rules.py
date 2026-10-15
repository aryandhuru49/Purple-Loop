"""Tests for the YARA credential-exposure rules in rules/yara/.

Positive samples are generated here at test time instead of being committed, because
secret-shaped files in the repo would trip gitleaks and GitHub push protection. Every
secret-like string is assembled from pieces (e.g. "-----BEGIN " + "PRIVATE KEY-----"),
so no complete secret pattern appears in this source file either. All values are
obviously fake: "FAKE" filler that is not valid key material.

Each rule must match all of its positive samples, and no rule may match any file in
tests/yara_samples/benign/.
"""

from pathlib import Path

import pytest
import yara

REPO_ROOT = Path(__file__).resolve().parent.parent
RULE_FILES = sorted((REPO_ROOT / "rules" / "yara").glob("*.yar"))
BENIGN_DIR = REPO_ROOT / "tests" / "yara_samples" / "benign"

FAKE_BODY = "\n".join(["FAKEKEYMATERIALFORPURPLELOOPTESTSNOTAREALKEY0000000000000000"] * 4)


def pem(label: str) -> str:
    """A PEM block with a fake body, e.g. pem("RSA PRIVATE KEY")."""
    dashes = "-" * 5
    return f"{dashes}BEGIN {label}{dashes}\n{FAKE_BODY}\n{dashes}END {label}{dashes}\n"


# rule name -> {sample file name: content}. Every rule needs at least one positive sample.
POSITIVE_SAMPLES = {
    "gcp_service_account_key_file": {
        "lab-sa-key.json": (
            "{\n"
            '  "type": "service_' + 'account",\n'
            '  "project_id": "purple-loop-lab",\n'
            '  "private_key_' + 'id": "0000000000000000000000000000000000000000",\n'
            '  "private_' + 'key": ' + repr(pem("PRIVATE KEY")).replace("'", '"') + ",\n"
            '  "client_email": "lab-sa@purple-loop-lab.iam.gserviceaccount.com",\n'
            '  "client_id": "100000000000000000000"\n'
            "}\n"
        ),
    },
    "pem_private_key": {
        "pkcs8.pem": pem("PRIVATE KEY"),
        "id_rsa": pem("RSA PRIVATE KEY"),
        "ec.key": pem("EC PRIVATE KEY"),
        "id_ed25519": pem("OPENSSH PRIVATE KEY"),
        "encrypted.pem": pem("ENCRYPTED PRIVATE KEY"),
    },
    "terraform_state_with_secrets": {
        "terraform.tfstate.backup": (
            '{"version": 4, "terraform_version": "1.15.8", "serial": 7,\n'
            ' "lineage": "00000000-0000-0000-0000-000000000000",\n'
            ' "resources": [{"type": "random_password", "name": "dsrm",\n'
            '   "instances": [{"attributes": {"result": "x", "pass'
            + 'word": "FAKEpassword123"}}]}]}\n'
        ),
    },
    "cloud_credential_file": {
        "application_default_credentials.json": (
            '{"client_id": "fake.apps.googleusercontent.com",\n'
            ' "client_' + 'secret": "FAKE-client-secret",\n'
            ' "refresh_' + 'token": "FAKE-refresh-token",\n'
            ' "type": "authorized_' + 'user"}\n'
        ),
        "credentials": "[default]\naws_access_key_id = FAKE\naws_secret_access_"
        + "key = "
        + "FAKE" * 10
        + "\n",
        "app.env": "GOOGLE_API_KEY=" + "AI" + "za" + "FAKE" * 8 + "XYZ\n",
    },
}


@pytest.fixture(scope="module")
def rules() -> yara.Rules:
    return yara.compile(filepaths={p.stem: str(p) for p in RULE_FILES})


def rule_names() -> list[str]:
    rules = yara.compile(filepaths={p.stem: str(p) for p in RULE_FILES})
    return sorted(r.identifier for r in rules)


def test_rules_compile_and_every_rule_is_tested():
    assert RULE_FILES, "no YARA rule files found"
    assert set(rule_names()) == set(POSITIVE_SAMPLES), "every rule needs positive samples"


@pytest.mark.parametrize(
    ("rule_name", "file_name"),
    [(r, f) for r, samples in POSITIVE_SAMPLES.items() for f in samples],
)
def test_rule_matches_fake_secret(rules, tmp_path, rule_name, file_name):
    sample = tmp_path / file_name
    sample.write_text(POSITIVE_SAMPLES[rule_name][file_name], encoding="utf-8")
    matched = {m.rule for m in rules.match(str(sample))}
    assert rule_name in matched, f"{rule_name} did not match {file_name}; matched {matched}"


@pytest.mark.parametrize("path", sorted(BENIGN_DIR.iterdir()), ids=lambda p: p.name)
def test_no_rule_matches_benign_file(rules, path):
    matched = [m.rule for m in rules.match(str(path))]
    assert not matched, f"{path.name} matched {matched}"


def test_rules_have_required_metadata(rules):
    for rule in rules:
        for key in ("description", "author", "date", "severity", "mitre_attack_id"):
            assert rule.meta.get(key), f"{rule.identifier} is missing meta {key}"
