# YARA test samples

Test data for `rules/yara/`. Origin: **synthetic** (hand-written for this repo).

- `benign/`: ordinary files that resemble secrets but contain none, such as a public
  certificate, a header-only mention of a private key in documentation, service account
  *metadata*, Terraform state with no secret attributes (or only Secret Manager resource
  names), and example configs with placeholders.
  No YARA rule may match any of them.
- Positive samples are **not committed**. `tests/test_yara_rules.py` generates obviously
  fake keys in a temporary directory at test time, assembling secret-shaped strings from
  pieces. Committing them would (correctly) trip this repo's gitleaks hook and GitHub push
  protection, and would teach secret scanners to ignore this repository.

No real credentials and no malware are stored here.
