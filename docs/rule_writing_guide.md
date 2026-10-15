# Rule writing guide

How to add a Sigma rule to Purple Loop so that CI accepts it.

## 1. Get attack telemetry

Use a public dataset (add it to `tests/data/sources.yaml`, then run
`scripts/fetch_datasets.py --record` to pin its hash) or the Phase 2 lab export.
Check the dataset's license first; it must be compatible with MIT.

## 2. Add malicious samples

Add an entry to `tests/data/manifest.yaml`:

```yaml
- output: malicious/<rule_file_name>/<source_id>.jsonl
  label: malicious
  origin: public-dataset
  source: <source id>
  technique: T1234.001
  why: One line on what the events show.
  where:                      # Sigma-style filter that selects only the attack events
    EventID: 1
    Image|endswith: '\evil.exe'
  expected_count: 1
```

Run `uv run python scripts/extract_samples.py`. The folder name must equal the rule's
file name (without `.yml`).

## 3. Write the rule

Place it in `rules/sigma/<tactic>/<logsource>_win_<what_it_detects>.yml`. Required, and
enforced by `tests/test_rule_quality.py`:

- `title`, a fresh UUID `id`, `status`, `author`, `date`, `references`
- a `description` of at least 25 words explaining *why* the behavior is suspicious
- `tags` with the ATT&CK tactic (v20 names, e.g. `attack.stealth`) and at least one
  `attack.tXXXX` technique
- `falsepositives`, quoted strings (an unquoted `text: more` becomes a YAML mapping)
- `level`

Guidelines that kept the existing rules precise:

- Key on behavior, not names an attacker controls. Match `OriginalFileName` as well as
  `Image` so renamed binaries are caught.
- Require two independent signals where one alone is noisy (e.g. hidden window **and**
  encoded command).
- Make look-alikes fail on purpose: `\CurrentVersion\Run\` with a trailing backslash
  does not match `\RunTime\`.
- Exclude known-good with the narrowest filter possible (exact signed path, not a folder).

## 4. Add benign near-misses

Add at least one legitimate event to `tests/data/benign/synthetic_near_misses.jsonl` that
looks like the attack but must not fire, with a `_synthetic_note`. The harness also fails
a rule if no benign event of its log type exists.

## 5. Run the checks

```bash
uv run sigma check rules/sigma
uv run python scripts/run_sigma_tests.py        # your rule must show PASS
uv run pytest
uv run python scripts/convert_rules.py          # must convert to Splunk
uv run python scripts/generate_coverage.py
```

Commit the rule, samples, manifest change and regenerated `converted/` and `coverage/`
together. CI will reject the change if any generated file is stale.
