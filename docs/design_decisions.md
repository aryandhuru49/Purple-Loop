# Design decisions

Short records of the choices that shaped this repo, and why.

## Sigma as the source of truth

Sigma is vendor-neutral and has a mature conversion ecosystem (pySigma). Writing rules
once and generating SPL and SecOps output keeps the logic in one place. Native YARA-L is
used only where Sigma can't express the idea (multi-event correlation), not as a second copy.

## Test harness: pySigma SQLite backend, not Zircolite

Both are maintained. Zircolite is a standalone EVTX hunting tool; the SQLite backend is a
library, so the same toolchain does conversion *and* testing, it plugs straight into pytest,
and the test table is easy to generate. Two SQLite details had to be handled to match Sigma
semantics: text columns use `COLLATE NOCASE` (Sigma matching is case-insensitive, SQLite's
`=` is not), and a field a rule references but no sample contains is added as an empty column
(a real SIEM treats it as absent rather than failing).

A rule passes only if it detects every malicious event, fires on no benign event, **and**
at least one benign event of its own log type exists. The last condition stops "zero false
positives" from being vacuously true.

## pySigma pinned below 2.0

sigma-cli 3.x and the Splunk and SecOps backends require pySigma 1.x; the SQLite backend's
2.x line requires pySigma 2.x. The repo pins pySigma `<2` and the SQLite backend `1.2.x`.

## Curated samples, not whole datasets

Raw datasets are downloaded to a gitignored cache, verified by SHA-256, and only the events
each rule needs are extracted into small JSONL files (about 120 KB total). Extraction filters
live in `tests/data/manifest.yaml` with an expected event count, and CI re-downloads the data
to prove the committed samples rebuild byte-for-byte. Normalization fixes real-world quirks:
OTRF writes `Security` and `security`, stores `EventID` as text in some files, and calls the
provider `SourceName` instead of Sigma's `Provider_Name`.

## Licensing of data

EVTX-ATTACK-SAMPLES is GPL-3.0; deriving test data from it into an MIT repository would
create a licensing mismatch, so it was not used. OTRF (MIT) and Splunk attack_data
(Apache-2.0) cover every technique.

## Benign data: background plus synthetic near-misses

Public datasets don't publish clean baselines. The benign corpus is (a) normal background
events from the same lab hosts and (b) hand-written near-misses aimed at each rule's edge
cases (Defender reading LSASS, a RunMRU key containing "powershell", Windows' own
`regsvr32 /i:` Active Setup call). Synthetic events are labeled `origin: synthetic` and carry
a `_synthetic_note`. The Phase 2 lab will add real benign data.

## Generated files are committed and checked

`converted/`, `coverage/` and the Logica `.sql` files are generated but committed, so readers
can browse them on GitHub. CI regenerates each one and fails if the committed copy differs,
so they can't be hand-edited or go stale. Formatting hooks exclude `converted/` for the same
reason.

## Don't guess field mappings

When the SecOps backend could not map a field to UDM, the rule is reported as unsupported
rather than mapped to a plausible-looking field. A wrong mapping produces a query that
compiles and silently never matches, which is worse than an honest gap.

## ATT&CK v20

Tags are validated against the current ATT&CK release by `sigma check`. In v20, TA0005 is
named Stealth (formerly Defense Evasion), so rules and folders use `stealth`.
