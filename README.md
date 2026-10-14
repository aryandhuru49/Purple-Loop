# Purple Loop

> Purple Loop turns simulated attacks into tested, portable detections.

**Status:** under construction (Phase 1: detection pipeline using public datasets).

Purple Loop is a detection-as-code repository. Sigma rules are the source of truth. Every rule is
automatically tested against labeled malicious and benign logs, converted to Splunk SPL and
Google SecOps YARA-L 2.0, and mapped onto MITRE ATT&CK coverage, all in CI.

The full README (architecture, rule lifecycle, coverage map, limitations, quick start) will be
written as the phases land.
