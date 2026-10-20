# Draft issue for AttackIQ/pySigma-backend-secops

Not yet posted. Target: https://github.com/AttackIQ/pySigma-backend-secops/issues
(checked 2026-10-20: no existing issue covers this; the tracker had issues #3 and #4, neither related).

---

**Title:** UDM output drops the NOT from a negated multi-condition filter (`sel and not filter`)

### Summary

When a negated selection has two or more AND-ed conditions, the `secops_udm` output keeps
the conditions but drops the negation. `sel and not filter` becomes `sel AND filter`. The
query is valid, so nothing warns you, and the rule alerts only on the activity it was meant
to exclude.

### Versions

- pySigma 1.5.1
- pySigma-backend-secops 1.0.0
- Python 3.12.5 (Windows 11)

### Reproduction

```python
from sigma.collection import SigmaCollection
from sigma.backends.secops import SecOpsBackend
from sigma.plugins import InstalledSigmaPlugins

RULE = r"""
title: Dropped NOT repro
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        Image|endswith: '\cmd.exe'
    filter:
        ParentImage|endswith: '\explorer.exe'
        User: 'alice'
    condition: sel and not filter
"""

resolver = InstalledSigmaPlugins.autodiscover().get_pipeline_resolver()
backend = SecOpsBackend(resolver.resolve(["secops_udm"]))
for query in backend.convert(SigmaCollection.from_yaml(RULE)):
    print(query)
```

### Actual output

```
(metadata.event_type = "PROCESS_LAUNCH") AND (target.process.file.full_path = /\\cmd\.exe$/ nocase AND principal.process.file.full_path = /\\explorer\.exe$/ nocase AND target.user.userid = "alice" nocase)
```

There is no `NOT` and no `!=`: the filter conditions are AND-ed in as positive matches.

### Expected output

The filter negated, for example:

```
(metadata.event_type = "PROCESS_LAUNCH") AND (target.process.file.full_path = /\\cmd\.exe$/ nocase AND (principal.process.file.full_path != /\\explorer\.exe$/ nocase OR target.user.userid != "alice" nocase))
```

or the equivalent `NOT (principal.process.file.full_path = ... AND target.user.userid = ...)`.

### Contrast: the single-condition case works

Removing `User: 'alice'` from `filter` gives the correct result:

```
(metadata.event_type = "PROCESS_LAUNCH") AND (target.process.file.full_path = /\\cmd\.exe$/ nocase AND principal.process.file.full_path != /\\explorer\.exe$/ nocase)
```

A negated OR (a list of values under one field) is also handled correctly, becoming
`!= ... AND != ...`. Only a negated AND loses its negation.

### Possible cause

In `sigma/backends/secops/secops.py`, `convert_condition` routes an AND whose parent is a
NOT to `convert_condition_and(cond, state, negation=True)`. There, `negation` only decides
whether children are grouped; the children are converted with `parent_cond=cond.parent`
rather than as negated, and the joiner stays `AND`. `convert_condition_not` then returns the
string result unchanged (only a `DeferredQueryExpression` is negated). So the negation is
lost on this path.

### Impact

The generated query compiles and looks plausible, so the error is easy to miss in review.
Any rule using `sel and not filter` with a multi-condition filter (a common pattern for
excluding known-good activity) inverts its intent: it fires only on the excluded activity
and never on what it was meant to detect.
