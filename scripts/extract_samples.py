"""Build the committed test samples from the cached public datasets.

tests/data/manifest.yaml lists every sample file. For each one it names the
source dataset and a filter that picks the events to keep. Filters use the same
"field|modifier: value" style as Sigma rules, so the whole repo reads alike:

    where:
      EventID: 10                        # equals (case-insensitive for text)
      TargetImage|endswith: '\\lsass.exe'
      CommandLine|contains: ' -enc '
      Image|endswith: ['\\a.exe', '\\b.exe']   # a list means "any of"

Each entry also states expected_count. If an upstream dataset changes and the
filter matches a different number of events, the build fails loudly instead of
silently testing against different data.

Usage:
    uv run python scripts/fetch_datasets.py     # once, to fill .cache/
    uv run python scripts/extract_samples.py    # writes tests/data/**.jsonl
    uv run python scripts/extract_samples.py --check   # verify committed files are current
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml
from fetch_datasets import cache_path
from normalize import read_source

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "tests" / "data"
SOURCES_FILE = DATA_DIR / "sources.yaml"
MANIFEST_FILE = DATA_DIR / "manifest.yaml"


# ---------------------------------------------------------------------------
# Filter matching (a tiny subset of Sigma's field modifiers)
# ---------------------------------------------------------------------------


def _value_matches(actual, op: str, expected) -> bool:
    if actual is None:
        return False
    if isinstance(expected, int) and not isinstance(expected, bool):
        return op == "equals" and actual == expected
    actual, expected = str(actual).lower(), str(expected).lower()
    if op == "equals":
        return actual == expected
    if op == "contains":
        return expected in actual
    if op == "endswith":
        return actual.endswith(expected)
    if op == "startswith":
        return actual.startswith(expected)
    raise ValueError(f"Unknown filter modifier: {op}")


def event_matches(event: dict, where: dict) -> bool:
    """True if the event satisfies every condition in `where` (logical AND)."""
    for key, expected in where.items():
        field, _, op = key.partition("|")
        options = expected if isinstance(expected, list) else [expected]
        if not any(_value_matches(event.get(field), op or "equals", o) for o in options):
            return False
    return True


# ---------------------------------------------------------------------------


def build_outputs() -> tuple[dict[str, list[dict]], list[str]]:
    """Return {output path: events} for every manifest entry, plus any errors."""
    sources = {s["id"]: s for s in yaml.safe_load(SOURCES_FILE.read_text("utf-8"))["sources"]}
    manifest = yaml.safe_load(MANIFEST_FILE.read_text("utf-8"))

    events_cache: dict[str, list[dict]] = {}
    outputs: dict[str, list[dict]] = defaultdict(list)
    errors: list[str] = []

    for sample in manifest["samples"]:
        source = sources[sample["source"]]
        if source["id"] not in events_cache:
            path = cache_path(source)
            if not path.exists():
                sys.exit(f"Missing {path}. Run scripts/fetch_datasets.py first.")
            events_cache[source["id"]] = list(read_source(path, source["format"]))

        matched = [e for e in events_cache[source["id"]] if event_matches(e, sample["where"])]
        if len(matched) != sample["expected_count"]:
            errors.append(
                f"{sample['output']} <- {source['id']}: filter matched {len(matched)} "
                f"events, manifest expects {sample['expected_count']}"
            )
        outputs[sample["output"]].extend(matched)

    return outputs, errors


def to_jsonl(events: list[dict]) -> str:
    # sort_keys gives stable, diff-friendly output across runs and platforms.
    return "".join(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n" for e in events)


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract curated test samples.")
    parser.add_argument("--check", action="store_true", help="fail if committed files are stale")
    args = parser.parse_args()

    outputs, errors = build_outputs()
    for error in errors:
        print(f"[COUNT MISMATCH] {error}")

    stale = 0
    for rel_path, events in sorted(outputs.items()):
        path = DATA_DIR / rel_path
        content = to_jsonl(events)
        if args.check:
            current = path.read_text("utf-8") if path.exists() else None
            if current != content:
                print(f"[STALE] {rel_path}")
                stale += 1
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
            print(f"[wrote] {rel_path} ({len(events)} events)")

    return 1 if errors or stale else 0


if __name__ == "__main__":
    sys.exit(main())
