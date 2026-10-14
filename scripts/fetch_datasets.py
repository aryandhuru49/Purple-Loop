"""Download the raw public datasets listed in tests/data/sources.yaml.

Files go to .cache/datasets/ (gitignored). Only the small curated samples
extracted from them are committed; see scripts/extract_samples.py.

Each download is checked against the SHA-256 recorded in sources.yaml.
If a source has no hash yet, the script prints it so it can be pinned
(trust on first use). Use --record to write new hashes into sources.yaml.

Usage:
    uv run python scripts/fetch_datasets.py            # download + verify
    uv run python scripts/fetch_datasets.py --record   # also pin missing hashes
"""

import argparse
import hashlib
import sys
from pathlib import Path

import requests
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = REPO_ROOT / "tests" / "data" / "sources.yaml"
CACHE_DIR = REPO_ROOT / ".cache" / "datasets"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cache_path(source: dict) -> Path:
    """Local file name: <id> plus the original extension (.zip or .log)."""
    suffix = Path(source["url"]).suffix
    return CACHE_DIR / f"{source['id']}{suffix}"


def download(url: str, dest: Path) -> None:
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    # Git LFS returns a tiny text pointer instead of the file if the URL is wrong.
    if response.content.startswith(b"version https://git-lfs"):
        raise RuntimeError(f"Got a Git LFS pointer instead of data for {url}")
    dest.write_bytes(response.content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--record", action="store_true", help="pin missing hashes in sources.yaml")
    args = parser.parse_args()

    sources_doc = yaml.safe_load(SOURCES_FILE.read_text(encoding="utf-8"))
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    failures = 0
    new_hashes: dict[str, str] = {}
    for source in sources_doc["sources"]:
        dest = cache_path(source)
        if not dest.exists():
            print(f"[download] {source['id']}")
            download(source["url"], dest)

        actual = sha256_of(dest)
        expected = source.get("sha256")
        if expected is None:
            print(f"[new hash] {source['id']}: {actual}")
            new_hashes[source["id"]] = actual
        elif actual != expected:
            print(f"[MISMATCH] {source['id']}: expected {expected}, got {actual}")
            failures += 1
        else:
            print(f"[ok]       {source['id']} ({dest.stat().st_size:,} bytes)")

    if args.record and new_hashes:
        # Edit the hash lines in place so the file's comments and layout survive.
        lines = SOURCES_FILE.read_text(encoding="utf-8").splitlines(keepends=True)
        current_id = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("- id:"):
                current_id = stripped.split(":", 1)[1].strip()
            elif stripped == "sha256: null" and current_id in new_hashes:
                lines[i] = line.replace("null", new_hashes[current_id])
        # newline="\n" keeps LF endings on Windows too (repo standard, see .gitattributes).
        SOURCES_FILE.write_text("".join(lines), encoding="utf-8", newline="\n")
        print(f"Recorded {len(new_hashes)} hash(es) in {SOURCES_FILE.relative_to(REPO_ROOT)}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
