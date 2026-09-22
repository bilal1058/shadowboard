"""Detect obvious holdout vocabulary leakage into evaluator development code."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VOCAB_PATH = ROOT / "validation" / "holdout" / "vocabulary.json"
CHECK_PATHS = (
    ROOT / "backend" / "app" / "verifier" / "execution_evaluator.py",
    ROOT / "backend" / "app" / "bench" / "probe_suite.py",
    ROOT / "backend" / "tests",
)


def iter_files(path: Path):
    if path.is_file():
        yield path
    else:
        yield from path.rglob("*.py")


def main() -> int:
    vocabulary = json.loads(VOCAB_PATH.read_text(encoding="utf-8"))
    terms = [term for values in vocabulary.values() for term in values]
    hits = []
    for path in CHECK_PATHS:
        for candidate in iter_files(path):
            text = candidate.read_text(encoding="utf-8")
            for term in terms:
                if term in text:
                    hits.append({"file": str(candidate.relative_to(ROOT)), "term": term})

    result = {"contaminated": bool(hits), "checked_terms": terms, "hits": hits}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
