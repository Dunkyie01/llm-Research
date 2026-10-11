#!/usr/bin/env python3
"""
verify_jsonl.py - check a chunks/index JSONL file and score it out of 10 for:

  COMPATIBILITY  will oss_harvester.py (embed / ask) run on this file without
                 crashing, and is every row shaped the way it expects?
  QUALITY        is the text itself good retrieval / training material?

Works on both file types in the pipeline:
  chunks file  (from owasp_harvester.py / oss_harvester.py harvest)
  index file   (from oss_harvester.py embed - has an "embedding" per row)

Usage:
  python verify_jsonl.py data/owasp.jsonl
  python verify_jsonl.py data/owasp_index.jsonl --min-score 7   # exit code 1 if below
  python verify_jsonl.py data/owasp.jsonl --report out/check.json
  python verify_jsonl.py data/owasp.jsonl --no-report

Scoring: each check has a weight; a check's credit drops 4% for every 1% of rows that fail it.
If any row would break the pipeline (bad JSON, missing fields, bad embeddings) compatibility
is capped at 6.0 no matter what else passes.

No dependencies beyond the standard library.
"""

import argparse
import hashlib
import json
import math
import re
import shutil
import sys
import time
from collections import Counter
from pathlib import Path

MAX_EXAMPLES = 3
MIN_LEN, MAX_LEN = 80, 3000          # sensible chunk length range (characters)
MIN_WORDS = 15                        # below this a chunk carries little information

REQUIRED = ("repo", "path", "text")   # needed by `embed`
RECOMMENDED = ("url", "chunk", "license")  # used by `ask` (sources) and attribution

# Leftover markdown/HTML syntax that the cleaner should have removed.
# (Code samples can trigger these legitimately, e.g. XSS examples - it's a heuristic.)
MARKUP = {
    "markdown link": re.compile(r"\]\(\s*https?://"),
    "image syntax": re.compile(r"!\[[^\]]*\]\("),
    "bold markers": re.compile(r"\*\*\S[^*\n]+\*\*"),
    "heading markers": re.compile(r"(?m)^#{2,6}\s+\S"),
    "table syntax": re.compile(r"(?m)^\s*\|?\s*:?-{3,}:?\s*\||^\|.*\|.*\|\s*$"),
    "html tags": re.compile(r"</?(?:p|br|div|span|em|strong|table|tr|td|ul|li|h[1-6])\b[^>]*>", re.I),
    "html comment": re.compile(r"<!--"),
    "front matter": re.compile(r"\A---\s*\n[\w-]+:"),
}
GARBAGE = {
    "replacement character": re.compile("\ufffd"),
    "control characters": re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"),
    "mojibake": re.compile("Ã[\u0080-\u00bf]|â€|Â[\u00a0-\u00bf]"),
    "huge unbroken token": re.compile(r"\S{300,}"),
}


# --------------------------------------------------------------------------
# Progress / output helpers (same as owasp_harvester.py)
# --------------------------------------------------------------------------
IS_TTY = sys.stdout.isatty()


def progress(done, total, label="", width=28):
    """Single-line progress bar. Falls back to occasional lines if not a terminal."""
    if not IS_TTY:
        if total and (done == total or done % max(1, total // 10) == 0):
            print(f"  {done}/{total}", flush=True)
        return
    pct = done / total if total else 1.0
    filled = int(width * pct)
    bar = "#" * filled + "-" * (width - filled)
    text = f"[{bar}] {done}/{total} {pct:4.0%} {label}"
    cols = shutil.get_terminal_size((80, 20)).columns
    sys.stdout.write("\r" + text[: cols - 1].ljust(cols - 1))
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")


def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


# --------------------------------------------------------------------------
# Checks and scoring
# --------------------------------------------------------------------------
class Check:
    def __init__(self, key, label, weight, advice):
        self.key, self.label, self.weight, self.advice = key, label, weight, advice
        self.passed: float = 0      # float: the source-balance check stores a fractional pass
        self.total: int = 0
        self.examples: list = []

    def add(self, ok, line=None, note=""):
        self.total += 1
        if ok:
            self.passed += 1
        elif len(self.examples) < MAX_EXAMPLES:
            self.examples.append({"line": line, "note": note})

    @property
    def frac(self):
        return self.passed / self.total if self.total else 1.0

    def status(self):
        if not self.total:
            return "N/A "
        return "OK  " if self.frac >= 0.98 else ("WARN" if self.frac >= 0.90 else "FAIL")


def score(checks):
    live = [c for c in checks if c.total]
    if not live:
        return 0.0
    # Each check's pass rate is turned into credit with a steep curve (1% of bad rows
    # costs 4% of that check's weight), so scattered defects visibly move the score.
    credit = lambda f: max(0.0, 1 - 4 * (1 - f))
    s = 10 * sum(c.weight * credit(c.frac) for c in live) / sum(c.weight for c in live)
    s = round(s, 1)
    if s >= 10.0 and any(c.frac < 1 for c in live):
        s = 9.9                                    # never show 10 if something failed
    return s


def rating(s):
    return ("Excellent" if s >= 9 else "Good" if s >= 7.5 else
            "Fair" if s >= 6 else "Poor" if s >= 4 else "Bad")


def check_embedding(emb):
    if not isinstance(emb, list) or not emb:
        return "not a non-empty list"
    if not all(isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) for x in emb):
        return "non-numeric or non-finite values"
    if not any(emb):
        return "all-zero vector"
    return None


def percentile(sorted_vals, p):
    if not sorted_vals:
        return 0
    return sorted_vals[min(len(sorted_vals) - 1, int(len(sorted_vals) * p))]


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------
def verify(path):
    # ----- compatibility checks
    c_utf8 = Check("utf8", "Valid UTF-8 encoding", 1.0,
                   "Re-save the file as UTF-8 (the harvesters write UTF-8 by default).")
    c_json = Check("json", "Each line is a JSON object", 2.0,
                   "Remove or regenerate the malformed lines - embed will crash on them.")
    c_req = Check("required", "Required fields present (repo, path, text)", 2.5,
                  "Rows missing repo/path/text will raise KeyError in the embed step.")
    c_types = Check("types", "Field types correct, text not empty", 1.5,
                    "repo/path/text must be non-empty strings.")
    c_rec = Check("recommended", "Recommended fields present (url, chunk, license)", 1.0,
                  "url is shown by `ask` as the source link; license/chunk keep attribution and ordering.")
    c_uniq = Check("unique", "No duplicate (repo, path, chunk) keys", 1.0,
                   "Duplicate keys suggest the file was appended to or built twice.")
    c_emb = Check("embeddings", "Embeddings valid and same dimension", 2.0,
                  "Re-run `embed` with a single model; every row needs a finite, non-zero, same-length vector.")
    compat = [c_utf8, c_json, c_req, c_types, c_rec, c_uniq, c_emb]
    blocking = [c_utf8, c_json, c_req, c_types, c_emb]

    # ----- quality checks
    q_len = Check("length", f"Chunk length {MIN_LEN}-{MAX_LEN} chars", 2.0,
                  "Raise --min-chars to drop tiny chunks and/or lower --chunk-size to split huge ones.")
    q_markup = Check("markup", "No leftover markdown/HTML syntax", 2.0,
                     "The cleaner missed some formatting - extend the regexes in clean_line().")
    q_dup = Check("duplicates", "No duplicate text", 1.5,
                  "De-duplicate rows (the same text appears more than once).")
    q_garbage = Check("garbage", "No encoding junk / blobs", 1.5,
                      "Look for mojibake, control characters or base64-like blobs in the source files.")
    q_dense = Check("density", f"Enough content (>= {MIN_WORDS} words)", 1.5,
                    "Very short chunks retrieve poorly - raise --min-chars.")
    q_bal = Check("balance", "Not dominated by one source file", 1.5,
                  "One file supplies most chunks, so answers will skew toward it - add more sources.")
    quality = [q_len, q_markup, q_dup, q_garbage, q_dense, q_bal]

    size = path.stat().st_size
    with path.open("rb") as f:
        total_lines = sum(1 for _ in f)

    rows = blanks = 0
    is_index = None
    seen_keys, seen_text = set(), {}
    dims = Counter()
    paths, repos, licenses = Counter(), Counter(), Counter()
    lengths = []
    step = max(1, total_lines // 200)

    with path.open("rb") as f:
        for lineno, raw in enumerate(f, 1):
            if lineno % step == 0 or lineno == 1:
                progress(lineno - 1, total_lines, f"line {lineno}")
            raw = raw.rstrip(b"\r\n")
            if not raw.strip():
                blanks += 1
                continue
            rows += 1

            try:
                line = raw.decode("utf-8")
                c_utf8.add(True)
            except UnicodeDecodeError:
                c_utf8.add(False, lineno, "invalid UTF-8 byte sequence")
                line = raw.decode("utf-8", "replace")

            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("not an object")
                c_json.add(True)
            except (ValueError, json.JSONDecodeError) as e:
                c_json.add(False, lineno, f"invalid JSON ({e})")
                c_req.add(False, lineno, "unparseable line")
                continue

            if is_index is None:
                is_index = "embedding" in row

            missing = [k for k in REQUIRED if k not in row]
            c_req.add(not missing, lineno, f"missing: {', '.join(missing)}")

            bad = [k for k in ("repo", "path") if k in row and not (isinstance(row[k], str) and row[k].strip())]
            if "text" in row and not (isinstance(row["text"], str) and row["text"].strip()):
                bad.append("text")
            if "repo" in row or "path" in row or "text" in row:
                c_types.add(not bad, lineno, f"wrong type or empty: {', '.join(bad)}")

            rec_missing = []
            if not (isinstance(row.get("url"), str) and row["url"]):
                rec_missing.append("url")
            if not (isinstance(row.get("chunk"), int) and not isinstance(row.get("chunk"), bool)):
                rec_missing.append("chunk")
            if not (isinstance(row.get("license"), str) and row["license"]):
                rec_missing.append("license")
            c_rec.add(not rec_missing, lineno, f"missing/invalid: {', '.join(rec_missing)}")

            if isinstance(row.get("chunk"), int) and isinstance(row.get("repo"), str) and isinstance(row.get("path"), str):
                key = (row["repo"], row["path"], row["chunk"])
                c_uniq.add(key not in seen_keys, lineno, f"duplicate key {row['path']}#{row['chunk']}")
                seen_keys.add(key)

            if is_index:
                problem = check_embedding(row.get("embedding")) if "embedding" in row else "no embedding field"
                c_emb.add(problem is None, lineno, problem or "")
                if problem is None:
                    dims[len(row["embedding"])] += 1

            # ---- quality (only rows with usable text)
            text = row.get("text")
            if not (isinstance(text, str) and text.strip()):
                continue
            stripped = text.strip()
            if isinstance(row.get("path"), str):
                paths[row["path"]] += 1
            if isinstance(row.get("repo"), str):
                repos[row["repo"]] += 1
            if isinstance(row.get("license"), str):
                licenses[row["license"]] += 1

            n = len(stripped)
            lengths.append(n)
            q_len.add(MIN_LEN <= n <= MAX_LEN, lineno, f"{n} chars ({'too short' if n < MIN_LEN else 'too long'})")

            hit = next((name for name, rx in MARKUP.items() if rx.search(text)), None)
            q_markup.add(hit is None, lineno, f"looks like {hit}" if hit else "")

            norm = hashlib.md5(" ".join(stripped.lower().split()).encode()).hexdigest()
            first = seen_text.get(norm)
            q_dup.add(first is None, lineno, f"same text as line {first}")
            seen_text.setdefault(norm, lineno)

            hit = next((name for name, rx in GARBAGE.items() if rx.search(text)), None)
            q_garbage.add(hit is None, lineno, hit or "")

            words = len(stripped.split())
            q_dense.add(words >= MIN_WORDS, lineno, f"only {words} word(s)")

    progress(total_lines, total_lines, "done")

    # embedding dimension consistency
    if is_index and c_emb.total:
        mode_dim = dims.most_common(1)[0][0] if dims else None
        if mode_dim is not None:
            c_emb.passed = dims[mode_dim]
            if len(dims) > 1 and len(c_emb.examples) < MAX_EXAMPLES:
                c_emb.examples.append({"line": None, "note": f"mixed dimensions: {dict(dims)}"})

    # source balance (only meaningful with enough rows)
    if sum(paths.values()) >= 20 and paths:
        share = max(paths.values()) / sum(paths.values())
        q_bal.total = 1
        q_bal.passed = 1.0 if share <= 0.2 else max(0.0, 1 - (share - 0.2) / 0.6)
        if q_bal.passed < 0.98:
            top = paths.most_common(1)[0]
            q_bal.examples.append({"line": None, "note": f"{top[0]} supplies {share:.0%} of chunks"})

    lengths.sort()
    stats = {
        "rows": rows, "blank_lines": blanks, "file_type": "index (with embeddings)" if is_index else "chunks",
        "repos": len(repos), "source_files": len(paths), "licenses": dict(licenses),
        "embedding_dims": dict(dims) if is_index else None,
        "length_chars": {"min": lengths[0] if lengths else 0, "median": percentile(lengths, 0.5),
                         "p95": percentile(lengths, 0.95), "max": lengths[-1] if lengths else 0},
    }
    return compat, blocking, quality, stats, size, total_lines


# --------------------------------------------------------------------------
def print_checks(title, checks):
    print(f"\n{title}")
    for c in checks:
        pct = f"{c.frac:6.1%}" if c.total else "   n/a"
        print(f"  [{c.status()}] {c.label:<52} {pct}  (weight {c.weight})")
        for ex in c.examples:
            where = f"line {ex['line']}: " if ex["line"] else ""
            print(f"           - {where}{ex['note']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="chunks or index .jsonl file")
    ap.add_argument("--report", help="where to save the JSON report (default: next to the input)")
    ap.add_argument("--no-report", action="store_true", help="don't write a report file")
    ap.add_argument("--min-score", type=float,
                    help="exit with code 1 if either score is below this (handy in scripts)")
    args = ap.parse_args()

    path = Path(args.input)
    if not path.is_file():
        raise SystemExit(f"File not found: {path.resolve()}")

    print(f"Verifying: {path.resolve()}")
    start = time.time()
    compat, blocking, quality, stats, size, total_lines = verify(path)
    print(f"  ({human_size(size)}, {total_lines} lines)")

    if stats["rows"] == 0:
        raise SystemExit("File is empty - nothing to verify (compatibility 0/10, quality 0/10).")

    compat_score, quality_score = score(compat), score(quality)
    blockers = [c for c in blocking if c.total and c.frac < 1]
    if blockers and compat_score > 6.0:
        compat_score = 6.0          # at least one row would break the pipeline

    print_checks("Compatibility checks", compat)
    print_checks("Quality checks", quality)

    print("\nStats")
    s = stats
    print(f"  File type    : {s['file_type']}")
    print(f"  Rows         : {s['rows']}  ({s['repos']} repo(s), {s['source_files']} source files)")
    ln = s["length_chars"]
    print(f"  Chunk length : min {ln['min']} / median {ln['median']} / p95 {ln['p95']} / max {ln['max']} chars")
    if s["licenses"]:
        print(f"  Licenses     : {', '.join(f'{k} ({v})' for k, v in s['licenses'].items())}")
    if s["embedding_dims"]:
        print(f"  Embedding dim: {', '.join(f'{k} ({v} rows)' for k, v in s['embedding_dims'].items())}")

    advice = [f"{c.label}: {c.advice}" for c in compat + quality if c.total and c.frac < 0.98]
    if blockers:
        first = next((e["line"] for c in blockers for e in c.examples if e["line"]), None)
        print("\n!! Blocking problem: the embed/ask steps would fail or give wrong results on this file"
              + (f" (first bad row: line {first})" if first else "") + ". Compatibility is capped at 6.0.")
    if advice:
        print("\nSuggested fixes")
        for a in advice:
            print(f"  - {a}")

    print("\n" + "=" * 52)
    print(f"  COMPATIBILITY : {compat_score:4.1f} / 10   ({rating(compat_score)})")
    print(f"  QUALITY       : {quality_score:4.1f} / 10   ({rating(quality_score)})")
    print("=" * 52)

    if not args.no_report:
        report_path = Path(args.report) if args.report else path.with_suffix(".report.json")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "input": str(path.resolve()), "size_bytes": size, "lines": total_lines,
            "seconds": round(time.time() - start, 2),
            "scores": {"compatibility": compat_score, "quality": quality_score},
            "ratings": {"compatibility": rating(compat_score), "quality": rating(quality_score)},
            "blocking_issue": bool(blockers),
            "checks": [{"group": g, "key": c.key, "label": c.label, "weight": c.weight,
                        "passed": c.passed, "total": c.total,
                        "pass_rate": round(c.frac, 4) if c.total else None, "examples": c.examples}
                       for g, cs in (("compatibility", compat), ("quality", quality)) for c in cs],
            "stats": stats, "suggested_fixes": advice,
        }
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nReport saved to: {report_path.resolve()}  ({human_size(report_path.stat().st_size)})")

    if args.min_score is not None and min(compat_score, quality_score) < args.min_score:
        sys.exit(1)


if __name__ == "__main__":
    main()