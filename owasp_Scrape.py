#!/usr/bin/env python3
"""

What "raw" means here:
  - markdown syntax stripped (headings, bold/italic, links, images, tables, HTML)
  - link text kept, URLs dropped
  - reference / further-reading / tool-list sections dropped (mostly links)
  - code examples kept as plain text (use --no-code to drop them)
  - each chunk is prefixed with its topic and section path, so it still makes
    sense when retrieved on its own

Output is JSONL

Usage:
  python owasp_harvester.py                      # everything -> data/owasp.jsonl
  python owasp_harvester.py --only SQL Injection # filenames containing these words
  python owasp_harvester.py --preview 3          # print 3 cleaned chunks, write nothing

Requirements: pip install requests

Licence note: the OWASP Cheat Sheet Series is CC BY-SA 4.0. Every row carries the
licence and source URL so attribution travels with the data.
"""

import argparse
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

import requests

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"

# Sections that are mostly links / lists of other resources
DROP_SECTIONS = {
    "references", "reference", "further reading", "additional resources",
    "external links", "see also", "tools", "related articles", "credits",
    "authors and primary editors", "contributors", "acknowledgements",
}

session = requests.Session()
session.headers["User-Agent"] = "owasp-harvester/1.0"
if os.environ.get("GITHUB_TOKEN"):
    session.headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"


# --------------------------------------------------------------------------
# Progress / output helpers
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
# Fetching
# --------------------------------------------------------------------------
def get_repo(repo):
    r = session.get(f"{API}/repos/{repo}", timeout=20)
    if r.status_code == 403:
        raise SystemExit("GitHub rate limit hit - set GITHUB_TOKEN and retry.")
    r.raise_for_status()
    d = r.json()
    return d["default_branch"], (d.get("license") or {}).get("spdx_id") or "CC-BY-SA-4.0"


def list_cheatsheets(repo, branch, prefix, only):
    r = session.get(f"{API}/repos/{repo}/git/trees/{branch}",
                    params={"recursive": "1"}, timeout=30)
    r.raise_for_status()
    paths = [
        i["path"] for i in r.json().get("tree", [])
        if i["type"] == "blob" and i["path"].startswith(prefix) and i["path"].endswith(".md")
    ]
    if only:
        words = [w.lower() for w in only]
        paths = [p for p in paths if any(w in p.lower() for w in words)]
    return sorted(paths)


def fetch_raw(repo, branch, path):
    r = session.get(f"{RAW}/{repo}/{branch}/{path}", timeout=30)
    return r.text if r.status_code == 200 else None


# --------------------------------------------------------------------------
# Cleaning
# --------------------------------------------------------------------------
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
INLINE_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
REF_LINK = re.compile(r"\[([^\]]+)\]\[[^\]]*\]")
REF_DEF = re.compile(r"^\s*\[[^\]]+\]:\s*\S+.*$")
HTML_TAG = re.compile(r"</?[A-Za-z][^>]*>")
BOLD = re.compile(r"(\*\*|__)(.+?)\1")
ITALIC = re.compile(r"(?<![\w*])[*_]([^*_\n]+)[*_](?![\w*])")
CODE_SPAN = re.compile(r"`([^`]*)`")
HR = re.compile(r"^\s*([-*_])(\s*\1){2,}\s*$")
TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")


def clean_line(line):
    line = IMAGE.sub("", line)
    line = INLINE_LINK.sub(r"\1", line)
    line = REF_LINK.sub(r"\1", line)
    line = HTML_TAG.sub("", line)
    line = BOLD.sub(r"\2", line)
    line = ITALIC.sub(r"\1", line)
    line = CODE_SPAN.sub(r"\1", line)
    line = re.sub(r"^\s*>\s?", "", line)                 # blockquote
    line = re.sub(r"^(\s*)[*+]\s+", r"\1- ", line)       # normalise bullets
    # table row -> "cell; cell; cell"
    if line.strip().startswith("|") and line.strip().endswith("|"):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        line = "; ".join(c for c in cells if c)
    return line.rstrip()


def parse_sections(md, keep_code=True, keep_refs=False):
    """Return a list of (path_of_headings, body_text) with markup removed."""
    md = md.replace("\r\n", "\n")
    md = re.sub(r"\A---\n.*?\n---\n", "", md, flags=re.S)   # front matter
    md = re.sub(r"<!--.*?-->", "", md, flags=re.S)          # html comments

    sections, stack, buf = [], [], []
    in_code = False

    def flush():
        body = re.sub(r"\n{3,}", "\n\n", "\n".join(buf)).strip()
        titles = [t for _, t in stack]
        dropped = (not keep_refs) and any(t.lower().strip(": ") in DROP_SECTIONS for t in titles)
        if body and not dropped:
            sections.append((titles, body))
        buf.clear()

    for raw in md.split("\n"):
        if raw.strip().startswith("```"):
            in_code = not in_code
            continue                                         # drop the fence itself
        if in_code:
            if keep_code:
                buf.append(raw.rstrip())
            continue
        m = HEADING.match(raw)
        if m:
            flush()
            level, title = len(m.group(1)), clean_line(m.group(2))
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, title))
            continue
        if HR.match(raw) or TABLE_SEP.match(raw) or REF_DEF.match(raw):
            continue
        buf.append(clean_line(raw))
    flush()
    return sections


# --------------------------------------------------------------------------
# Chunking
# --------------------------------------------------------------------------
def split_body(body, size):
    """Split on blank lines, packing paragraphs up to `size` characters."""
    out, cur = [], ""
    for para in re.split(r"\n\s*\n", body):
        para = para.strip()
        if not para:
            continue
        while len(para) > size:                              # very long paragraph/code block
            cut = para.rfind("\n", 0, size)
            cut = cut if cut > size // 2 else size
            if cur:
                out.append(cur)
                cur = ""
            out.append(para[:cut].strip())
            para = para[cut:].strip()
        if cur and len(cur) + len(para) + 2 > size:
            out.append(cur)
            cur = para
        else:
            cur = f"{cur}\n\n{para}" if cur else para
    if cur:
        out.append(cur)
    return out


def build_chunks(sections, size, min_chars):
    chunks = []
    for titles, body in sections:
        if len(body) < min_chars:
            continue
        header = " > ".join(titles) if titles else ""
        for piece in split_body(body, size):
            text = f"{header}\n{piece}" if header else piece
            chunks.append((header, text))
    return chunks


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--output", default="data/owasp.jsonl")
    ap.add_argument("--repo", default="OWASP/CheatSheetSeries")
    ap.add_argument("--prefix", default="cheatsheets/", help="folder inside the repo")
    ap.add_argument("--only", nargs="+", help="only files whose name contains any of these words")
    ap.add_argument("--chunk-size", type=int, default=1200, help="max characters per chunk")
    ap.add_argument("--min-chars", type=int, default=60, help="drop tiny sections")
    ap.add_argument("--no-code", action="store_true", help="drop code examples")
    ap.add_argument("--keep-references", action="store_true",
                    help="keep References / Further Reading sections")
    ap.add_argument("--preview", type=int, metavar="N",
                    help="print N cleaned chunks and exit without writing a file")
    ap.add_argument("--delay", type=float, default=0.05)
    args = ap.parse_args()

    branch, lic = get_repo(args.repo)
    paths = list_cheatsheets(args.repo, branch, args.prefix, args.only)
    if not paths:
        raise SystemExit("No matching cheat sheets found.")
    print(f"{args.repo} ({lic}): {len(paths)} cheat sheets")

    out = Path(args.output)
    if not args.preview:
        note = "  (will overwrite existing file)" if out.exists() else ""
        print(f"Output will be saved to: {out.resolve()}{note}\n")

    start = time.time()
    rows, shown, skipped = [], 0, 0
    for n, p in enumerate(paths, 1):
        if not args.preview:
            progress(n - 1, len(paths), Path(p).stem)
        md = fetch_raw(args.repo, branch, p)
        if not md:
            skipped += 1
            continue
        sections = parse_sections(md, keep_code=not args.no_code,
                                  keep_refs=args.keep_references)
        for i, (header, text) in enumerate(build_chunks(sections, args.chunk_size, args.min_chars)):
            rows.append({
                "repo": args.repo,
                "license": lic,
                "path": p,
                "chunk": i,
                "section": header,
                "url": f"https://github.com/{args.repo}/blob/{branch}/{p}",
                "text": text,
            })
            if args.preview and shown < args.preview:
                print(f"\n----- {p} [chunk {i}] -----\n{text}")
                shown += 1
        if args.preview and shown >= args.preview:
            return
        time.sleep(args.delay)
    progress(len(paths), len(paths), "done")

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print("\nDone in {:.1f}s".format(time.time() - start))
    print(f"  Cheat sheets : {len(paths) - skipped}" + (f"  ({skipped} failed to download)" if skipped else ""))
    print(f"  Chunks       : {len(rows)}")
    print(f"  File size    : {human_size(out.stat().st_size)}")
    print(f"  Saved to     : {out.resolve()}")
    print(f"\nNext: python oss_harvester.py embed \"{out}\" -o data/owasp_index.jsonl")


if __name__ == "__main__":
    main()
