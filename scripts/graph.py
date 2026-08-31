#!/usr/bin/env python3
"""graph.py: verify and print the Apple-MTE-Research knowledge graph.

Scans every .md file under the repo for [[wikilink]] and [text](path.md)
link targets, checks each target resolves to a file (docs/, resources/,
or repo root, basename match, .md optional), prints nodes, edges, and
dangling links.

Usage:
    python3 scripts/graph.py          full report
    python3 scripts/graph.py --edges  edges only
    python3 scripts/graph.py --dangling  dangling links only
Exit code 1 if any dangling links exist (handy for a pre-commit hook).
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIKI = re.compile(r"\[\[([^\]|#]+)(?:#[^\]|]*)?(?:\|[^\]]*)?\]\]")
MDLINK = re.compile(r"\[[^\]]*\]\(([^)#]+)(?:#[^)]*)?\)")

def md_files(root):
    out = {}
    for dirpath, _dirs, names in os.walk(root):
        if ".git" in dirpath:
            continue
        for n in names:
            if n.endswith(".md"):
                p = os.path.join(dirpath, n)
                out[os.path.splitext(n)[0]] = p
    return out

def resolve(target, src_path):
    """Resolve a link target from the source file to a repo-root relative
    path, or None. Handles both bare names (wikilinks) and relative paths
    (markdown links). Non-.md targets (scripts, papers, urls) return a
    sentinel so they are counted as fine, not dangling."""
    target = target.strip()
    if not target.endswith(".md"):
        return True  # link to a non-doc file: not a graph edge, not an error
    target = target[:-3]
    if "/" not in target:
        # same-directory lookup, then repo-root fallback
        for cand in (os.path.join(os.path.dirname(src_path), target + ".md"),
                     os.path.join(ROOT, target + ".md")):
            if os.path.isfile(cand):
                return cand
        return None
    cand = os.path.normpath(os.path.join(os.path.dirname(src_path), target + ".md"))
    return cand if os.path.isfile(cand) else None

def main():
    only_edges = "--edges" in sys.argv
    only_dangling = "--dangling" in sys.argv

    files = md_files(ROOT)
    edges = []
    dangling = []

    for name, path in sorted(files.items()):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for m in WIKI.finditer(text):
            target = m.group(1).strip()
            resolved = resolve(target, path)
            if resolved is None:
                dangling.append((name, target))
            elif isinstance(resolved, str):
                edges.append((name, os.path.splitext(os.path.basename(resolved))[0]))
        for m in MDLINK.finditer(text):
            target = m.group(1).strip()
            if target.startswith("http") or target.startswith("#"):
                continue
            resolved = resolve(target, path)
            if resolved is None:
                dangling.append((name, target))
            elif isinstance(resolved, str):
                edges.append((name, os.path.splitext(os.path.basename(resolved))[0]))

    if only_dangling:
        for src, tgt in dangling:
            print(f"{src} -> [[{tgt}]] MISSING")
        sys.exit(1 if dangling else 0)

    print(f"nodes: {len(files)}  edges: {len(set(edges))}  dangling: {len(dangling)}")
    print()
    if not only_edges:
        print("documents:")
        for name in sorted(files):
            print(f"  {name:20s} {os.path.relpath(files[name], ROOT)}")
        print()
    print("edges:")
    for src, tgt in sorted(set(edges)):
        print(f"  {src:20s} -> {tgt}")
    print()
    if dangling:
        print("dangling:")
        for src, tgt in dangling:
            print(f"  {src:20s} -> [[{tgt}]] MISSING")
        sys.exit(1)
    print("graph intact")

if __name__ == "__main__":
    main()
