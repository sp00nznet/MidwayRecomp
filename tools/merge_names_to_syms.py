#!/usr/bin/env python3
"""
Apply a derived name_map.json into a MidwayRecomp symbols TOML so renamed
functions flow into generated code on the next recompile. Project-agnostic.

Only rewrites default func_/static_ names. Addresses listed in --exclude (one
0xADDR per line) are skipped -- use this for functions that have hand-written
overrides or are referenced by name from hand-written runtime code, so their
func_XXXX symbol must be preserved.

Usage:
  merge_names_to_syms.py --syms game_syms.toml --map ghidra_export/name_map.json \
                         [--exclude keep_func.txt]
"""
import json, re, argparse
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--syms", required=True)
ap.add_argument("--map", required=True)
ap.add_argument("--exclude", default=None)
a = ap.parse_args()

name_map = json.load(open(a.map))
exclude = set()
if a.exclude:
    for l in open(a.exclude):
        l = l.strip()
        if l:
            exclude.add(int(l, 16) if l.lower().startswith("0x") else int(l, 16))
safe = {int(k, 16): v for k, v in name_map.items() if int(k, 16) not in exclude}

p = Path(a.syms); lines = p.read_text(encoding="utf-8").split("\n")
nre = re.compile(r'^(\s*)name = "([^"]*)"\s*$')
vre = re.compile(r'^\s*vram = (0x[0-9A-Fa-f]+)\s*$')
applied = 0; pend = None; ind = None
for i, line in enumerate(lines):
    m = nre.match(line)
    if m: pend = i; ind = m.group(1); continue
    v = vre.match(line)
    if v and pend is not None:
        addr = int(v.group(1), 16)
        if addr in safe:
            cur = nre.match(lines[pend]).group(2)
            if cur.startswith("func_") or cur.startswith("static_"):
                lines[pend] = '%sname = "%s"' % (ind, safe[addr]); applied += 1
        pend = None
p.write_text("\n".join(lines), encoding="utf-8")
print("Applied %d / %d names to %s" % (applied, len(safe), p.name))
