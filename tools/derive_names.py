#!/usr/bin/env python3
"""
Derive meaningful function names from a Ghidra export (see
ghidra_export_analysis.py). Project-agnostic.

Sources, later overrides earlier:
  1. self-string : a debug string starting with an identifier + ':' or '()'
     ("main_init_sound:", "coin_volume_proc()"), used only when referenced by
     exactly one function (so it's the function naming itself, not a shared
     logger format).
  2. slug-string : a uniquely-referenced descriptive string, slugified, format
     specifiers stripped, label-like (fewest words) preferred.
  3. seed        : optional JSON {"0xADDR":"name", ...} of hand-verified names.

Every name gets an _ADDR8 suffix for uniqueness + traceability.

Usage:
  derive_names.py [--export DIR] [--seed seed.json] [--out name_map.json]
"""
import json, re, argparse, collections
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--export", default="ghidra_export")
ap.add_argument("--seed", default=None)
ap.add_argument("--out", default=None)
a = ap.parse_args()

EXPORT = Path(a.export)
fns = json.load(open(EXPORT / "functions.json"))
seed = {}
if a.seed:
    seed = {int(k, 16): v for k, v in json.load(open(a.seed)).items()}

str_referrers = collections.defaultdict(list)
for f in fns:
    for s in f["string_refs"]:
        str_referrers[s].append(f["addr"])

def sanitize(s):
    s = re.sub(r"[^0-9A-Za-z_]", "_", s); s = re.sub(r"_+", "_", s).strip("_")
    if s and s[0].isdigit(): s = "_" + s
    return s[:48]

SELF = [re.compile(r"^\s*([A-Za-z_]\w{2,46})\s*\(\s*\)"),
        re.compile(r"^\s*([A-Za-z_]\w{2,46})\s*:")]
BAD = re.compile(r"^(ERROR|FATAL|WARNING|INFO|OK|DONE|NULL|TRUE|FALSE)$", re.I)
def self_name(s):
    for rx in SELF:
        m = rx.match(s)
        if m:
            i = m.group(1)
            if len(i) >= 4 and not BAD.match(i) and any(c.islower() for c in i):
                return i
    return None

FMT = re.compile(r"%[-+ 0#]*\d*\.?\d*[hlL]*[diouxXeEfgGcsp%]")
def clean(s):
    s = FMT.sub(" ", s).replace("\\n"," ").replace("\\r"," ").replace("\\t"," ")
    s = re.sub(r"[^0-9A-Za-z _]", " ", s); return re.sub(r"\s+"," ",s).strip()
def good(s):
    c = clean(s); return 4 <= len(c) <= 60 and sum(ch.isalpha() for ch in c) >= 4
def rank(s):
    c = clean(s); return (len(c.split()), len(c))

names, source = {}, {}
# 1. self-string (single referrer)
for s, refs in str_referrers.items():
    n = self_name(s)
    if n and len(refs) == 1 and refs[0] not in names:
        names[refs[0]] = sanitize(n); source[refs[0]] = "self-string"
# 2. slug-string
for f in fns:
    if f["addr"] in names: continue
    cands = [s for s in f["string_refs"] if len(str_referrers[s]) == 1 and good(s)]
    if not cands: continue
    cands.sort(key=rank)
    b = sanitize(clean(cands[0]).lower())
    if b: names[f["addr"]] = b; source[f["addr"]] = "slug-string"
# 3. seed
for addr, n in seed.items():
    names[addr] = sanitize(n); source[addr] = "seed"

final = {"0x%08X" % a_: "%s_%08X" % (b, a_) for a_, b in names.items()}
out = Path(a.out) if a.out else (EXPORT / "name_map.json")
json.dump(final, open(out, "w"), indent=1, sort_keys=True)

by = collections.Counter(source.values())
print("Derived %d names (%s)" % (len(final), dict(by)))
print("-> %s" % out)
