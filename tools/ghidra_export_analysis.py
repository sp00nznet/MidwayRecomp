# -*- coding: utf-8 -*-
# Ghidra headless analysis exporter for MidwayRecomp naming.
#
# Exports three JSON files used by derive_names.py to give recompiled functions
# meaningful names instead of func_XXXXXXXX:
#   functions.json  : [{addr,name,size,signature,callees[],string_refs[]}]
#   symbols.json    : {labels:[{addr,name,type,source}], strings:[{addr,value}]}
#   decompiled.json : {"%08X": "<decompiled C>"}
#
# string_refs (functions a string is referenced from) are collected via the
# reference manager and are the strongest naming signal for stripped binaries
# whose debug strings self-name functions (e.g. "main_init_sound:").
#
# Usage (headless):
#   analyzeHeadless <proj_dir> <proj> -process <prog> -noanalysis \
#     -scriptPath <dir> -postScript ghidra_export_analysis.py [OUT_DIR] [DECOMP_LIMIT]
# OUT_DIR defaults to ./ghidra_export ; DECOMP_LIMIT 0 = decompile all funcs.
#
# @category Recomp
# @runtime Jython

import json, os

args = list(getScriptArgs())
OUT_DIR = args[0] if len(args) >= 1 else "./ghidra_export"
DECOMP_LIMIT = int(args[1]) if len(args) >= 2 else 0
DECOMP_TIMEOUT = 60

try:
    os.makedirs(OUT_DIR)
except:
    pass

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

fm = currentProgram.getFunctionManager()
st = currentProgram.getSymbolTable()
listing = currentProgram.getListing()
rm = currentProgram.getReferenceManager()

def is_string_data(d):
    try:
        n = d.getDataType().getName().lower()
    except:
        return False
    return ("string" in n) or ("char" in n and d.isArray())

# strings + addr->value
strings = []
di = listing.getDefinedData(True)
while di.hasNext():
    d = di.next()
    if is_string_data(d):
        try:
            val = d.getValue()
            if val is not None:
                val = unicode(val)
        except:
            try:
                val = d.getDefaultValueRepresentation()
            except:
                val = None
        strings.append({"addr": d.getAddress().getOffset(), "value": val})

# string -> referencing functions
func_string_refs = {}
for s in strings:
    refs = rm.getReferencesTo(toAddr(s["addr"]))
    for r in refs:
        f = fm.getFunctionContaining(r.getFromAddress())
        if f is None:
            continue
        fe = f.getEntryPoint().getOffset()
        func_string_refs.setdefault(fe, [])
        if s["value"] is not None and s["value"] not in func_string_refs[fe]:
            func_string_refs[fe].append(s["value"])

# functions.json
all_funcs = []
fit = fm.getFunctions(True)
while fit.hasNext():
    all_funcs.append(fit.next())
funcs = []
for f in all_funcs:
    fe = f.getEntryPoint().getOffset()
    callees = []
    try:
        for c in f.getCalledFunctions(ConsoleTaskMonitor()):
            callees.append(c.getEntryPoint().getOffset())
    except:
        pass
    try:
        sig = f.getPrototypeString(False, False)
    except:
        sig = ""
    funcs.append({"addr": fe, "name": f.getName(),
                  "size": f.getBody().getNumAddresses(), "signature": sig,
                  "callees": callees, "string_refs": func_string_refs.get(fe, [])})
json.dump(funcs, open(os.path.join(OUT_DIR, "functions.json"), "w"), indent=1)
println("functions.json: %d" % len(funcs))

# symbols.json
labels = []
sit = st.getAllSymbols(True)
while sit.hasNext():
    s = sit.next()
    labels.append({"addr": s.getAddress().getOffset(), "name": s.getName(),
                   "type": str(s.getSymbolType()), "source": str(s.getSource())})
json.dump({"labels": labels, "strings": strings},
          open(os.path.join(OUT_DIR, "symbols.json"), "w"), indent=1)
println("symbols.json: %d labels, %d strings" % (len(labels), len(strings)))

# decompiled.json
ifc = DecompInterface(); ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()
decomp = {}; count = 0
for f in all_funcs:
    if DECOMP_LIMIT and count >= DECOMP_LIMIT:
        break
    res = ifc.decompileFunction(f, DECOMP_TIMEOUT, monitor)
    key = "%08X" % f.getEntryPoint().getOffset()
    decomp[key] = res.getDecompiledFunction().getC() if (res and res.decompileCompleted()) else ""
    count += 1
    if count % 200 == 0:
        println("  decompiled %d/%d" % (count, len(all_funcs)))
json.dump(decomp, open(os.path.join(OUT_DIR, "decompiled.json"), "w"), indent=0)
println("decompiled.json: %d" % len(decomp))
println("DONE -> " + OUT_DIR)
