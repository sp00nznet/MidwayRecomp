# MidwayRecomp tools — Ghidra-assisted function naming

These tools give recompiled functions meaningful names instead of
`func_XXXXXXXX`, by mining a Ghidra analysis of the target binary. They are
project-agnostic; point them at your game's Ghidra project and symbols TOML.

The strongest signal for stripped Midway binaries is the game's own debug
strings — many self-name the function that prints them
(`coin_volume_proc():`, `main_init_sound:`, `sst1InitSli`).

## Pipeline

```bash
# 1) Export Ghidra analysis -> functions.json / symbols.json / decompiled.json
#    (run from your game project dir; OUT_DIR defaults to ./ghidra_export)
analyzeHeadless <proj_dir> <proj> -process <prog> -noanalysis \
  -scriptPath path/to/MidwayRecomp/tools \
  -postScript ghidra_export_analysis.py ./ghidra_export 0

# 2) Derive names -> ghidra_export/name_map.json
python tools/derive_names.py --export ghidra_export [--seed seed.json]

# 3) Apply into your symbols TOML (skip overridden / runtime-referenced addrs)
python tools/merge_names_to_syms.py --syms game_syms.toml \
  --map ghidra_export/name_map.json --exclude keep_func.txt
```

`seed.json` is an optional `{"0xADDR":"name"}` map of hand-verified names that
take priority. `keep_func.txt` lists `0xADDR`s whose `func_XXXX` symbol must be
preserved (e.g. functions you override or call by name from hand-written runtime
code) — renaming those would break the link.

Names are suffixed with the 8-hex address for uniqueness and round-trip
traceability (`main_init_sound_800C5E30`). The recompiler reads names from the
symbols TOML, so changes take effect on the next regen.

## Notes

- `decompiled.json` (full decompile) is the slow step; pass a DECOMP_LIMIT as the
  2nd postScript arg for a quick pass, or 0 for all functions.
- Keep the bulky raw JSONs out of version control; commit only `name_map.json`.
- After renaming, regenerate any address→symbol registration table your runtime
  uses so the names stay consistent (see the CarnEvil consumer for an example).
