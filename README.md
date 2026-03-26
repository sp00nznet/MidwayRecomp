# MidwayRecomp

A MIPS static recompilation toolkit for **Midway Seattle** and **Midway Vegas** arcade hardware. Converts MIPS-IV R5000 game binaries into portable C code that compiles natively on modern platforms -- no emulator required.

Built on top of [N64Recomp](https://github.com/N64Recomp/N64Recomp) by [Mr-Wiseguy](https://github.com/Mr-Wiseguy), which pioneered this approach for N64 titles like [Zelda 64: Recompiled](https://github.com/Zelda64Recomp/Zelda64Recomp). MidwayRecomp extends it with the instruction set and platform support needed for Midway's arcade boards.

## What's Different From N64Recomp

N64Recomp targets the Nintendo 64 (MIPS III, R4300i, big-endian). Midway Seattle/Vegas boards use the **MIPS R5000** (MIPS IV, little-endian) with different hardware. MidwayRecomp adds:

| Feature | N64Recomp | MidwayRecomp |
|---------|-----------|--------------|
| **Endianness** | Big-endian only | Big-endian + little-endian (`little_endian = true`) |
| **ISA** | MIPS III (R4300i) | MIPS III + MIPS IV extensions |
| **Conditional moves** | -- | `movn`, `movz` |
| **Prefetch** | -- | `pref` (stubbed as NOP) |
| **FP multiply-add** | -- | `madd.s/d`, `msub.s/d`, `nmadd.s/d`, `nmsub.s/d` |
| **Indexed FP load/store** | -- | `lwxc1`, `ldxc1`, `swxc1`, `sdxc1` |
| **Exception handlers** | Stack analysis fails on negative SP offsets | Negative SP offsets allowed |
| **Entrypoint** | Must be at ROM offset 0x1000 | Any ROM offset accepted |

Everything else -- the core recompilation engine, ELF parsing, symbol file format, overlay support, mod tools, live recompilation -- is inherited from N64Recomp and works identically.

## Target Hardware

MidwayRecomp is designed for the following Midway arcade platforms:

**Midway Seattle** (1996-1999)
| Component | Spec |
|-----------|------|
| CPU | MIPS R5000LE @ 150 MHz (MIPS-IV ISA) |
| System | Galileo GT64010 |
| GPU | 3DFX Voodoo 1 (2MB framebuffer + 4MB texture) |
| Sound | DCS2 (ADSP-2115) |
| I/O | Midway IOASIC |

**Titles:** CarnEvil, NFL Blitz, NFL Blitz '99, California Speed, Hyperdrive, Wayne Gretzky's 3D Hockey, Mace: The Dark Age, War Gods, San Francisco Rush, Vapor TRX, BioFreaks

**Midway Vegas** (1998-2002)
| Component | Spec |
|-----------|------|
| CPU | MIPS R5000LE @ 200-250 MHz (MIPS-IV ISA) |
| System | VRC5074 Nile 4 |
| GPU | 3DFX Voodoo 2/Banshee |
| Sound | DCS2 (ADSP-2115) |
| I/O | Midway IOASIC |

**Titles:** Gauntlet Legends, Gauntlet Dark Legacy, NBA Showtime, NBA on NBC, NFL Blitz 2000/2001, San Francisco Rush 2049, Tenth Degree, Road Burners, Invasion

## Quick Start

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/sp00nznet/MidwayRecomp.git
cd MidwayRecomp

# Build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

# Run
./build/Release/MidwayRecomp your_config.toml
```

## Configuration

MidwayRecomp uses the same TOML config format as N64Recomp. For Midway Seattle/Vegas binaries, set `little_endian = true`:

```toml
[input]
symbols_file_path = "symbols.toml"
rom_file_path = "game.bin"
entrypoint = 0x800C4000
output_func_path = "recomp_out/funcs"
little_endian = true
uses_mips3_float_mode = true

[patches]
stubs = ["exception_handler_func"]
```

The symbol file format is unchanged from N64Recomp. For flat binaries without ELF headers, provide a symbol TOML listing all functions:

```toml
[[section]]
name = ".text"
rom = 0x1000
vram = 0x800C4000
size = 0xDF504

  [[section.functions]]
  name = "entry_point"
  vram = 0x800C4000
  size = 0xA4
```

See the [N64Recomp documentation](https://github.com/N64Recomp/N64Recomp) for the full config reference -- everything there applies here too.

## How It Works

Same approach as N64Recomp: each MIPS instruction is translated one-to-one into a C statement. The output compiles with any C/C++ compiler and runs with a platform-specific runtime that provides memory access macros and hardware shims.

```
MIPS:  addiu $r4, $r4, 0x20
  C:   ctx->r4 = ADD32(ctx->r4, 0X20);

MIPS:  jal 0x80143A10
  C:   func_80143A10(rdram, ctx);

MIPS:  movn $rd, $rs, $rt        (MIPS IV -- new in MidwayRecomp)
  C:   if (ctx->r3 != 0) ctx->r2 = ctx->r4;

MIPS:  madd.s $fd, $fr, $fs, $ft (MIPS IV COP1X -- new in MidwayRecomp)
  C:   ctx->f6.fl = ctx->f8.fl * ctx->f10.fl + ctx->f4.fl;
```

## Credits

**MidwayRecomp** is a fork of [N64Recomp](https://github.com/N64Recomp/N64Recomp) by **Mr-Wiseguy** and contributors. The core recompilation engine, instruction processing pipeline, ELF parser, symbol file format, overlay/relocation support, mod tools, live recompilation framework, and the overall architecture are all their work. Without N64Recomp, this project would not exist.

The Midway-specific extensions (MIPS IV instructions, little-endian support, exception handler handling) were added by [sp00nznet](https://github.com/sp00nznet).

### Libraries Used
* [rabbitizer](https://github.com/Decompollaborate/rabbitizer) for MIPS instruction decoding (by Decompollaborate)
* [ELFIO](https://github.com/serge1/ELFIO) for ELF parsing
* [toml++](https://github.com/marzer/tomlplusplus) for TOML parsing
* [fmtlib](https://github.com/fmtlib/fmt) for string formatting
* [sljit](https://github.com/zherczeg/sljit) for live recompilation JIT

## License

MIT (same as upstream N64Recomp)
