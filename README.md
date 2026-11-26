# MStar AEON R2 — Ghidra processor module

A Ghidra SLEIGH processor module for **MStar AEON R2**, a 32-bit RISC architecture derived from OpenRISC but using MStar's variable-length instruction encoding and substantial extensions. This project targets **AEON R2**, not the separate AEON1 or AEON2 variants.

The project separates three things that are easy to conflate:
1. **Architecture model** — the instruction set, registers, flags, SPRs, memory model and control flow that define AEON R2.
2. **Ghidra implementation** — the decoder, p-code semantics, compiler specifications and analysis helpers.
3. **Target validation** — checks against vendor tools, simulator vectors and particular firmware images. A specific firmware image is evidence for the architecture; it is not the definition of the architecture.

## Processor overview

| Property | AEON R2 model |
|---|---|
| Word size | 32-bit |
| General-purpose registers | 32 (r0–r31); r0 reads as zero |
| Instruction width | Variable 16, 24 or 32 bits (2, 3 or 4 bytes) |
| Instruction byte order | Big-endian in all supplied languages |
| Data byte order | Big- or little-endian, selected by the language |
| Delay slots | None in the vendor AEON R2 toolchain model |
| Stack pointer | r1 |
| Link register | r9 |
| Status state | sr, including condition, carry and overflow flags |
| Special-purpose state | OpenRISC-derived system/exception registers plus MStar-defined register groups |

The ISA is not simply OpenRISC with a different byte order. It has variable-length encodings, MStar-specific system and cache operations, scalar floating point, MAC/DSP and SIMD instruction families, and additional stack/control instructions.

See [docs/architecture.md](docs/architecture.md) for the architectural description, register model, evidence levels and known unknowns.

## Ghidra languages

All three languages decode the same instruction bytes. They differ in data endianness and, for the Harvard language, the address space used by loads, stores and the stack.

| Language ID | Instruction bytes | Data | Intended use |
|---|---|---|---|
| **AEON:BE:32:R2** | Big-endian | Big-endian | Code/data built for -EB |
| **AEON:LE:32:R2** | Big-endian | Little-endian | Typical MStar -EL -EBinst firmware |
| **AEON:LE:32:R2-harvard** | Big-endian | Little-endian in a separate data space | Images whose data and code use overlapping numeric addresses |

Choose the language based on the binary's data layout and memory organization, not on the monitor or product name alone.

## Decoder and semantic coverage

The decoder is generated from the vendor AEON R2 assembler's ISA tables, then calibrated against the vendor disassembler. Source tables and calibration data are committed under isa/; tools/gen_sleigh.py produces the active SLEIGH constructors.

**Successful decoding does not mean complete emulation.** Vendor-table instruction forms are represented in the decoder, but forms without an established semantic model decode as opaque/pseudo operations. Implemented p-code covers core integer and control-flow operations, loads/stores, selected system and special-register behavior, selected scalar single-precision operations, and several architectural helpers. The custom MAC/DSP and SIMD families remain major gaps; double-precision and some fused/remainder floating-point operations also need work.

Named MAC state and multiply-high assumptions are documented with their evidence levels in [docs/architecture-state.md](docs/architecture-state.md). Inferred behavior is not presented as vendor-confirmed.

## Installation

Download a packaged extension from [GitHub Releases](https://github.com/Ikarus1111a/AEONR2CONS/releases). In Ghidra, use **File → Install Extensions**, select the AEON R2 ZIP, and restart Ghidra. Then select one of the language IDs above when importing a raw binary.

The latest published release tracks main. New work on an unmerged pull-request branch is not included in that release.

## Build and verification

Requires a local Ghidra installation and a Java runtime supported by that Ghidra release.

    export GHIDRA_INSTALL_DIR=/path/to/ghidra
    ./gradlew buildExtension
    ./gradlew verify

- **buildExtension** compiles the SLEIGH specifications and packages the extension.
- **verify** runs packaging checks, JUnit tests, headless smoke/decompiler checks and committed emulator regression cases across the language variants.
- Committed emulator cases are golden vectors recorded from the vendor simulator and replayed in Ghidra. Generating or extending vectors requires the MStar AEON R2 vendor toolchain/simulator, which is not bundled with this repository.

The CI workflow builds against Ghidra 12.2 and the latest official release selected by the workflow. See [the Actions runs](https://github.com/Ikarus1111a/AEONR2CONS/actions).

## Project documentation

- [Architecture overview](docs/architecture.md) — instruction encoding, register/state model, memory variants, implementation boundaries and unresolved semantics.
- [Architectural state details](docs/architecture-state.md) — SR fields, MAC SPRs, multiply-high and stack-frame semantics.
- [Legacy integration](docs/legacy-integration.md) — corrections from older AEON Ghidra work integrated into the maintained implementation.
- [Firmware validation notes](docs/firmware-validation.md) — simulator, disassembly, decompiler and firmware case-study evidence.

## Scope and limitations

This repository is an actively developed processor module, not a claim of complete AEON R2 emulation. Treat unknown/pseudo operations as instructions whose decode is known but whose execution semantics are not yet modeled. Establish unfamiliar instruction behavior from vendor documentation, simulator behavior or hardware; do not assume an instruction is unimportant because one firmware sample does not use it.
