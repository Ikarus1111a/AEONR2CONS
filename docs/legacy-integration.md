# Legacy AEON corrections in the maintained implementation

This repository is one AEON R2 processor module and one installable Ghidra extension.
The older projects were reviewed and their applicable improvements were carried into
the active implementation. They are not installed as a second, competing processor.

Reviewed source histories:

- [throwaway96/ghidra-aeon, dev](https://github.com/throwaway96/ghidra-aeon/tree/dev)
- [rajkosto/ghidra-aeon, master](https://github.com/rajkosto/ghidra-aeon/tree/master)

The modern decoder is generated from MStar's vendor ISA tables and measured operand
calibration. The old hand-authored SLEIGH files were therefore not overlaid wholesale:
doing so would create a competing decoder. The corrections below are implemented in
the maintained generator, generated SLEIGH, and compiler specifications that ship
inside the same extension ZIP.

## Ported into active source

| Legacy improvement | Active implementation | Effect |
|---|---|---|
| Rajkosto's reversed token-field correction | `tools/gen_sleigh.py` emits `t_c2_4`, `n_c2_4`, and `g_c2_4` as ascending `(2,4)` slices | Correct extraction of the affected instruction fields |
| Signed `bn.sfnei`, `bn.beqi`, `bg.sfnei`, and `bg.beqi` immediates | Vendor signedness flags and calibration in `isa/aeon_isa.json`, `isa/calibration.json`; constructors emitted by `tools/gen_sleigh.py` | Negative immediates are sign-extended instead of treated as large unsigned values |
| Conditional-move operand correction (`bn.cmovsi_1`) | `SEMANTICS` in `tools/gen_sleigh.py`, emitted as `bn.cmovir`, `bn.cmovri`, and `bn.cmovii` | Immediate and register operands are not interchanged |
| `lbz` zero extension / `lbs` sign extension | Active generated constructors in `data/languages/aeonR2.sinc` | Correct byte-load values in P-code and decompilation |
| Cache and synchronization P-code | `SEMANTICS` and active constructors in `tools/gen_sleigh.py` / `data/languages/aeonR2.sinc` | Cache operations carry named address/operation operands instead of being empty semantics |
| Natural alignment for scalar ABI types | `data_organization` and `size_alignment_map` in all three active `.cspec` files | 1-, 2-, 4-, and 8-byte scalars use 1-, 2-, 4-, and 4-byte alignment respectively |

The old branch also marked unimplemented encodings with SLEIGH's `unimpl` marker.
The maintained generator uses a more useful fallback for known-but-unmodelled
instructions: a named opaque P-code operation that preserves the decoded mnemonic,
operands, and instruction length. It does not silently treat those instructions as
empty no-ops.

## Why the old SLEIGH files are not copied into the package

The old projects use a hand-maintained OpenRISC-derived decoder. This package has
one active decoder generated from vendor opcode tables, operand calibration, and
decoder-priority measurements. Copying the old `aeon.slaspec` or
`aeon_ORBIS32.sinc` into the active language would create duplicate/competing
instruction definitions and could undo the vendor-calibrated decode rules.

The old corrections are therefore ported into the single active source model. There
is no separately installed "legacy AEON" extension to combine with this package.

## Verification

Run:

```sh
python3 tools/check_legacy_regressions.py
./gradlew verify
```

The regression task checks the live generated SLEIGH, P-code generator, and all three
compiler specifications. `verify` additionally compiles all language variants and
runs the project's existing disassembly, analysis, decompilation, and P-code
emulation tests.
