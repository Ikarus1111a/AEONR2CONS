# AEON R2 SIMD semantic coverage

The SIMD register file is 32 registers wide and 64 bits per register. Native
semantics are emitted as lane-local SLEIGH P-code, rather than opaque
`CALLOTHER` userops, so Ghidra can track register data flow.

## Native P-code implemented

- Whole-register bitwise: `mv.and`, `mv.or`, `mv.xor`
- Wrapping lane arithmetic: 16-bit `mv.add`/`mv.addu`, 8-bit
  `mv.add.b`/`mv.addu.b`, and corresponding subtract forms
- Signed/unsigned rounded-up averages: halfword and byte forms
- Equality and signed/unsigned less-than masks: halfword and byte forms
- Signed/unsigned halfword minimum and maximum
- Per-halfword variable arithmetic/logical shifts, with the SDK's
  `min(count & 0xf, 8)` rule
- Signed halfword absolute value (including the two's-complement
  `INT16_MIN` edge case)
- Low/high byte unpack to zero-extended halfword lanes
- Scalar extraction (signed/unsigned halfword and byte, plus low-word transfer)
- Scalar-to-vector lane insertion, sign-bit mask extraction, and halfword broadcast
- 64-bit byte concatenation and low/high 32-bit scalar insertion

The operation formulas are based on the independent MStar SDK's AEON
`__m64` compatibility routines. Those routines are evidence for intended
software-visible behavior, not a complete hardware specification. A generated
coverage check confirms these semantic keys correspond to actual ISA entries
and that the committed SLEIGH constructors contain native P-code.

## Explicitly not claimed complete

Other vector instructions—including multiply/accumulate, packing/extraction,
lane insertion, clipping, complex OPT/OPC/OPV/OPM composites, queue-memory
loads/stores, and several reduction/special operations—remain opaque or need
additional work. Some SDK helper implementations are marked unsupported or
have implementation-specific endian assumptions; they must not be translated
blindly.

## Regression coverage

Emulator tests compare exact 64-bit vector values in all three language
variants (BE, LE data, and LE Harvard), including:

- independent lane wrap with no cross-lane carry
- signed and unsigned averages and comparisons
- byte arithmetic
- per-lane shift counts and clamp behavior
- signed absolute value at `-32768`
- unpack ordering

These tests are part of the Ghidra headless `verify` task. Passing CI is the
acceptance condition; merely generating the constructors is not validation.
