# AEON R2 architectural state: MAC and multiply-high

## Confirmed MStar register-save state

The public MStar RISC32 headers define a MAC SPR group at group index 5 (11 index
bits per group), with:

| SPR | Index | Byte address in the SLEIGH `spr` space | Register |
|---|---:|---:|---|
| MACLO | `0x2801` | `0xA004` | `maclo` |
| MACHI | `0x2802` | `0xA008` | `machi` |
| MACHI2 | `0x2803` | `0xA00C` | `machi2` |

MStar's AEON R2 context-save layout and vector handler save/restore code preserve
all three 32-bit words. Together, these are 96 bits of architectural MAC state.
They are modelled as real register varnodes and direct SPR accesses now alias them;
they are no longer anonymous memory reads/writes when the SPR number is constant.

The same MStar header defines the SR bit masks. The full context-ID field is
represented as `CID=sr[28,4]`, alongside the existing supervisor, interrupt,
cache, F, CY and OV bits.

## Multiply-high

The independent Reko AEON implementation reads `SPR 0x2808` as `MULHI` after
32x32 multiply operations. This repository models that register as `mulhi` and
updates it for signed `bn.mul`, unsigned `bn.mulu`, and signed-immediate
`bg.muli`: the destination GPR receives product bits 0–31 and `mulhi` receives
bits 32–63.

This mapping has independent disassembler/rewriter evidence, but it is not
explicitly named in the public MStar SPR header. It is therefore tested separately
and documented as a Reko-derived architectural inference, not a MStar-confirmed
SPR name.

## SIMD register width and lane model

The SDK's AEON SIMD reference declares all 32 vector registers as 64-bit __m64 values. Its compatibility implementation uses four 16-bit lanes or eight 8-bit lanes. The corresponding memory helpers treat mv.ldv and mv.sdv as eight-byte transfers with eight-byte alignment, while mv.ldw and mv.sdw are four-byte transfers with four-byte alignment. The architectural register bank is therefore 32 x 64 bits, not 32 x 128 bits. The active SLEIGH register declaration and the emulator test now use that width.

This host-side compatibility implementation is a strong reference for register width and many operation formulas, but it is not proof of every silicon corner case. In particular, the SDK marks mv.textnz and mv.lzc as unsupported in that compatibility path. Their helper bodies are clues, not an adequate validation oracle. Lane-wise arithmetic, packing, reductions, and the mv.opt/mv.opc/mv.opv/mv.opm compound operations still require dedicated tests and, where possible, differential checks.

Sources: [AEON SIMD reference implementation](https://github.com/longyanjun2020/SDK_pulbic/blob/c1436fa7446457e8d6547874d27ee4e34be150cf/Mercury5/proj/sc/middleware/avp/viddecoder/common/avp_aeon_simd_gcc.h), [AEON SIMD assembler helpers](https://github.com/longyanjun2020/SDK_pulbic/blob/c1436fa7446457e8d6547874d27ee4e34be150cf/Mercury5/proj/sc/middleware/venc/inc/common/swvenc_aeon-simd.h).

## AMAC control and queue state

A separate MStar AEON SPR header supplies the wider MAC-group map. In addition to the scalar accumulator halves and configuration register already named in SLEIGH, it defines AMULHI at 0x2808, two guard registers at 0x2805 and 0x2806, and AMACSTATUS at 0x280e. Two queue-control banks occupy 0x2810..0x2814 and 0x2818..0x281c; each has a queue word, address offset, stride, second stride, and combined offset/stride register. The queue-stride word carries two 8-bit stride values and a 16-bit address offset.

The SDK's AMACCFG bitfield defines enable at bit 0 and a separate mode bit at bit 2. Accumulator 0 has a two-bit saturation mode at bits 8..9 and a rounding-mode bit at bit 10; accumulator 1 has corresponding fields at bits 16..17 and bit 18. The saturation modes are documented as 64-bit-before-shift, 64-bit-after-shift, 32-bit-after-shift, and 16-bit-after-shift. Rounding modes are toward infinity and away from zero. AMACSTATUS exposes an overflow bit at bit 0.

The current Ghidra model names the scalar accumulator and configuration SPRs but does not yet name the guard, status, and queue registers or model queue/DMA side effects. Twelve simple scalar AMUL/AMAC/AMSB word and halfword forms have native P-code; the remaining MAC/DSP rows include extraction, rounding/saturation, queue transfers, packed operations, and special address generation. Those forms must be classified and validated individually.

Sources: [MStar AEON SPR definitions and AMAC data structures](https://github.com/jockyw2001/utopia/blob/53ee8cc121a030b8d368113ac3e966b4705770ef/UTPA2-700.0.x/projects/tools/lint/aeon_include/machine/spr_defs.h), [SDK AMAC arithmetic and extraction usage](https://github.com/longyanjun2020/SDK_pulbic/blob/c1436fa7446457e8d6547874d27ee4e34be150cf/Mercury5/proj/sc/middleware/mmaudio/amrnb_codec/src/Aeon/amrnb_com/anc_mac.h).
## What is deliberately not modelled yet

The R2 vendor opcode set contains 154 MAC/DSP forms. Twelve simple scalar forms (bg.amul, bg.amac, bg.amsb, their unsigned-word variants, and the low/high signed-halfword variants) now have native 64-bit arithmetic semantics. The remaining 142 forms include accumulator extraction, rounding/saturation, queue and DMA transfers, packed MAC operations, and special address generation. They must be classified and validated individually; the existence of the MAC register bank does not prove those side effects.

The public MStar assembly also uses `l.mac` and `l.macrc`; the current R2
vendor opcode table does not expose these spellings as R2 constructors. They are
not silently added as aliases here.

## Sources

- [MStar RISC32 SPR definitions](https://github.com/neuschaefer/mstar-mboot/blob/master/sboot/src/macaw12/risc32_spr.h)
- [MStar AEON R2 vector save/restore](https://github.com/neuschaefer/mstar-mboot/blob/master/sboot/src/eden/vectors.S)
- [MStar AEON R2 register-save structure](https://github.com/Toysoft/mstar/blob/master/Chakra3_017a0d6_20170731/core/drv_bsp/nasa_nos_r2m/include/MsOS.h)
- [Reko AEON multiply and SPR_MULHI rewrite](https://github.com/uxmal/reko/blob/master/src/Arch/OpenRISC/Aeon/AeonRewriter.cs)
- [Reko AEON MULHI disassembler test](https://github.com/uxmal/reko/blob/master/src/UnitTests/Arch/OpenRISC/AeonDisassemblerTests.cs)

## Function-frame instructions

`bn.entri F,V` saves `F` registers beginning at `r9`, allocates a frame of `F+V` words, and updates `r1`. `bn.rtnei F,V` restores those registers and releases the same frame. The semantics unroll the maximum fifteen possible register saves/restores, so Ghidra sees individual stack accesses and register definitions instead of opaque user-ops.

The paired layout currently encoded here stores r(9+i) at old_sp - 4*(i+1) and restores it from new_sp + 4*(F+V-i-1). Those addresses are mathematical inverses for any F and V. This deliberately differs from the current Reko ENTRI emitter's apparent save-slot convention. The Ghidra emulator tests verify internal round-trip consistency, not the silicon's precise save-slot convention. A vendor-simulator differential test is still required before calling the stack layout hardware-confirmed.


## Named system exception-register banks

MStar's system SPR header defines three contiguous 16-entry banks:

| Bank | SPR indices | Architectural purpose |
|---|---:|---|
| EPCR | 32–47 | Exception program counters |
| EEAR | 48–63 | Exception effective addresses |
| ESR | 64–79 | Saved exception status registers |

These are represented as named Ghidra register varnodes (`epcr0..epcr15`,
`eear0..eear15`, `esr0..esr15`). Immediate and register-indexed SPR accesses
route to the corresponding varnode, while unknown SPR indices continue to use
the generic `spr` address space. `bt.rfe` reads `epcr0` and `esr0` directly,
so exception return and explicit SPR reads/writes share the same modeled state.

The register names and index ranges are defined by MStar's public RISC32 SPR
header. This does not emulate exception-entry hardware, nested-exception policy,
interrupt arbitration, or automatic updates to EEAR/EPCR/ESR on a fault.
