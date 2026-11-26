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

## What is deliberately not modelled yet

The R2 vendor opcode set contains a large custom MAC/DSP family (for example,
`bg.amac*`, `bg.amsb*`, `bg.amul*`, `bg.pamac*`). The existence of the MAC
register bank does not prove the lane selection, Q-format, rounding, saturation,
accumulator selection, or queue side effects for those instructions. They remain
opaque until each form can be validated against the vendor simulator or
independent hardware evidence.

The public MStar assembly also uses `l.mac` and `l.macrc`; the current R2
vendor opcode table does not expose these spellings as R2 constructors. They are
not silently added as aliases here.

## Sources

- [MStar RISC32 SPR definitions](https://github.com/neuschaefer/mstar-mboot/blob/master/sboot/src/macaw12/risc32_spr.h)
- [MStar AEON R2 vector save/restore](https://github.com/neuschaefer/mstar-mboot/blob/master/sboot/src/eden/vectors.S)
- [MStar AEON R2 register-save structure](https://github.com/Toysoft/mstar/blob/master/Chakra3_017a0d6_20170731/core/drv_bsp/nasa_nos_r2m/include/MsOS.h)
- [Reko AEON multiply and SPR_MULHI rewrite](https://github.com/uxmal/reko/blob/master/src/Arch/OpenRISC/Aeon/AeonRewriter.cs)
- [Reko AEON MULHI disassembler test](https://github.com/uxmal/reko/blob/master/src/UnitTests/Arch/OpenRISC/AeonDisassemblerTests.cs)
