# AEON R2 architecture overview

## Identity and scope

AEON R2 is MStar's 32-bit RISC processor architecture. It is OpenRISC-derived, but its instruction encoding and instruction set are customized. This module models R2 specifically; AEON1 and AEON2 are not interchangeable language IDs or instruction sets.

The model draws on vendor AEON R2 assembler/disassembler tables, public MStar RISC32 headers and startup/exception code, independent AEON implementations, and vendor-simulator behavior where available. Evidence is not equally strong for every feature: the implementation distinguishes confirmed definitions, measured behavior, corroborated inference and unresolved behavior.

## Instruction encoding and execution

- Instructions are 16, 24 or 32 bits long.
- Instruction bytes are big-endian in every language defined by this module.
- Data accesses may be big-endian or little-endian.
- The supplied model has no branch delay slots.
- r0 is hardwired to zero.
- The architecture has 32 32-bit general-purpose registers, r0–r31.

The vendor opcode table is the source of the decoder. The generation pipeline reads the assembler's instruction and operand tables, calibrates operand presentation against vendor objdump, checks field encodings and emits SLEIGH constructors. The decoder table currently covers 532 vendor opcode entries. Some entries are synonyms, aliases or specialized forms; that count is not a count of independent operations.

## General registers and calling convention

The MStar AEON R2 toolchain model uses:

| Register | Conventional role |
|---|---|
| r0 | Constant zero |
| r1 | Stack pointer |
| r3–r8 | First six scalar argument words |
| r3 | Scalar return value |
| r9 | Link/return address |
| r10–r22 | Callee-saved under the observed vendor ABI |
| r23–r31 | Caller-saved / freely used by leaf functions under the observed ABI |

The ABI's 64-bit argument/return register ordering depends on data endianness. Consult compiler-specification and firmware ABI evidence before interpreting 64-bit values across languages. These are ABI conventions, not instruction-set definitions.

## Status register

The architectural sr is modeled as one 32-bit register with bitranges. The public MStar RISC32 header defines:

| Bits | Field | Meaning |
|---:|---|---|
| 0 | SM | Supervisor mode |
| 1 | TEE | Tick-timer exception enable |
| 2 | IEE | Interrupt exception enable |
| 3 | DCE | Data cache enable |
| 4 | ICE | Instruction cache enable |
| 5 | DME | Data MMU enable |
| 6 | IME | Instruction MMU enable |
| 7 | LEE | Little-endian enable |
| 8 | CE | Context-ID enable |
| 9 | F | Condition flag |
| 10 | CY | Carry flag |
| 11 | OV | Overflow flag |
| 12 | OVE | Overflow exception enable |
| 13 | DSX | Delay-slot exception state |
| 14 | EPH | Exception prefix high |
| 15 | FO | Fixed-one bit |
| 16 | SUMRA | Supervisor SPR read access |
| 28–31 | CID | Context ID |

Bit names and masks come from the MStar header. Exact exception side effects and some privilege behaviors still require hardware or simulator validation. F, CY and OV are shared architectural state and must remain aliased with sr.

## Special-purpose registers

MStar divides SPR indices into 2,048-register groups:

| Group | Group index | Base SPR index |
|---|---:|---:|
| System | 0 | 0x0000 |
| Data MMU | 1 | 0x0800 |
| Instruction MMU | 2 | 0x1000 |
| Data cache | 3 | 0x1800 |
| Instruction cache | 4 | 0x2000 |
| MAC | 5 | 0x2800 |
| Debug | 6 | 0x3000 |
| Performance counter | 7 | 0x3800 |
| Performance monitor | 8 | 0x4000 |
| PIC | 9 | 0x4800 |
| Tick timer | 10 | 0x5000 |

The MStar header explicitly names MACLO=0x2801, MACHI=0x2802 and MACHI2=0x2803; MStar exception context code preserves all three. The module gives them named architectural register state.

MULHI=0x2808 is modeled separately because the independent Reko AEON implementation reads that SPR after 32×32-bit multiplies. It is not explicitly named by the public MStar header, so this remains an inference rather than an MStar-confirmed definition. See [architectural state details](architecture-state.md).

Naming an SPR does not itself emulate side effects such as cache invalidation, interrupt delivery, timer progression or MMU translation.

## Memory models in Ghidra

The module exposes three languages:

- **AEON:BE:32:R2**: big-endian instructions and data in one ram space.
- **AEON:LE:32:R2**: big-endian instructions and little-endian data in one ram space.
- **AEON:LE:32:R2-harvard**: instructions/branch targets in ram; loads, stores and stack accesses use a separate little-endian data space.

The Harvard variant addresses a Ghidra modeling problem: firmware may use identical numeric addresses for executable bytes and unrelated data bytes. It does not assert all AEON R2 silicon has physically separate code and data buses.

## Instruction-family implementation status

Decode coverage and p-code coverage are separate.

| Family | Current implementation status |
|---|---|
| Core integer arithmetic, logic and shifts | Substantial native p-code; selected specialized forms remain opaque |
| Conditional/unconditional control flow | Substantial coverage; specialized loop/return forms are still being completed |
| Loads and stores | Common scalar widths modeled; specialized multiword/DMA forms remain incomplete |
| SPR and exception state | Named SR/MAC state and selected exception behavior modeled; complete system side effects remain incomplete |
| Scalar single-precision FPU | Add/subtract/multiply/divide, integer conversions and selected compares have native semantics |
| Scalar double precision and fused/remainder operations | Incomplete; some forms remain opaque pending exact rounding/exception semantics |
| MAC/DSP | MAC state is named; the large arithmetic/queue/rounding family remains opaque |
| SIMD/vector | Vector register file is represented; arithmetic, packing, saturation and lane semantics remain largely unimplemented |
| Subword/bitfield/saturation | Incomplete; needs per-form validation for field numbering, sign extension and saturation behavior |
| Cache, MMU, PIC and timer | Some control operations have p-code hooks; detailed device/translation side effects are not fully emulated |

Opaque operations can still disassemble with correct length and operands when covered by the vendor table. Their decompiler output is not a trustworthy semantic reconstruction until a real p-code model exists.

## Evidence and validation policy

1. Vendor assembler tables establish encodings and operand-field structure.
2. Vendor objdump calibration checks how those encodings decode and print.
3. Vendor simulator probes establish execution behavior for the tested input/state combinations.
4. Independent implementations provide corroboration, not automatic truth.
5. Ghidra emulator tests prove the SLEIGH model behaves as its tests assert; they do not independently establish undocumented silicon behavior.

A firmware image is an additional test corpus. It reveals instructions used in that image and tests analysis of that target. It cannot define AEON R2's instruction set or determine which instructions matter to the architecture generally.
