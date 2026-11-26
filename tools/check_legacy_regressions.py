#!/usr/bin/env python3
"""Verify legacy AEON corrections in the active generated processor and ABI."""
import json
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SINC = (ROOT / "data/languages/aeonR2.sinc").read_text()
GEN = (ROOT / "tools/gen_sleigh.py").read_text()
CAL = json.loads((ROOT / "isa/calibration.json").read_text())
ISA = json.loads((ROOT / "isa/aeon_isa.json").read_text())["aeon_aeonR2_isa"]
LETTERS = {item["letter"]: item for item in ISA["letters"] if item.get("letter")}


def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)
    print("PASS:", message)


# Rajkosto's reversed-field correction is present in the active 16/24/32-bit
# generated instruction tokens, not just in a detached compatibility file.
for token in ("t_c2_4=(2,4)", "n_c2_4=(2,4)", "g_c2_4=(2,4)"):
    require(token in SINC, f"active SLEIGH bit slice: {token}")

# throwaway96's signed-immediate fixes are active generator inputs and output.
for mnemonic, letter, constructor, field in (
    ("bn.sfnei", "O", ":b.sfnei", "n_O_5_12"),
    ("bn.beqi", "%", ":b.beqi", "n_PCT_10_12"),
    ("bg.sfnei", "Y", ":b.sfnei", "g_Y_5_20"),
    ("bg.beqi", "I", ":b.beqi", "g_I_16_20"),
):
    require(mnemonic in CAL, f"calibration includes {mnemonic}")
    require(letter in LETTERS and (LETTERS[letter]["flags"] & 2),
            f"{mnemonic} operand {letter!r} is signed in the vendor ISA")
    require(any(constructor in line and field in line for line in SINC.splitlines()),
            f"active SLEIGH constructor uses signed field {field}")

# The old conditional-move operand bug is corrected in the live semantic
# generator: immediate/register order is represented by distinct operations.
for snippet, description in (
    ("'bn.cmovir':", "immediate-first conditional move"),
    ("'bn.cmovri':", "immediate-second conditional move"),
    ("'bn.cmovii':", "two-immediate conditional move"),
):
    require(snippet in GEN, f"active P-code generator defines {description}")
for mnemonic in (":b.cmovir", ":b.cmovri", ":b.cmovii"):
    require(mnemonic in SINC, f"active SLEIGH contains {mnemonic[1:]}")

# Byte loads retain the legacy zero/sign-extension correction.
require(":b.lbz" in SINC and "zext(*[$(DATA)]:1" in SINC,
        "unsigned byte loads zero-extend")
require(":b.lbs" in SINC and "sext(*[$(DATA)]:1" in SINC,
        "signed byte loads sign-extend")

# Supervision Register bit fields alias the architectural SR varnode; flags are
# not independent state that can diverge from mfspr/mtspr or exception restore.
COMMON = (ROOT / "data/languages/aeonR2_common.sinc").read_text()
for bitrange in ("F=sr[9,1]", "CY=sr[10,1]", "OV=sr[11,1]", "SM=sr[0,1]"):
    require(bitrange in COMMON, f"SR bit-range alias: {bitrange}")
require("define register offset=0x120 size=1 [ F CY ]" not in COMMON,
        "F/CY are no longer independent registers")
for filename in ("aeonR2.cspec", "aeonR2le.cspec", "aeonR2le_harvard.cspec"):
    cspec = ET.parse(ROOT / "data/languages" / filename).getroot()
    killed = {node.attrib["name"] for node in cspec.findall(".//killedbycall/register")}
    require("sr" in killed, f"{filename} marks SR caller-clobbered")
    require(not ({"F", "CY", "OV"} & killed),
            f"{filename} does not refer to non-varnode bitranges in call effects")
for mnemonic in ("'bg.mtspr':", "'bg.mfspr':", "'bg.mtspr1':", "'bg.mfspr1':"):
    require(mnemonic in GEN and "n == 17:4" in GEN[GEN.index(mnemonic):GEN.index(mnemonic)+500],
            f"{mnemonic.strip(chr(39)+chr(58))} routes SPR_SR to SR")
require("local esr_addr:4 = 0x100" in SINC and "sr = esr" in SINC and "return [epc]" in SINC,
        "RFE restores ESR0 to SR and returns through EPCR0")


# Scalar IEEE-754 single-precision operations must be represented by native P-code.
for mnemonic, expression in (
    (":b.addsf", "f+"),
    (":b.subsf", "f-"),
    (":b.mulsf", "f*"),
    (":b.divsf", "f/"),
    (":lf.itof.s", "int2float("),
    (":lf.ftoi.s", "trunc("),
    (":b.sfeqsf", "f=="),
    (":b.sflesf", "f<="),
    (":b.sfnesf", "f!="),
    (":b.sfgtsf", "f<"),
):
    line = next((line for line in SINC.splitlines() if line.startswith(mnemonic + " ")), "")
    require(bool(line) and expression in line and "aeon_" not in line,
            f"{mnemonic} uses native floating-point semantics")
for name in ("'bn.addsf':", "'bn.subsf':", "'bn.mulsf':", "'bn.divsf':",
             "'bn.i2sf':", "'bn.sf2i':", "'bn.sfeqsf':", "'bn.sflesf':",
             "'bn.sfnesf':", "'bn.sfgtsf':"):
    require(name in GEN, f"generator defines {name.strip(chr(39)+chr(58))}")

# MStar AEON R2 preserves the three 32-bit MAC words across exception entry/exit.
for name in ("maclo", "machi", "machi2", "mulhi"):
    require(name in COMMON, f"architectural register is named: {name}")
for spr_number, register_name in (
    (10241, "maclo"), (10242, "machi"), (10243, "machi2"), (10248, "mulhi")
):
    value = str(spr_number)
    require(value in GEN and f"{register_name} = {{B}}" in GEN and
            f"{{Dw}} = {register_name}" in GEN,
            f"SPR {spr_number:#06x} aliases {register_name}")
for mnemonic in (":b.mul ", ":b.mulu ", ":b.muli "):
    line = next((line for line in SINC.splitlines() if line.startswith(mnemonic)), "")
    require("product[0,32]" in line and "product[32,32]" in line and "mulhi" in line,
            f"{mnemonic.strip()} writes low and high halves")
require("CID=sr[28,4]" in COMMON, "SR context-ID bits are represented")

# Cache/synchronization behavior is emitted as active AEON P-code operations,
# including the operations added or refined during the legacy work.
for name in ("aeon_flush(", "aeon_invalidate(", "aeon_flush_invalidate(",
             "aeon_sync_write_buffer(", "aeon_flush_line(",
             "aeon_invalidate_line(", "aeon_flush_invalidate_line("):
    require(name in SINC, f"active cache/sync semantics: {name[:-1]}")

# Carry the corrected legacy ABI scalar alignment into every active language.
expected = {1: 1, 2: 2, 4: 4, 8: 4}
for filename in ("aeonR2.cspec", "aeonR2le.cspec", "aeonR2le_harvard.cspec"):
    root = ET.parse(ROOT / "data/languages" / filename).getroot()
    org = root.find("data_organization")
    require(org is not None, f"{filename} defines data organization")
    sizes = {
        int(entry.attrib["size"]): int(entry.attrib["alignment"])
        for entry in org.findall("./size_alignment_map/entry")
    }
    require(sizes == expected, f"{filename} uses ABI scalar alignment {expected}")
    require(org.find("pointer_size").attrib["value"] == "4",
            f"{filename} uses 32-bit pointers")

# The modern generator does not turn unsupported encodings into empty no-ops:
# it emits named opaque pseudo-ops, preserving their mnemonic, operands and length.
require("def pseudo(" in GEN and "self.pcodeops.add(fn)" in GEN,
        "unmodelled instructions retain named opaque P-code operations")

print("Legacy AEON implementation checks passed.")
