#!/usr/bin/env python3
"""Check that the native SIMD semantic inventory is real, generated, and non-opaque."""
import json
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ISA = ROOT / "isa" / "aeon_isa.json"
SINC = ROOT / "data" / "languages" / "aeonR2.sinc"
GENERATOR = ROOT / "tools" / "gen_sleigh.py"

def fail(message):
    raise SystemExit("AEON SIMD coverage failure: " + message)

namespace = runpy.run_path(str(GENERATOR), run_name="aeon_simd_coverage_test")
semantics = namespace["SEMANTICS"]
isa = json.loads(ISA.read_text(encoding="utf-8"))["aeon_aeonR2_isa"]
opcodes = {op["name"] for op in isa["opcodes"] if not op.get("for_encode_only")}
native = {name for name in semantics if name.startswith("mv.")}

required = {
    "mv.and", "mv.or", "mv.xor",
    "mv.add", "mv.addu", "mv.add.b", "mv.addu.b",
    "mv.sub", "mv.subu", "mv.sub.b", "mv.subu.b",
    "mv.avg", "mv.avgu", "mv.avg.b", "mv.avgu.b",
    "mv.seq", "mv.seq.b", "mv.slt", "mv.sltu", "mv.slt.b", "mv.sltu.b",
    "mv.min", "mv.minu", "mv.max", "mv.maxu",
    "mv.sra", "mv.srl", "mv.sll", "mv.abs", "mv.upckl", "mv.upckh",
}
missing = sorted(required - native)
if missing:
    fail("required native semantics absent: " + ", ".join(missing))
unknown = sorted(native - opcodes)
if unknown:
    fail("semantic keys are not real ISA opcodes: " + ", ".join(unknown))

sinc = SINC.read_text(encoding="utf-8")
for name in sorted(native):
    constructors = [line for line in sinc.splitlines()
                   if line.startswith(":" + name + " ")]
    if not constructors:
        fail(f"{name} has a generator semantic but no emitted SLEIGH constructor")
    if any("aeon_" in line for line in constructors):
        fail(f"{name} still lowers to an opaque userop instead of native P-code")

simd_opcodes = sorted(name for name in opcodes if name.startswith("mv."))
fallback = sorted(set(simd_opcodes) - native)
print(f"AEON SIMD coverage: {len(native)}/{len(simd_opcodes)} opcode forms have native semantics")
print("Native: " + ", ".join(sorted(native)))
print("Still opaque/unmodeled: " + ", ".join(fallback))
