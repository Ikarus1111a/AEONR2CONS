#!/usr/bin/env python3
"""Guard the generated AEON R2 SPR aliases against architectural-state drift.

This is intentionally a source-level invariant test: it needs only Python's
standard library and runs without Ghidra or the proprietary vendor toolchain.
"""
import ast
import runpy
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "tools" / "gen_sleigh.py"
STATE_DOC = ROOT / "docs" / "architecture-state.md"
SLEIGH = ROOT / "data" / "languages" / "aeonR2.sinc"


def fail(message):
    raise SystemExit("AEON SPR invariant failure: " + message)


tree = ast.parse(GENERATOR.read_text(encoding="utf-8"), filename=str(GENERATOR))
function = next(
    node for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name == "spr_access_semantics"
)

named_node = None
for node in ast.walk(function):
    if isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id == "named"
        for target in node.targets
    ):
        named_node = node.value
        break
if named_node is None:
    fail("spr_access_semantics no longer declares its named SPR map")

try:
    named = ast.literal_eval(named_node)
except (ValueError, TypeError):
    fail("named SPR map must remain a literal list of (index, name) pairs")

actual = list(named)
# Keep this expectation independent of the generator's bank-expansion loop.
expected = {
    17: "sr",
    0x2801: "maclo",
    0x2802: "machi",
    0x2803: "machi2",
    0x2805: "amacguard0",
    0x2806: "amacguard1",
    0x2808: "mulhi",
    0x2809: "amac0lo",
    0x280A: "amac0hi",
    0x280B: "amac1lo",
    0x280C: "amac1hi",
    0x280D: "amac_cfg",
    0x280E: "amacstatus",
    0x2810: "amacq0",
    0x2811: "amacq0_addrofs",
    0x2812: "amacq0_stride",
    0x2813: "amacq0_stride2",
    0x2814: "amacq0_addrofs_stride",
    0x2818: "amacq1",
    0x2819: "amacq1_addrofs",
    0x281A: "amacq1_stride",
    0x281B: "amacq1_stride2",
    0x281C: "amacq1_addrofs_stride",
}
for base, prefix in ((32, "epcr"), (48, "eear"), (64, "esr")):
    expected.update({base + i: f"{prefix}{i}" for i in range(16)})

actual_indices = [index for index, _ in actual]
actual_names = [name for _, name in actual]
if len(actual_indices) != len(set(actual_indices)):
    fail("duplicate SPR index in generator")
if len(actual_names) != len(set(actual_names)):
    fail("duplicate SPR register name in generator")
if dict(actual) != expected:
    missing = sorted(set(expected.items()) - set(actual))
    extra = sorted(set(actual) - set(expected.items()))
    fail(f"SPR map differs; missing={missing}, extra={extra}")

# Exercise the actual generator function for immediate and register-indexed
# accesses, on both read and write paths. Every named alias must be routed.
namespace = runpy.run_path(str(GENERATOR), run_name="aeon_generator_invariant_test")
route = namespace["spr_access_semantics"]
generated_routes = {}
for write in (False, True):
    for immediate in (False, True):
        output = route(write, immediate)
        direction = "write" if write else "read"
        generated_routes[direction] = output
        for index, name in expected.items():
            branch = f"if (n == {index}:4) goto <{direction}_{name}>;"
            if branch not in output or f"<{direction}_{name}>" not in output:
                fail(f"{direction} route missing {name} at SPR {index:#x}, immediate={immediate}")
        fallback = "*[spr]:4 (addr)"
        if fallback not in output:
            fail(f"{direction} route lost generic SPR fallback")
        if immediate and "local n:4 = {U};" not in output:
            fail(f"{direction} immediate route uses the wrong SPR index source")
        if not immediate and "local n:4 = {A} + {PIPE};" not in output:
            fail(f"{direction} register-indexed route uses the wrong SPR index source")

# The generated .sinc is the source Ghidra consumes. Check that it contains
# the exact routing, not merely that the Python helper could generate it.
sinc = SLEIGH.read_text(encoding="utf-8")
for direction, output in generated_routes.items():
    for index, name in expected.items():
        if f"if (n == {index}:4) goto <{direction}_{name}>;" not in sinc:
            fail(f"checked-in SLEIGH {direction} route missing {name} at SPR {index:#x}")
        if f"<{direction}_{name}>" not in sinc:
            fail(f"checked-in SLEIGH {direction} label missing for {name}")
        if direction == "read":
            alias = "<read_" + name + r">\s+\S+\s*=\s*" + re.escape(name) + r"\s*;"
        else:
            alias = "<write_" + name + r">\s+" + re.escape(name) + r"\s*=\s*\S+\s*;"
        if not re.search(alias, sinc):
            fail(f"checked-in SLEIGH {direction} alias does not access {name}")
    if "*[spr]:4 (addr)" not in sinc:
        fail("checked-in SLEIGH lost generic SPR fallback")

# Assert that the four real constructors wire the intended index source.
# This catches a regression where the helper is correct but the committed
# .sinc attaches the wrong operand or a stale generated body.
constructor_sources = {
    ":b.mtspri ": "local n:4 = g_U_5_20;",
    ":b.mfspri ": "local n:4 = g_U_5_20;",
    ":b.mtspr ": "local n:4 = RD_g_A_16_20 + g_PIPE_4_15;",
    ":b.mfspr ": "local n:4 = RD_g_A_16_20 + g_PIPE_4_15;",
}
for constructor, source in constructor_sources.items():
    lines = [line for line in sinc.splitlines() if line.startswith(constructor)]
    if len(lines) != 1:
        fail(f"expected exactly one checked-in constructor {constructor.strip()}")
    if source not in lines[0]:
        fail(f"{constructor.strip()} uses an incorrect SPR index source")
    if "local addr:4 = n * 4;" not in lines[0]:
        fail(f"{constructor.strip()} no longer scales SPR index to byte address")

doc = STATE_DOC.read_text(encoding="utf-8")
for name in expected.values():
    if name not in doc:
        fail(f"architecture-state.md does not document {name}")
for fragment in ("32–47", "48–63", "64–79", "0x2801", "0x281C"):
    if fragment not in doc:
        fail(f"architecture-state.md is missing map evidence {fragment!r}")

print(f"AEON SPR invariants OK: {len(expected)} named registers; "
      "immediate/register-indexed read/write routes verified")
