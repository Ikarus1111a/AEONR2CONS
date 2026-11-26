#!/usr/bin/env python3
"""Regression checks for corrections reviewed from the legacy AEON R2 plugins."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SINC = (ROOT / "data/languages/aeonR2.sinc").read_text()
CAL = json.loads((ROOT / "isa/calibration.json").read_text())
ISA = json.loads((ROOT / "isa/aeon_isa.json").read_text())["aeon_aeonR2_isa"]
LETTERS = {item["letter"]: item for item in ISA["letters"] if item.get("letter")}


def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)
    print("PASS:", message)


# Rajkosto's correction: old i16/i24 token ranges were accidentally reversed.
# The generated AEON R2 language has corresponding slices in 16-, 24-, and
# 32-bit tokens, all with ascending endpoints 2..4.
for token in ("t_c2_4=(2,4)", "n_c2_4=(2,4)", "g_c2_4=(2,4)"):
    require(token in SINC, f"correct bit-field endpoints: {token}")

# throwaway96's signed-immediate fixes, now derived from the vendor ISA table.
for mnemonic, letter in (
    ("bn.sfnei", "O"),
    ("bn.beqi", "%"),
    ("bg.sfnei", "Y"),
    ("bg.beqi", "I"),
):
    require(mnemonic in CAL, f"vendor calibration includes {mnemonic}")
    require(letter in LETTERS and (LETTERS[letter]["flags"] & 2),
            f"{mnemonic} operand {letter!r} is marked signed in vendor ISA")

# The generated constructors must use the calibrated operand fields.
for constructor, field, description in (
    (":b.sfnei", "n_O_5_12", "bn.sfnei signed O field"),
    (":b.beqi", "n_PCT_10_12", "bn.beqi signed percent-immediate field"),
    (":b.sfnei", "g_Y_5_20", "bg.sfnei signed Y field"),
    (":b.beqi", "g_I_16_20", "bg.beqi signed I field"),
):
    require(any(constructor in line and field in line for line in SINC.splitlines()),
            f"{description}")

# The old throwaway96 decoder needed an explicit zero-extension fix for lbz.
require(":b.lbz" in SINC and "zext(*[$(DATA)]:1" in SINC,
        "byte loads zero-extend")
require(":b.lbs" in SINC and "sext(*[$(DATA)]:1" in SINC,
        "signed byte loads sign-extend")

# Cache semantics from the old branch are represented by named AEON p-code ops.
for name in ("aeon_flush(", "aeon_invalidate(", "aeon_flush_invalidate(",
             "aeon_sync_write_buffer(", "aeon_flush_line(",
             "aeon_invalidate_line(", "aeon_flush_invalidate_line("):
    require(name in SINC, f"cache/synchronization semantics: {name[:-1]}")

print("Legacy AEON R2 regression checks passed.")
