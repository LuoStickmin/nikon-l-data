#!/usr/bin/env python3
"""Probe the obfuscation of the 27 coefficient words in NKLD records.

Observation (2.017 and 2.018): for every (phase, word index) pair the high
16 bits of the 32-bit word take only a handful of values, and they flip
between M and ~M according to the sign bit of the low 16 bits.  That is the
signature of a 32-bit XOR keystream applied to a plaintext word that is a
sign-extended 16-bit value:

    cipher = plaintext ^ key,   plaintext_high = 0x0000 or 0xFFFF

This script quantifies that model and prints, per position, the high-half
base value M (the key's high half, up to the sign convention).

    python analyze_obfuscation.py records.csv
    python analyze_obfuscation.py --bin NKLD0218.BIN
"""

import argparse
import csv
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nkld


def load_words(path):
    if path.lower().endswith(".csv"):
        rows = list(csv.DictReader(open(path)))
        coef = ["c%d" % i for i in range(27)]
        out = [[0] * 27 for _ in rows]
        for i, r in enumerate(rows):
            out[i] = [int(r[c]) for c in coef]
        return out
    raw = open(path, "rb").read()
    d = nkld.parse(raw)
    return [list(nkld.record_fields(r)["coeffs"]) for r in d["records"]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--bin", action="store_true", help="file is a .BIN, not a CSV")
    args = ap.parse_args()
    recs = load_words(args.file)
    n = len(recs)
    print("%d records" % n)

    total = 0
    ok = 0
    positions = []
    for phase in range(4):
        idx = list(range(phase, n, 4))
        for j in range(27):
            vals = [recs[i][j] for i in idx]
            highs = Counter(v >> 16 for v in vals)
            m0 = highs.most_common(1)[0][0]

            def score(base):
                good = 0
                for v in vals:
                    neg = (v & 0xFFFF) >= 0x8000
                    good += (v >> 16) == (base ^ (0xFFFF if neg else 0))
                return good

            base = m0 if score(m0) >= score(m0 ^ 0xFFFF) else m0 ^ 0xFFFF
            good = score(base)
            total += len(vals)
            ok += good
            positions.append((phase, j, base, len(highs), good, len(vals)))

    print("sign-extension-under-XOR model: %d/%d = %.2f%% consistent"
          % (ok, total, 100.0 * ok / total))
    print("\nphase word  key_high  distinct_high16  consistent")
    for phase, j, base, nh, good, cnt in positions:
        print("%5d %4d  0x%04X   %12d      %3d/%d" % (phase, j, base, nh, good, cnt))
    return 0


if __name__ == "__main__":
    sys.exit(main())
