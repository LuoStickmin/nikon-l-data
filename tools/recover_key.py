#!/usr/bin/env python3
"""Recover the per-position XOR key of the NKLD coefficient area.

Model (see README section 4): the 27 32-bit words of each record are

    cipher = (sign-extended 16-bit value) ^ key

where the key is the same for every record at a given (phase, word index),
phase = record index mod 4.  The high half of the key follows from the
sign-extension pattern; the low half is recovered here by choosing, for each
position, the 16-bit value that makes the decoded sequence vary most
smoothly across records (records of one lens are stored next to each other).

The search has an inherent 4-fold ambiguity per position:
    v, ~v, v ^ 0x8000, ~v ^ 0x8000
all decode to "smooth" sequences.  This tool keeps the member with the
smallest mean |v| and records the whole class so the ambiguity is explicit.

    python recover_key.py records.csv --out-prefix lens-fw/out/key-2.018
"""

import argparse
import csv
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nkld


def load_records(path):
    if path.lower().endswith(".csv"):
        rows = list(csv.DictReader(open(path)))
        coef = ["c%d" % i for i in range(27)]
        return [[int(r[c]) for c in coef] for r in rows]
    raw = open(path, "rb").read()
    d = nkld.parse(raw)
    return [list(nkld.record_fields(r)["coeffs"]) for r in d["records"]]


def recover(recs):
    n = len(recs)
    arr = np.array(recs, dtype=np.uint32)
    keys = np.zeros((4, 27), dtype=np.uint16)
    decoded = np.zeros((n, 27), dtype=np.int16)
    for phase in range(4):
        idx = np.arange(phase, n, 4)
        for j in range(27):
            C = (arr[idx, j] & 0xFFFF).astype(np.uint16)
            K = np.arange(65536, dtype=np.uint16)
            V = (C[None, :] ^ K[:, None]).astype(np.uint16).view(np.int16)
            score = np.abs(np.diff(V, axis=1).astype(np.int32)).sum(axis=1)
            k = int(np.argmin(score))
            best = None
            best_val = None
            for cand in (k, k ^ 0x8000, k ^ 0xFFFF, (k ^ 0x8000) ^ 0xFFFF):
                VV = (C ^ np.uint16(cand)).astype(np.uint16).view(np.int16)
                val = float(np.mean(np.abs(VV.astype(np.int32))))
                if best_val is None or val < best_val:
                    best_val, best = val, cand
            keys[phase, j] = best
            decoded[idx, j] = (C ^ np.uint16(best)).astype(np.uint16).view(np.int16)
    return keys, decoded


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--out-prefix", default=None)
    args = ap.parse_args()
    recs = load_records(args.file)
    keys, decoded = recover(recs)
    print("records", len(recs))
    print("keys[phase0]:", " ".join("%04X" % k for k in keys[0]))
    print("mean|v| %.1f  median|v| %.1f  zeros %.1f%%"
          % (np.abs(decoded).mean(), np.median(np.abs(decoded)),
             100.0 * (decoded == 0).mean()))
    g = np.abs(decoded).reshape(len(recs), 9, 3)
    mono = ((g[:, :, 0] >= g[:, :, 1]) & (g[:, :, 1] >= g[:, :, 2])).mean()
    print("triplets with |a|>=|b|>=|c|: %.1f%% (random 15.8%%)" % (100 * mono))
    if args.out_prefix:
        base = args.out_prefix
        np.save(base + "-keys.npy", keys)
        np.save(base + "-decoded.npy", decoded)
        json.dump({"%d_%d" % (p, j): int(keys[p, j])
                   for p in range(4) for j in range(27)},
                  open(base + "-keys.json", "w"), indent=0)
        with open(base + "-decoded.csv", "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["idx"] + ["k%d" % i for i in range(27)])
            for i, row in enumerate(decoded):
                w.writerow([i] + [int(x) for x in row])
        print("wrote", base + "-keys.json", "and", base + "-decoded.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
