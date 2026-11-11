#!/usr/bin/env python3
"""Parser for Nikon distortion-control lens data ("L" firmware, NKLD????.BIN).

Verified against Nikon Distortion Control Data 2.017 (NKLD0217.BIN) and
2.018 (NKLD0218.BIN).

Container layout (all multi-byte integers are big-endian):

  0x0000  u16  data offset (always 0x0020)
  0x0002  u16  0
  0x0004  u16  version: major (2) | minor as a hex-coded decimal (0x11=17, 0x12=18)
  0x0006  u16  record count N
  0x0008  u32  magic 0x87C7CAAC  (stored as bytes 87 C7 CA AC)
  0x000C  u32  2 + N*128          (data size, seen in 2.017/2.018)
  0x0010  u32  0
  0x0014  u32  0
  0x0018  u32  0
  0x001C  u16  0
  0x001E  u16  0x20 + N*128 + 4   (offset of the trailer's last field + 4)
  0x0020  N x 128-byte lens records

Trailer (immediately after the records):

  +0x00  u16  CRC16(poly 0x1021, init 0) over header + records
  +0x02  u16  0
  +0x04  u32  magic 0xF8E7C8A6 (stored as bytes F8 E7 C8 A6)
  +0x08  u32  0
  +0x0C  u32  24 + M*52            (offset where entry table ends)
  +0x10  u16  M (entry count)
  +0x12  u16  0
  +0x14  u16  52 (entry size)
  +0x16  u16  0
  +0x18  M x 52-byte entries
  +...   u16  CRC16(poly 0x1021, init 0) over every byte before it,
              excluding the trailing 0xCD fill
  +...   u16  0
  then   0xCD fill up to the end of the file

Record header (128-byte records, plaintext; matches the D750 lookup code):

  +0x00  u16  type tag: one of 0x3433 / 0xF473 / 0xB4B3 / 0x74F3
  +0x02  u16  lookup key 1 (compared by the camera lookup code)
  +0x04  u16  lookup key 2
  +0x06  u8   field copied to the runtime struct
  +0x07  u8   lookup key 3
  +0x08  u8   lookup key 4
  +0x09  u8   padding (never copied)
  +0x0A  u32  word A (big-endian, copied as one native word)
  +0x0E  u32  word B
  +0x12  u16  half-word C
  +0x14  27 x u32 coefficients (zeros included), big-endian
"""

import argparse
import binascii
import os
import struct
import sys

HDR = 0x20
REC = 0x80
MAGIC_HDR = 0x87C7CAAC
MAGIC_TRL = 0xF8E7C8A6
TAGS = {0x3433: "T0", 0xF473: "T1", 0xB4B3: "T2", 0x74F3: "T3"}


def crc16(data):
    """Nikon's CRC16: polynomial 0x1021, initial value 0, no final XOR."""
    return binascii.crc_hqx(data, 0)


def parse(raw):
    if len(raw) < HDR + 16:
        raise ValueError("file is too short")
    h = raw[:HDR]
    off, _z, ver, count = struct.unpack_from(">4H", h, 0)
    magic, size_a = struct.unpack_from(">II", h, 8)
    size_b = struct.unpack_from(">H", h, 0x1E)[0]
    if magic != MAGIC_HDR:
        raise ValueError("bad header magic 0x%08X" % magic)
    if off != HDR:
        raise ValueError("unexpected record offset 0x%X" % off)
    end = off + count * REC
    if end > len(raw):
        raise ValueError("record table runs past EOF")
    body = raw[:end]
    recs = [raw[off + i * REC:off + (i + 1) * REC] for i in range(count)]

    tr = raw[end:]
    if len(tr) < 0x18 + 4:
        raise ValueError("truncated trailer")
    crc_data = struct.unpack_from(">H", tr, 0)[0]
    tmagic = struct.unpack_from(">I", tr, 4)[0]
    len1 = struct.unpack_from(">I", tr, 0x0C)[0]
    m = struct.unpack_from(">H", tr, 0x10)[0]
    esz = struct.unpack_from(">H", tr, 0x14)[0]
    if tmagic != MAGIC_TRL:
        raise ValueError("bad trailer magic 0x%08X" % tmagic)

    entries = tr[0x18:0x18 + m * esz]
    if len(entries) != m * esz:
        raise ValueError("truncated trailer entries")
    tail = tr[0x18 + m * esz:]
    # last 4 bytes before the 0xCD fill carry the whole-file CRC16
    fill = 0
    while fill < len(tail) and tr[len(tr) - 1 - fill] == 0xCD:
        fill += 1
    meaningful_end = len(tr) - fill
    final_crc = struct.unpack_from(">H", tr, meaningful_end - 4)[0]

    return {
        "offset": off,
        "version": ver,
        "version_str": "%d.%03d" % (ver >> 8, ver & 0xFF),
        "count": count,
        "size_a": size_a,
        "size_b": size_b,
        "records": recs,
        "end": end,
        "trailer": tr,
        "trailer_len": len(tr),
        "fill": fill,
        "crc_data_stored": crc_data,
        "crc_data_actual": crc16(body),
        "entries": entries,
        "entry_count": m,
        "entry_size": esz,
        "len1": len1,
        "crc_final_stored": final_crc,
        "crc_final_actual": crc16(raw[:meaningful_end + end - 4]),
    }


def record_fields(r):
    tag = struct.unpack_from(">H", r, 0)[0]
    return {
        "tag": TAGS.get(tag, "0x%04X" % tag),
        "key1": struct.unpack_from(">H", r, 2)[0],
        "key2": struct.unpack_from(">H", r, 4)[0],
        "b6": r[6],
        "key3": r[7],
        "key4": r[8],
        "word_a": struct.unpack_from(">I", r, 0x0A)[0],
        "word_b": struct.unpack_from(">I", r, 0x0E)[0],
        "half_c": struct.unpack_from(">H", r, 0x12)[0],
        "coeffs": list(struct.unpack_from(">27I", r, 0x14)),
    }


def cmd_info(args):
    raw = open(args.file, "rb").read()
    d = parse(raw)
    ok_a = d["crc_data_stored"] == d["crc_data_actual"]
    ok_b = d["crc_final_stored"] == d["crc_final_actual"]
    print("file            %s (%d bytes)" % (args.file, len(raw)))
    print("data offset     0x%X" % d["offset"])
    print("version         %s  (header 0x%04X)" % (d["version_str"], d["version"]))
    print("records         %d x 128 = %d bytes (0x%X..0x%X)"
          % (d["count"], d["count"] * REC, d["offset"], d["end"]))
    print("size fields     0x%08X / 0x%04X" % (d["size_a"], d["size_b"]))
    print("trailer         %d bytes, %d x %d-byte entries, 0x%X fill"
          % (d["trailer_len"], d["entry_count"], d["entry_size"], d["fill"]))
    print("CRC data        stored %04X  computed %04X  %s"
          % (d["crc_data_stored"], d["crc_data_actual"], "OK" if ok_a else "MISMATCH"))
    print("CRC whole file  stored %04X  computed %04X  %s"
          % (d["crc_final_stored"], d["crc_final_actual"], "OK" if ok_b else "MISMATCH"))
    tags = {}
    for r in d["records"]:
        t = record_fields(r)["tag"]
        tags[t] = tags.get(t, 0) + 1
    print("record tags     %s" % ", ".join("%s=%d" % kv for kv in sorted(tags.items())))
    return 0 if ok_a and ok_b else 1


def cmd_dump(args):
    raw = open(args.file, "rb").read()
    d = parse(raw)
    print("idx  tag   key1  key2  b6   k3   k4   wordA     wordB     c     coeff0")
    for i, r in enumerate(d["records"]):
        f = record_fields(r)
        print("%3d  %-5s %04X  %04X  %02X   %02X   %02X   %08X  %08X  %04X  %08X"
              % (i, f["tag"], f["key1"], f["key2"], f["b6"], f["key3"], f["key4"],
                 f["word_a"], f["word_b"], f["half_c"], f["coeffs"][0]))
    return 0


def cmd_csv(args):
    import csv
    raw = open(args.file, "rb").read()
    d = parse(raw)
    w = csv.writer(open(args.out, "w", newline=""))
    w.writerow(["idx", "tag", "key1", "key2", "b6", "key3", "key4",
                "word_a", "word_b", "half_c"] + ["c%d" % i for i in range(27)])
    for i, r in enumerate(d["records"]):
        f = record_fields(r)
        w.writerow([i, f["tag"], f["key1"], f["key2"], f["b6"], f["key3"], f["key4"],
                    f["word_a"], f["word_b"], f["half_c"]] + f["coeffs"])
    print("wrote %s (%d records)" % (args.out, d["count"]))
    return 0


def cmd_verify(args):
    raw = open(args.file, "rb").read()
    d = parse(raw)
    problems = []
    if d["crc_data_stored"] != d["crc_data_actual"]:
        problems.append("data CRC")
    if d["crc_final_stored"] != d["crc_final_actual"]:
        problems.append("whole-file CRC")
    if problems:
        print("FAIL: " + ", ".join(problems))
        return 1
    print("OK: 2 CRC16 fields valid (%04X, %04X)"
          % (d["crc_data_stored"], d["crc_final_stored"]))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("info", help="print container summary")
    p.add_argument("file")
    p.set_defaults(func=cmd_info)
    p = sub.add_parser("dump", help="list records")
    p.add_argument("file")
    p.set_defaults(func=cmd_dump)
    p = sub.add_parser("verify", help="verify both CRC16 fields")
    p.add_argument("file")
    p.set_defaults(func=cmd_verify)
    p = sub.add_parser("csv", help="export all records to CSV")
    p.add_argument("file")
    p.add_argument("out")
    p.set_defaults(func=cmd_csv)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
