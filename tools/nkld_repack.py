#!/usr/bin/env python3
"""Edit NKLD lens-data containers and restore the two CRC16 fields.

The container has no signature, only two CRC16s:

  * header + record array  ->  trailer +0x00
  * whole file (up to the final field) -> trailer + len1

So a modified record becomes structurally valid again once both CRCs are
recomputed.  This tool edits plaintext record bytes in place and rewrites
the checksums; it never re-encrypts or re-signs anything.

Usage:
    python nkld_repack.py patch IN.bin OUT.bin --record 0 --offset 0x14 --hex DEADBEEF
    python nkld_repack.py selftest IN.bin
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nkld


def fix_crcs(raw):
    """Return a bytearray with both CRC16 fields recomputed."""
    buf = bytearray(raw)
    d = nkld.parse(raw)
    end = d["end"]
    trailer = d["trailer"]
    len1 = d["len1"]

    # data CRC: header + records
    struct.pack_into(">H", buf, end, nkld.crc16(bytes(buf[:end])))

    # whole-file CRC: everything before the field, padding excluded
    crc_at = end + len1
    struct.pack_into(">H", buf, crc_at, nkld.crc16(bytes(buf[:crc_at])))
    return buf


def check_layout(raw, path="<buffer>"):
    """Parse and assert the layout invariants the camera code relies on."""
    d = nkld.parse(raw)
    assert d["offset"] == 0x20
    assert d["version"] >> 8 == 2
    assert 0 < d["count"] <= 64 * 8
    assert d["trailer"][4:8] == b"\xF8\xE7\xC8\xA6"
    return d


def cmd_patch(args):
    raw = open(args.file, "rb").read()
    d = nkld.parse(raw)
    rec_start = d["offset"] + args.record * nkld.REC
    if not 0 <= args.record < d["count"]:
        sys.exit("record %d out of range (0..%d)" % (args.record, d["count"] - 1))
    if args.offset < 0 or args.offset + len(args.hex) // 2 > nkld.REC:
        sys.exit("patch does not fit inside a 128-byte record")
    data = bytes.fromhex(args.hex)
    buf = bytearray(raw)
    buf[rec_start + args.offset:rec_start + args.offset + len(data)] = data
    print("patched record %d, +0x%X, %d bytes: %s"
          % (args.record, args.offset, len(data), data.hex()))
    print("  old data CRC  %04X" % d["crc_data_stored"])
    print("  old file CRC  %04X" % d["crc_final_stored"])

    buf = fix_crcs(bytes(buf))
    d2 = check_layout(bytes(buf))
    print("  new data CRC  %04X %s"
          % (d2["crc_data_stored"], "OK" if d2["crc_data_stored"] == d2["crc_data_actual"] else "BAD"))
    print("  new file CRC  %04X %s"
          % (d2["crc_final_stored"], "OK" if d2["crc_final_stored"] == d2["crc_final_actual"] else "BAD"))
    with open(args.out, "wb") as fh:
        fh.write(buf)
    print("wrote %s (%d bytes)" % (args.out, len(buf)))
    return 0


def cmd_patch_raw(args):
    raw = open(args.file, "rb").read()
    d = nkld.parse(raw)
    if args.offset < 0 or args.offset + len(args.hex) // 2 > len(raw) - 4:
        sys.exit("patch does not fit inside the file")
    buf = bytearray(raw)
    data = bytes.fromhex(args.hex)
    buf[args.offset:args.offset + len(data)] = data
    print("patched file offset 0x%X, %d bytes: %s" % (args.offset, len(data), data.hex()))
    print("  old data CRC  %04X" % d["crc_data_stored"])
    print("  old file CRC  %04X" % d["crc_final_stored"])
    buf = fix_crcs(bytes(buf))
    d2 = check_layout(bytes(buf))
    print("  new data CRC  %04X" % d2["crc_data_stored"])
    print("  new file CRC  %04X" % d2["crc_final_stored"])
    with open(args.out, "wb") as fh:
        fh.write(buf)
    print("wrote %s (%d bytes)" % (args.out, len(buf)))
    return 0


def cmd_selftest(args):
    raw = open(args.file, "rb").read()
    d0 = nkld.parse(raw)
    print("baseline: %d records, version %s, trailers %d x %d"
          % (d0["count"], d0["version_str"], d0["entry_count"], d0["entry_size"]))

    # Flip one coefficient byte deep inside record 0 and repair the CRCs.
    off = d0["offset"] + 0x30
    buf = bytearray(raw)
    buf[off] ^= 0xFF
    buf = fix_crcs(bytes(buf))
    d1 = check_layout(bytes(buf), "patched")
    print("after patch: data CRC %04X (was %04X), file CRC %04X (was %04X)"
          % (d1["crc_data_stored"], d0["crc_data_stored"],
             d1["crc_final_stored"], d0["crc_final_stored"]))
    ok = (d1["crc_data_stored"] == d1["crc_data_actual"] and
          d1["crc_final_stored"] == d1["crc_final_actual"] and
          d1["count"] == d0["count"] and
          d1["version"] == d0["version"] and
          d1["offset"] == d0["offset"] and
          d1["entry_count"] == d0["entry_count"])
    print("selftest:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("patch", help="patch bytes in a record and fix CRCs")
    p.add_argument("file")
    p.add_argument("out")
    p.add_argument("--record", type=int, required=True)
    p.add_argument("--offset", type=lambda s: int(s, 0), required=True,
                   help="byte offset inside the 128-byte record (e.g. 0x14)")
    p.add_argument("--hex", required=True)
    p.set_defaults(func=cmd_patch)

    p = sub.add_parser("selftest", help="patch one byte and verify CRC repair")
    p.add_argument("file")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("patch-raw", help="patch any file offset and fix CRCs")
    p.add_argument("file")
    p.add_argument("out")
    p.add_argument("--offset", type=lambda s: int(s, 0), required=True)
    p.add_argument("--hex", required=True)
    p.set_defaults(func=cmd_patch_raw)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
