#!/usr/bin/env python3
"""Read Nikon NEF lens information: lens ID, focal/aperture, distortion flag.

Decrypts the MakerNote LensData block with ExifTool's documented algorithm
(see Nikon.pm: Decrypt() + @xlat tables) so the 8-byte lens ID can be read
without exiftool installed.

    python nef_info.py photo.NEF [more.NEF ...]
"""

import os
import re
import struct
import sys

SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}


XLAT_HEX = (
    "c1bf6d0d59c5139d83616b4fc77f3d3d5359e3c7e92f95a7951fdf7f2b29c70ddf07ef71893d133d3b13fb0d89c1651f"
    "b30d6b29e3fbefa36b477f9535a7474fc7f1599535112961f13db32b0d4389c19d9d8965f1e9dfbf3d7f5397e5e99517"
    "1d3d8bfbc7e367a707f171a753b52989e52ba71729e94fc5656d6bef0d89492fb34353651d49a3138959ef6bef651d0b5"
    "913e34f9db329432b071d95595947fbe5e961472f357f177fef7f959571d3a30b71a3ad0b3bb5fba3bf4f831dade92f71"
    "65a3e507353d0db5e9e5473b9def35a3bfb3df53d397534971073561712f432f11df1797fb953b7f6bd325bfadc7c5c5"
    "b58bef2fd3076b25499525496d71c7"
)
XLAT_HEX2 = (
    "a7bcc9ad91df85e5d478d517467c294c4d03e925681186b3bdf76f6122a226342abe1e4614689d4418c240f47e5f1bad"
    "0b94b667b40be1ea959c66dce75d6c05dad5df7aeff6db1f824cc06847a1bdee3950564adddfa5f8c6daca90ca01429d"
    "8b0c7343750594de24b38034e52cdc9b3fca3345d0db5ff552c321dae222726b3ed05ba8878c065d0fdd091993d0b9fc"
    "8b0f8460331c9b45f1f0a3943a1277334d4478283c9efd655716946bfb59d0c82236dbd2639843a1048786f7a626bbd6"
    "594dbf6a2eaa2befe678b64ee02fdc7cbe5719327e2ad0b8ba29003c527da8493b2deb2549faa3aa39a7c5a7501136fb"
    "c6674af5a512657eb0dfaf4eb3617f2f"
)


def load_xlat():
    return [list(bytes.fromhex(XLAT_HEX)), list(bytes.fromhex(XLAT_HEX2))]


def decrypt(data, start, serial, count, xlat):
    ci0 = xlat[0][serial & 0xFF]
    key = 0
    for i in range(4):
        key ^= (count >> (i * 8)) & 0xFF
    cj = xlat[1][key]
    ck = 0x60
    out = bytearray(data)
    for i in range(start, len(out)):
        cj = (cj + ci0 * ck) & 0xFF
        ck = (ck + 1) & 0xFF
        out[i] ^= cj
    return bytes(out)


def read_ifd(b, base, off, order):
    out = {}
    cnt = struct.unpack_from(order + "H", b, base + off)[0]
    for i in range(cnt):
        e = base + off + 2 + i * 12
        tag, typ, num, val = struct.unpack_from(order + "HHII", b, e)
        out.setdefault(tag, []).append((typ, num, val, e))
    return out


def tag_data(b, base, order, typ, num, val, e):
    n = SIZES.get(typ, 1) * num
    if n <= 4:
        return b[e + 8:e + 8 + n]
    return b[base + val:base + val + n]


def lens_info(path, xlat):
    b = open(path, "rb").read()
    order = "<" if b[:2] == b"II" else ">"
    _, ifd0_off = struct.unpack_from(order + "HI", b, 2)
    ifd0 = read_ifd(b, 0, ifd0_off, order)
    exif = read_ifd(b, 0, ifd0[0x8769][0][2], order)
    mn = exif[0x927C][0][2]
    mt = mn + 10
    o2 = "<" if b[mt:mt + 2] == b"II" else ">"
    m = read_ifd(b, mt, struct.unpack_from(o2 + "I", b, mt + 4)[0], o2)

    def dat(tag):
        return tag_data(b, mt, o2, *m[tag][0])

    serial = int(dat(0x001D).rstrip(b"\0").decode())
    sc = dat(0x00A7) if 0x00A7 in m else b"\0\0\0\0"
    count = struct.unpack_from(o2 + "I", (sc + b"\0\0\0\0")[:4])[0]
    ld = dat(0x0098)
    dec = decrypt(ld, 4, serial, count, xlat)

    fl = exif[0x920A][0]
    n, d = struct.unpack_from(order + "II", b, fl[2])
    fn = exif[0x829D][0]
    n2, d2 = struct.unpack_from(order + "II", b, fn[2])
    di = dat(0x002B)
    return dict(
        file=os.path.basename(path),
        focal=n / d if d else 0,
        fnumber=n2 / d2 if d2 else 0,
        serial=serial,
        shutter_count=count,
        lens_version=dec[:4].decode("latin1"),
        lens_id=dec[0x0C:0x14].hex(" ").upper(),
        lens_id_number=dec[0x0C],
        min_focal=round(5 * 2 ** (dec[0x0E] / 24), 1),
        max_focal=round(5 * 2 ** (dec[0x0F] / 24), 1),
        ap_min=round(2 ** (dec[0x10] / 24), 1),
        ap_max=round(2 ** (dec[0x11] / 24), 1),
        auto_distortion=di[4] if len(di) > 4 else None,
    )


def main(argv):
    xlat = load_xlat()
    for p in argv:
        r = lens_info(p, xlat)
        print("%s: %gmm f/%g  lens %s (%d-%dmm f/%g-%g)  distort=%s"
              % (r["file"], r["focal"], r["fnumber"], r["lens_id"],
                 r["min_focal"], r["max_focal"], r["ap_min"], r["ap_max"],
                 r["auto_distortion"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
