#!/usr/bin/env python3
"""Generate placeholder PNG screenshots — replace with real captures later."""

import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(__file__), "..", "docs", "assets", "screenshots")

FILES = [
    "main-window-light.png",
    "main-window-dark.png",
    "context-menu.png",
    "tab-file-info.png",
    "tab-metadata.png",
    "tab-permissions.png",
    "tab-components.png",
    "tab-component-names.png",
    "tab-contents.png",
    "tab-signing.png",
    "tab-certificate.png",
    "tab-native-libs.png",
    "tab-strings.png",
]


def _chunk(chunk_type, data):
    c = chunk_type + data
    return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)


def write_placeholder(path, width=960, height=600):
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            r = 30 + (x * 18 // width)
            g = 38 + (y * 12 // height)
            b = 55 + ((x + y) % 24)
            rows.extend((r, g, b))

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    data = sig + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", zlib.compress(bytes(rows), 9))
    data += _chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(data)


def main():
    os.makedirs(OUT, exist_ok=True)
    for name in FILES:
        path = os.path.join(OUT, name)
        write_placeholder(path)
        print(f"  {path}")
    print(f"\nCreated {len(FILES)} placeholder PNGs in docs/assets/screenshots/")


if __name__ == "__main__":
    main()
