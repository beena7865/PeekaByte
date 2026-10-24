"""Show the first bytes hidden in the low bits, with NO filtering.
Usage: python peek_bits.py "path\\to\\image.png"
Read the lines: real text looks like words; noise looks like symbols."""
import sys

import numpy as np
from PIL import Image


def show(data):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def main(path):
    img = Image.open(path)
    if img.mode not in ("RGB", "RGBA", "L"):
        img = img.convert("RGBA" if "A" in img.getbands() else "RGB")
    a = np.array(img)
    if a.ndim == 2:
        a = a[:, :, None]
    c = a.shape[2]
    names = "RGBA"[:c] if c > 1 else "L"
    sets = {names[i]: [i] for i in range(c)}
    if c >= 3:
        sets["RGB"] = [0, 1, 2]
        sets["BGR"] = [2, 1, 0]
    scans = {"rows": a.reshape(-1, c)[:2000], "columns": a.transpose(1, 0, 2).reshape(-1, c)[:2000]}
    print(path, img.mode, img.size, "\n")
    for sname, px in scans.items():
        for cname, idx in sets.items():
            for plane in (0, 1):
                bits = ((px[:, idx] >> plane) & 1).reshape(-1)
                n = len(bits) // 8 * 8
                big = np.packbits(bits[:n], bitorder="big").tobytes()[:40]
                lit = np.packbits(bits[:n], bitorder="little").tobytes()[:40]
                print(f"{sname:7} {cname:4} bit{plane} big   : {show(big)}")
                print(f"{sname:7} {cname:4} bit{plane} little: {show(lit)}")


if __name__ == "__main__":
    main(sys.argv[1])