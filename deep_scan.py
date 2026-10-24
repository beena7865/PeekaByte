"""Deep scan: tries many more bit layouts on an image and reports candidates.
Usage: python deep_scan.py "path\\to\\image.png"
Candidates are LEADS, not proof. Encrypted messages cannot be read."""
import re
import sys

import numpy as np
from PIL import Image

LIMIT = 300_000            # bytes examined per layout
SIGS = [(b"PK\x03\x04", "ZIP archive"), (b"\x89PNG", "PNG image"),
        (b"%PDF-", "PDF document"), (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF8", "GIF image"), (b"Rar!", "RAR archive"),
        (b"7z\xbc\xaf", "7-Zip archive"), (b"\x1f\x8b\x08", "gzip data"),
        (b"BZh", "bzip2 data"), (b"RIFF", "RIFF (WAV/WebP)"),
        (b"OggS", "Ogg audio"), (b"ID3", "MP3 audio")]
RUN = re.compile(rb"[\x20-\x7e\r\n\t]{20,}")


def wordlike(run):
    s = run.decode("latin-1")
    letters = sum(c.isalpha() for c in s)
    spaces = s.count(" ")
    vowels = sum(c in "aeiouAEIOU" for c in s)
    if letters / len(s) < 0.6 or spaces == 0:
        return False
    return 0.15 <= vowels / max(letters, 1) <= 0.65


def streams(arr):
    """Yield (label, bit array) for many layouts."""
    h, w, c = arr.shape
    names = "RGBA"[:c] if c > 1 else "L"
    sets = {names[i]: [i] for i in range(c)}
    if c >= 3:
        sets["RGB"] = [0, 1, 2]
        sets["BGR"] = [2, 1, 0]
    if c == 4:
        sets["RGBA"] = [0, 1, 2, 3]
        sets["ARGB"] = [3, 0, 1, 2]
    scans = {"rows": arr.reshape(-1, c),
             "columns": arr.transpose(1, 0, 2).reshape(-1, c)}
    for sname, px in scans.items():
        px = px[:LIMIT * 8 // 1]
        for cname, idx in sets.items():
            sub = px[:, idx]
            for plane in (0, 1, 2, 3):
                bits = ((sub >> plane) & 1).reshape(-1)
                yield f"plane {plane}, {cname}, {sname}", bits
            for a, b in ((1, 0), (0, 1)):           # two lowest bits together
                pair = np.stack([(sub >> a) & 1, (sub >> b) & 1], axis=-1)
                yield f"2 low bits ({a},{b}), {cname}, {sname}", pair.reshape(-1)


def pack(bits, order):
    n = len(bits) // 8 * 8
    return np.packbits(bits[:n].astype(np.uint8), bitorder=order).tobytes()[:LIMIT]


def main(path):
    img = Image.open(path)
    if img.mode not in ("RGB", "RGBA", "L"):
        img = img.convert("RGBA" if "A" in img.getbands() else "RGB")
    arr = np.array(img)
    if arr.ndim == 2:
        arr = arr[:, :, None]
    print(f"{path}\nmode {img.mode}, size {img.size}")
    if arr.shape[2] == 4:
        a = arr[:, :, 3]
        print(f"alpha channel: min {a.min()}, max {a.max()}, "
              f"{len(np.unique(a))} different values")
    found = []
    for label, bits in streams(arr):
        for order in ("big", "little"):
            data = pack(bits, order)
            full = f"{label}, {order}-bit-first"
            for sig, name in SIGS:
                if data[:len(sig)] == sig:
                    found.append((3, full, f"starts with a {name} signature"))
            for m in RUN.finditer(data):
                if wordlike(m.group()):
                    txt = m.group().decode("latin-1").strip()
                    found.append((2, full, f"at byte {m.start()}: {txt[:200]}"))
                    break
    seen, shown = set(), 0
    print()
    for _, label, what in sorted(found, key=lambda x: -x[0]):
        if what in seen:
            continue
        seen.add(what)
        print(f"[{label}]\n   {what}")
        shown += 1
        if shown >= 12:
            break
    if not shown:
        print("Nothing found in any of the layouts tried.")
        print("Likely causes: encrypted/password-protected, a custom method,")
        print("or the file has no hidden message.")


if __name__ == "__main__":
    main(sys.argv[1])