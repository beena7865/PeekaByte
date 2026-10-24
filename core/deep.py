"""Deep scan for the app: finds hidden text/files in many bit layouts and
builds 'reveal' pictures (low bits stretched) that can show a hidden image."""
import io
import re

import numpy as np
from PIL import Image

LIMIT = 100_000
MAX_PIXELS = 300_000
OK_FORMATS = {"PNG", "BMP", "TIFF", "GIF", "WEBP"}
SIGS = [(b"PK\x03\x04", "a ZIP archive"), (b"\x89PNG", "a PNG image"),
        (b"%PDF-", "a PDF document"), (b"\xff\xd8\xff", "a JPEG image"),
        (b"GIF8", "a GIF image"), (b"Rar!", "a RAR archive"),
        (b"7z\xbc\xaf", "a 7-Zip archive"), (b"\x1f\x8b\x08", "gzip data"),
        (b"OggS", "Ogg audio"), (b"ID3", "MP3 audio")]
RUN = re.compile(rb"[\x20-\x7e\r\n\t]{20,}")


def _wordlike(run):
    s = run.decode("latin-1")
    letters = sum(c.isalpha() for c in s)
    if letters / len(s) < 0.6 or s.count(" ") == 0:
        return False
    vowels = sum(c in "aeiouAEIOU" for c in s)
    return 0.15 <= vowels / max(letters, 1) <= 0.65


def _streams(arr):
    h, w, c = arr.shape
    names = "RGBA"[:c] if c > 1 else "L"
    sets = {names[i]: [i] for i in range(c)}
    if c >= 3:
        sets["RGB"] = [0, 1, 2]
        sets["BGR"] = [2, 1, 0]
    if c == 4:
        sets["RGBA"] = [0, 1, 2, 3]
        sets["ARGB"] = [3, 0, 1, 2]
    ncols = max(1, MAX_PIXELS // h + 1)
    scans = {"rows": arr.reshape(-1, c)[:MAX_PIXELS],
             "columns": arr.transpose(1, 0, 2)[:ncols].reshape(-1, c)[:MAX_PIXELS]}
    for sname, px in scans.items():
        for cname, idx in sets.items():
            sub = px[:, idx]
            for plane in (0, 1):
                yield f"bit {plane}, channels {cname}, {sname}", ((sub >> plane) & 1).reshape(-1)
            for a, b in ((1, 0), (0, 1)):
                pair = np.stack([(sub >> a) & 1, (sub >> b) & 1], axis=-1)
                yield f"2 low bits ({a},{b}), channels {cname}, {sname}", pair.reshape(-1)


def _pack(bits, order):
    n = len(bits) // 8 * 8
    return np.packbits(bits[:n].astype(np.uint8), bitorder=order).tobytes()[:LIMIT]


def _png_bytes(arr):
    buf = io.BytesIO()
    Image.fromarray(arr.astype(np.uint8)).save(buf, format="PNG", compress_level=3)
    return buf.getvalue()


def deep_scan(data):
    out = {"leads": [], "images": [], "note": ""}
    try:
        img = Image.open(io.BytesIO(data))
        fmt = img.format
        img.load()
    except Exception:
        out["note"] = "This file is not an image, so the pixel deep scan does not apply."
        return out
    if fmt not in OK_FORMATS:
        out["note"] = (f"{fmt} pixels are lossy, so a pixel-level deep scan would give "
                       "meaningless answers. Use the checks above.")
        return out
    if img.mode not in ("RGB", "RGBA", "L"):
        img = img.convert("RGBA" if "A" in img.getbands() else "RGB")
    arr = np.array(img)
    if arr.ndim == 2:
        arr = arr[:, :, None]

    # 1) hidden text / files in many layouts
    found, seen = [], set()
    for label, bits in _streams(arr):
        for order in ("big", "little"):
            d = _pack(bits, order)
            where = f"{label}, {order}-bit-first"
            for sig, name in SIGS:
                if d[:len(sig)] == sig:
                    t = f"The data starts like {name}: a file may be hidden here."
                    if t not in seen:
                        seen.add(t); found.append((3, where, t))
            for m in RUN.finditer(d):
                if _wordlike(m.group()):
                    t = m.group().decode("latin-1").strip()[:300]
                    if t not in seen:
                        seen.add(t); found.append((2, where, t))
                    break
    found.sort(key=lambda x: -x[0])
    out["leads"] = [(w, t) for _, w, t in found[:6]]

    # 2) reveal pictures: low bits stretched to full brightness
    rgb = np.array(Image.fromarray(arr[:, :, :3] if arr.shape[2] >= 3 else
                                   np.repeat(arr, 3, axis=2)).convert("RGB")).astype(np.int32)
    step = max(1, int(max(rgb.shape[:2]) // 1600))      # keep reveal pictures small
    rgb = rgb[::step, ::step]
    low4 = (rgb & 15) * 17
    gray4 = low4.mean(axis=2)
    out["images"] = [
        ("Last 4 bits of every colour, stretched (grey)", _png_bytes(gray4)),
        ("Last 4 bits of every colour, stretched (colour)", _png_bytes(low4)),
        ("Last 2 bits, stretched", _png_bytes((rgb & 3) * 85)),
        ("Last bit only (black and white)", _png_bytes((rgb[:, :, 0] & 1) * 255)),
    ]
    return out