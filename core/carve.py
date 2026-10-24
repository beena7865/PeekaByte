"""Brute-force search for REAL readable text hidden in a file (zsteg style).
Tries many bit planes / channel orders / scan orders, plus metadata,
appended data and ZIP members. No password-protected data can be read."""
import io, re, wave, zipfile
import numpy as np
from PIL import Image

MIN_LEN = 6          # shortest text we accept
START_WINDOW = 32    # hidden text normally starts at the very beginning
SCAN_BYTES = 512
PIXELS = SCAN_BYTES * 8
RUN = re.compile(rb"[\x20-\x7e\r\n\t]{%d,}" % MIN_LEN)

TOKEN = re.compile(r"^[\W\d_]*[A-Za-z]?[a-z]*[\W\d_]*$")
ACRO = re.compile(r"^[A-Z]{2,6}[\W\d]*$")


def _clean(run, at_start=False):
    s = run.decode("latin-1")
    need = 6 if at_start else 10
    if len(s) < need:
        return False
    letters = sum(c.isalpha() for c in s)
    ok = sum(c.isalnum() or c in " .,!?'-_:;@/()" for c in s)
    if ok / len(s) < 0.9 or letters / len(s) < 0.6:
        return False
    vowels = sum(c in "aeiouAEIOU" for c in s)
    if letters and not (0.15 <= vowels / letters <= 0.65):
        return False
    toks = s.split()
    if not toks:
        return False
    good = sum(1 for t in toks if TOKEN.match(t) or ACRO.match(t))
    need_share = 1.0 if len(toks) == 1 else 0.6
    return good / len(toks) >= need_share


def find_text(data, window=None):
    """Return the first believable readable run in data (or None)."""
    for m in RUN.finditer(data):
        if window is not None and m.start() > window:
            return None
        run = m.group()
        if _clean(run, m.start() == 0):
            return run.decode("latin-1").strip()
    return None

def _pack(bits, order):
    n = len(bits) // 8 * 8
    return np.packbits(bits[:n], bitorder=order).tobytes()

def _bit_hits(bits, label, out, seen):
    for order in ("big", "little"):
        for inv in (False, True):
            b = (1 - bits) if inv else bits
            txt = find_text(_pack(b, order), START_WINDOW)
            if txt and txt not in seen:
                seen.add(txt)
                out.append({"where": f"{label}, {order}-bit-first"
                            + (", inverted" if inv else ""), "text": txt})

def carve_image(path):
    out, seen = [], set()
    img = Image.open(path)
    if img.mode not in ("RGB", "RGBA", "L"):
        img = img.convert("RGBA" if "A" in img.getbands() else "RGB")
    a = np.array(img)
    if a.ndim == 2:
        a = a[:, :, None]
    names = "RGBA"[:a.shape[2]] if a.shape[2] > 1 else "L"
    combos = [[i] for i in range(a.shape[2])]
    if a.shape[2] >= 3:
        combos += [[0, 1, 2], [2, 1, 0]]
    if a.shape[2] == 4:
        combos += [[0, 1, 2, 3], [3, 0, 1, 2]]
    scans = {"rows": a.reshape(-1, a.shape[2])[:PIXELS],
             "columns": a.transpose(1, 0, 2).reshape(-1, a.shape[2])[:PIXELS]}
    for sname, px in scans.items():
        for combo in combos:
            for plane in (0, 1, 2):
                sub = (px[:, combo] >> plane) & 1
                lab = f"bit plane {plane}, channels {''.join(names[i] for i in combo)}, {sname}"
                _bit_hits(sub.reshape(-1).astype(np.uint8), lab, out, seen)
    return out

def carve_wav(path):
    out, seen = [], set()
    with wave.open(path, "rb") as w:
        if w.getsampwidth() != 2:
            return out
        raw = w.readframes(min(w.getnframes(), PIXELS * w.getnchannels()))
    s = np.frombuffer(raw, dtype="<i2").astype(np.int64) & 0xFFFF
    for plane in (0, 1):
        _bit_hits(((s >> plane) & 1).astype(np.uint8)[:PIXELS],
                  f"audio sample bit {plane}", out, seen)
    return out

def tail_after_end(data):
    """Bytes stored after the real end of the file."""
    for end in (b"IEND\xaeB`\x82", b"\xff\xd9"):
        i = data.rfind(end)
        if i != -1 and (end != b"\xff\xd9" or data.startswith(b"\xff\xd8")):
            return data[i + len(end):]
    return b""

def carve_container(data):
    out = []
    # JPEG comments
    if data.startswith(b"\xff\xd8"):
        for m in re.finditer(rb"\xff\xfe(..)", data[:200000], re.S):
            n = int.from_bytes(m.group(1), "big")
            t = find_text(data[m.end():m.end() + n - 2])
            if t:
                out.append({"where": "JPEG comment", "text": t})
    # PNG text chunks
    if data.startswith(b"\x89PNG"):
        for m in re.finditer(rb"(tEXt|iTXt)", data):
            t = find_text(data[m.end():m.end() + 2000])
            if t:
                out.append({"where": "PNG text chunk", "text": t})
    tail = tail_after_end(data)
    if tail:
        if tail[:2] == b"PK":
            try:
                z = zipfile.ZipFile(io.BytesIO(tail))
                for info in z.infolist():
                    if info.flag_bits & 1:
                        out.append({"where": f"zip member {info.filename}",
                                    "text": "(locked with a password)"})
                        continue
                    t = find_text(z.read(info)[:4000])
                    out.append({"where": f"zip member {info.filename}",
                                "text": t or "(not readable text)"})
            except Exception:
                pass
        t = find_text(tail[:4000])
        if t:
            out.append({"where": "data appended after the file end", "text": t})
    return out

def carve(path):
    """Main entry. Returns [{'where':..., 'text':...}, ...]."""
    data = open(path, "rb").read()
    out = carve_container(data)
    try:
        if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
            out += carve_wav(path)
        elif not data.startswith(b"\xff\xd8"):   # JPEG pixels are lossy: use dct.py
            out += carve_image(path)
    except Exception:
        pass
    return out