"""PNG structure check and repair (the pcrt/pngcheck equivalent).

Reads every chunk in a PNG, verifies its CRC and the key header fields, and
can rebuild a PNG whose chunks are fine but whose header got corrupted or
whose signature bytes were tampered with -- a common way people try to break
a stego tool that reads PNGs strictly."""
import struct
import zlib

SIG = b"\x89PNG\r\n\x1a\n"
CRITICAL = {b"IHDR", b"PLTE", b"IDAT", b"IEND"}


def _chunks(body):
    i, out = 0, []
    while i + 8 <= len(body):
        length = struct.unpack(">I", body[i:i + 4])[0]
        ctype = body[i + 4:i + 8]
        data_start = i + 8
        data_end = data_start + length
        if data_end + 4 > len(body):
            out.append({"type": ctype, "ok": False, "reason": "truncated chunk", "data": None})
            break
        data = body[data_start:data_end]
        crc_stored = struct.unpack(">I", body[data_end:data_end + 4])[0]
        crc_calc = zlib.crc32(ctype + data) & 0xffffffff
        out.append({"type": ctype, "ok": crc_stored == crc_calc, "data": data,
                   "reason": None if crc_stored == crc_calc else "bad CRC"})
        i = data_end + 4
        if ctype == b"IEND":
            break
    return out


def check_png(data):
    """Return {"ok": bool, "signature_ok": bool, "chunks": [...], "problems": [str]}."""
    out = {"ok": True, "signature_ok": data[:8] == SIG, "chunks": [], "problems": []}
    if not out["signature_ok"]:
        out["ok"] = False
        out["problems"].append("The 8-byte PNG signature is wrong or missing.")
    chunks = _chunks(data[8:])
    out["chunks"] = [(c["type"].decode("latin-1", "replace"), c["ok"], c["reason"]) for c in chunks]
    types = [c["type"] for c in chunks]
    if b"IHDR" not in types:
        out["problems"].append("No IHDR chunk: the file has no valid image header.")
    elif types[0] != b"IHDR":
        out["problems"].append("IHDR is not the first chunk (it must be).")
    if b"IDAT" not in types:
        out["problems"].append("No IDAT chunk: there is no pixel data.")
    if b"IEND" not in types:
        out["problems"].append("No IEND chunk: the file is truncated.")
    for ctype, ok, reason in out["chunks"]:
        if not ok and ctype.encode("latin-1") in CRITICAL:
            out["problems"].append(f"{ctype} chunk has a {reason}.")
    out["ok"] = out["signature_ok"] and not out["problems"]
    return out


def repair_png(data):
    """Best-effort repair: fix the signature and recompute CRCs for chunks
    whose length/type/data look intact. Returns (fixed_bytes, notes)."""
    notes = []
    body = data[8:]
    if data[:8] != SIG:
        notes.append("Rebuilt the 8-byte PNG signature.")
    out = bytearray(SIG)
    chunks = _chunks(body)
    for c in chunks:
        if c["data"] is None:
            notes.append(f"Dropped a truncated {c['type']!r} chunk at the end.")
            break
        length = struct.pack(">I", len(c["data"]))
        crc = struct.pack(">I", zlib.crc32(c["type"] + c["data"]) & 0xffffffff)
        if not c["ok"]:
            notes.append(f"Recomputed the CRC for {c['type'].decode('latin-1')}.")
        out += length + c["type"] + c["data"] + crc
    if not notes:
        notes.append("No damage found; nothing needed fixing.")
    return bytes(out), notes