"""JPEG DCT-coefficient tools: decoder, encoder, JSteg-style hiding and a
histogram detector. Works on baseline (sequential Huffman) JPEG files."""
import re
from math import ceil, erfc, sqrt

import numpy as np

from core.lsb import MAGIC, bits_to_bytes, bytes_to_bits

MAX_BLOCKS = 200000       # about 8 megapixels; keeps pure-Python decoding to a few seconds
_SCAN_END = re.compile(rb"\xff[^\x00\xd0-\xd7]")
_RESTART = re.compile(rb"\xff[\xd0-\xd7]")

# Standard Huffman tables (JPEG spec, Annex K): (counts per code length, symbols)
STD_TABLES = {
    ("dc", 0): ([0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0],
                bytes.fromhex("000102030405060708090a0b")),
    ("ac", 0): ([0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125],
                bytes.fromhex(
                    "01020300041105122131410613516107227114328191a1082342b1c11552d1f0"
                    "2433627282090a161718191a25262728292a3435363738393a43444546474849"
                    "4a535455565758595a636465666768696a737475767778797a83848586878889"
                    "8a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5"
                    "c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8"
                    "f9fa")),
    ("dc", 1): ([0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
                bytes.fromhex("000102030405060708090a0b")),
    ("ac", 1): ([0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 119],
                bytes.fromhex(
                    "000102031104052131061241510761711322328108144291a1b1c109233352f0"
                    "156272d10a162434e125f11718191a262728292a35363738393a434445464748"
                    "494a535455565758595a636465666768696a737475767778797a828384858687"
                    "88898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3"
                    "c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8"
                    "f9fa")),
}


class JpegError(Exception):
    """Raised when a file cannot be handled (progressive, too large, broken)."""


# ------------------------------------------------------------------ parsing
def _parse(data):
    if data[:2] != b"\xff\xd8":
        raise JpegError("not a JPEG file")
    pos, kept = 2, []                    # kept: raw segments before SOS
    info = {"restart": 0, "huff": {}, "qt": {}, "frame": None, "scan": None}
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            raise JpegError("broken marker structure")
        marker = data[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker == 0xD8 or marker == 0x01 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xD9:
            break
        length = int.from_bytes(data[pos + 2:pos + 4], "big")
        raw = data[pos:pos + 2 + length]
        payload = data[pos + 4:pos + 2 + length]
        if marker in (0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            raise JpegError("progressive or arithmetic JPEG is not supported")
        if marker == 0xC4:               # DHT
            i = 0
            while i < len(payload):
                tc_th, counts = payload[i], list(payload[i + 1:i + 17])
                n = sum(counts)
                info["huff"][(tc_th >> 4, tc_th & 15)] = (counts, payload[i + 17:i + 17 + n])
                i += 17 + n
        elif marker == 0xDB:             # DQT
            i = 0
            while i < len(payload):
                pq, tq = payload[i] >> 4, payload[i] & 15
                size = 128 if pq else 64
                step = 2 if pq else 1
                vals = [int.from_bytes(payload[i + 1 + j * step:i + 1 + (j + 1) * step], "big")
                        for j in range(64)]
                info["qt"][tq] = vals
                i += 1 + size
        elif marker == 0xDD:             # DRI
            info["restart"] = int.from_bytes(payload[:2], "big")
        elif marker in (0xC0, 0xC1):     # SOF
            comps = []
            for j in range(payload[5]):
                cid, hv, tq = payload[6 + 3 * j:9 + 3 * j]
                comps.append({"id": cid, "h": hv >> 4, "v": hv & 15, "tq": tq})
            info["frame"] = {"marker": marker, "precision": payload[0],
                             "height": int.from_bytes(payload[1:3], "big"),
                             "width": int.from_bytes(payload[3:5], "big"), "comps": comps}
        elif marker == 0xDA:             # SOS: entropy data follows
            ns = payload[0]
            info["scan"] = [(payload[1 + 2 * j], payload[2 + 2 * j] >> 4, payload[2 + 2 * j] & 15)
                            for j in range(ns)]
            start = pos + 2 + length
            m = _SCAN_END.search(data, start)
            info["entropy"] = data[start:(m.start() if m else len(data))]
            info["kept"] = kept
            return info
        if marker not in (0xC4, 0xDD):   # DHT and DRI are rewritten when encoding
            kept.append(raw)
        pos += 2 + length
    raise JpegError("no image data found")


def _build_lookup(counts, symbols):
    """16-bit lookup table: next 16 bits -> (code length, symbol)."""
    table = [(0, 0)] * 65536
    code, k = 0, 0
    for length in range(1, 17):
        for _ in range(counts[length - 1]):
            start = code << (16 - length)
            span = 1 << (16 - length)
            table[start:start + span] = [(length, symbols[k])] * span
            code += 1
            k += 1
        code <<= 1
    return table


def _check_supported(info):
    frame = info["frame"]
    if frame is None or info["scan"] is None:
        raise JpegError("missing frame or scan header")
    if frame["precision"] != 8:
        raise JpegError("only 8-bit JPEG is supported")
    if len(info["scan"]) != len(frame["comps"]):
        raise JpegError("multi-scan JPEG is not supported")
    if len(frame["comps"]) not in (1, 3):
        raise JpegError("only grayscale and colour JPEG are supported")
    return frame


# ------------------------------------------------------------------ decoder
def decode(data):
    """Return the quantised DCT coefficients of a baseline JPEG.

    Result: dict with 'info', 'comps', 'coefs' (one array per component, shape
    (block rows, block columns, 64) in zigzag order) and the MCU layout."""
    info = _parse(data)
    frame = _check_supported(info)
    comps = frame["comps"]
    hmax = max(c["h"] for c in comps)
    vmax = max(c["v"] for c in comps)
    mcux = ceil(frame["width"] / (8 * hmax))
    mcuy = ceil(frame["height"] / (8 * vmax))
    total = mcux * mcuy * sum(c["h"] * c["v"] for c in comps)
    if total > MAX_BLOCKS:
        raise JpegError(f"image too large for DCT analysis ({total} blocks, limit {MAX_BLOCKS})")

    coefs = [np.zeros((mcuy * c["v"], mcux * c["h"], 64), dtype=np.int16) for c in comps]
    lookups = []
    for comp, (cid, td, ta) in zip(comps, info["scan"]):
        try:
            dc = _build_lookup(*info["huff"][(0, td)])
            ac = _build_lookup(*info["huff"][(1, ta)])
        except KeyError:
            raise JpegError("missing Huffman table")
        lookups.append((dc, ac))

    segments = _RESTART.split(info["entropy"])
    interval = info["restart"] or (mcux * mcuy)
    buf, pos, preds = b"", 0, [0] * len(comps)
    try:
        for m in range(mcux * mcuy):
            if m % interval == 0:
                index = m // interval
                if index >= len(segments):
                    raise JpegError("scan data ended early")
                buf = segments[index].replace(b"\xff\x00", b"\xff") + b"\x00\x00\x00\x00"
                pos, preds = 0, [0] * len(comps)
            my, mx = divmod(m, mcux)
            for ci, comp in enumerate(comps):
                dc_tbl, ac_tbl = lookups[ci]
                arr = coefs[ci]
                for v in range(comp["v"]):
                    for h in range(comp["h"]):
                        by, bx = my * comp["v"] + v, mx * comp["h"] + h
                        block = arr[by, bx]
                        # --- DC
                        i = pos >> 3
                        peek = (((buf[i] << 16) | (buf[i + 1] << 8) | buf[i + 2])
                                >> (8 - (pos & 7))) & 0xFFFF
                        length, size = dc_tbl[peek]
                        if length == 0:
                            raise JpegError("bad Huffman code")
                        pos += length
                        if size:
                            i = pos >> 3
                            bits = (((buf[i] << 16) | (buf[i + 1] << 8) | buf[i + 2])
                                    >> (24 - (pos & 7) - size)) & ((1 << size) - 1)
                            pos += size
                            if bits < (1 << (size - 1)):
                                bits -= (1 << size) - 1
                            preds[ci] += bits
                        block[0] = preds[ci]
                        # --- AC
                        k = 1
                        while k < 64:
                            i = pos >> 3
                            peek = (((buf[i] << 16) | (buf[i + 1] << 8) | buf[i + 2])
                                    >> (8 - (pos & 7))) & 0xFFFF
                            length, rs = ac_tbl[peek]
                            if length == 0:
                                raise JpegError("bad Huffman code")
                            pos += length
                            run, size = rs >> 4, rs & 15
                            if size == 0:
                                if run == 15:
                                    k += 16
                                    continue
                                break
                            k += run
                            if k > 63:
                                raise JpegError("coefficient index out of range")
                            i = pos >> 3
                            bits = (((buf[i] << 16) | (buf[i + 1] << 8) | buf[i + 2])
                                    >> (24 - (pos & 7) - size)) & ((1 << size) - 1)
                            pos += size
                            if bits < (1 << (size - 1)):
                                bits -= (1 << size) - 1
                            block[k] = bits
                            k += 1
    except IndexError:
        raise JpegError("scan data is truncated")
    return {"info": info, "comps": comps, "coefs": coefs, "mcux": mcux, "mcuy": mcuy}


# ------------------------------------------------------------------ encoder
def _encoder_table(counts, symbols):
    codes, code, k = {}, 0, 0
    for length in range(1, 17):
        for _ in range(counts[length - 1]):
            codes[symbols[k]] = (code, length)
            code += 1
            k += 1
        code <<= 1
    return codes


def _dht_segment(kind, ident):
    counts, symbols = STD_TABLES[(kind, ident)]
    payload = bytes([(0 if kind == "dc" else 16) | ident]) + bytes(counts) + symbols
    return b"\xff\xc4" + (len(payload) + 2).to_bytes(2, "big") + payload


def encode(decoded):
    """Write the (possibly modified) coefficients back as a JPEG file."""
    comps, coefs = decoded["comps"], decoded["coefs"]
    mcux, mcuy = decoded["mcux"], decoded["mcuy"]
    enc = {key: _encoder_table(*value) for key, value in STD_TABLES.items()}

    out, acc, nbits = bytearray(), 0, 0

    def put(code, length):
        nonlocal acc, nbits
        acc = (acc << length) | code
        nbits += length
        while nbits >= 8:
            byte = (acc >> (nbits - 8)) & 0xFF
            out.append(byte)
            if byte == 0xFF:
                out.append(0)
            nbits -= 8
        acc &= (1 << nbits) - 1

    def magnitude(value):
        size = abs(value).bit_length()
        return size, (value if value > 0 else value + (1 << size) - 1)

    preds = [0] * len(comps)
    for m in range(mcux * mcuy):
        my, mx = divmod(m, mcux)
        for ci, comp in enumerate(comps):
            table = 0 if ci == 0 else 1
            dc_codes, ac_codes = enc[("dc", table)], enc[("ac", table)]
            for v in range(comp["v"]):
                for h in range(comp["h"]):
                    block = coefs[ci][my * comp["v"] + v, mx * comp["h"] + h].tolist()
                    diff = block[0] - preds[ci]
                    preds[ci] = block[0]
                    size, bits = magnitude(diff)
                    put(*dc_codes[size])
                    if size:
                        put(bits, size)
                    run = 0
                    last = max((k for k in range(1, 64) if block[k]), default=0)
                    for k in range(1, last + 1):
                        value = block[k]
                        if value == 0:
                            run += 1
                            continue
                        while run > 15:
                            put(*ac_codes[0xF0])
                            run -= 16
                        size, bits = magnitude(value)
                        put(*ac_codes[(run << 4) | size])
                        put(bits, size)
                        run = 0
                    if last < 63:
                        put(*ac_codes[0x00])
    if nbits:
        put((1 << (8 - nbits)) - 1, 8 - nbits)

    sos_body = bytes([len(comps)])
    for ci, comp in enumerate(comps):
        table = 0 if ci == 0 else 1
        sos_body += bytes([comp["id"], (table << 4) | table])
    sos_body += bytes([0, 63, 0])
    sos = b"\xff\xda" + (len(sos_body) + 2).to_bytes(2, "big") + sos_body

    return (b"\xff\xd8" + b"".join(decoded["info"]["kept"])
            + _dht_segment("dc", 0) + _dht_segment("ac", 0)
            + _dht_segment("dc", 1) + _dht_segment("ac", 1)
            + sos + bytes(out) + b"\xff\xd9")


# ------------------------------------------------------------------ JSteg-style hiding
def _usable(decoded):
    """All AC coefficients (component by component, row by row) and the
    positions whose value is not 0 or 1 - the only ones JSteg uses."""
    values = np.concatenate([a.reshape(-1, 64)[:, 1:].ravel() for a in decoded["coefs"]])
    positions = np.flatnonzero((values != 0) & (values != 1))
    return values, positions


def _store(decoded, values):
    start = 0
    for a in decoded["coefs"]:
        flat = a.reshape(-1, 64)
        count = flat.shape[0] * 63
        flat[:, 1:] = values[start:start + count].reshape(-1, 63)
        start += count


def capacity_bytes(path):
    with open(path, "rb") as f:
        decoded = decode(f.read())
    _, positions = _usable(decoded)
    return max(0, (len(positions) - 64) // 8)


def embed_jpeg(image_path, text, out_path):
    with open(image_path, "rb") as f:
        decoded = decode(f.read())
    values, positions = _usable(decoded)
    message = text.encode("utf-8")
    bits = np.array(bytes_to_bits(MAGIC + len(message).to_bytes(4, "big") + message),
                    dtype=np.int16)
    if len(bits) > len(positions):
        raise ValueError("Message is too long for this JPEG "
                         f"(room for about {max(0, (len(positions) - 64) // 8)} characters).")
    chosen = positions[:len(bits)]
    values[chosen] = (values[chosen] & ~1) | bits
    _store(decoded, values)
    with open(out_path, "wb") as f:
        f.write(encode(decoded))


def extract_jpeg(path):
    with open(path, "rb") as f:
        decoded = decode(f.read())
    return _extract_from(decoded)


def _extract_from(decoded):
    values, positions = _usable(decoded)
    if len(positions) < 64:
        return None
    header = bits_to_bytes((values[positions[:64]] & 1).tolist())
    if header[:4] != MAGIC:
        return None
    length = int.from_bytes(header[4:8], "big")
    if 64 + length * 8 > len(positions):
        return None
    body = (values[positions[64:64 + length * 8]] & 1).tolist()
    return bits_to_bytes(body).decode("utf-8", errors="replace")


# ------------------------------------------------------------------ detection
MIN_SAMPLE = 4000        # fewer coefficients cannot show the natural imbalance
MIN_QUANT_MEAN = 3.0     # above about JPEG quality 97 clean files look "uniform" too


def _pair_ratio(sample):
    """Do the values 2k and 2k+1 occur in the SAME proportion for every k?

    Natural JPEGs: no - small values are far more common than their odd
    neighbours, which gives a large chi-square.  After JSteg-style hiding the
    last bit of every usable value is overwritten, so the proportion becomes
    the same for all pairs.  Unlike the classic test this does not need the
    hidden bits to be 50/50, so it also works for text.
    Returns chi-square divided by its degrees of freedom: about 1 means
    'perfectly uniform', natural images give 7 to several hundred."""
    clipped = sample[(sample >= -64) & (sample <= 63)] + 64      # 0..127
    counts = np.bincount(clipped, minlength=128).astype(float)
    odd, total = [], []
    for low in range(0, 128, 2):
        if low == 64:                    # the (0, 1) pair is never used by JSteg
            continue
        a, b = counts[low], counts[low + 1]
        if a + b >= 10:
            odd.append(b)
            total.append(a + b)
    if len(odd) < 8:
        return None
    b, n = np.array(odd), np.array(total)
    share = b.sum() / n.sum()            # overall share of odd values
    if share <= 0 or share >= 1:
        return None
    chi = float((((b - n * share) ** 2) / (n * share * (1 - share))).sum())
    return chi / (len(b) - 1)


def dct_check(path):
    """Run every DCT-domain test on a JPEG file."""
    try:
        with open(path, "rb") as f:
            decoded = decode(f.read())
    except JpegError as error:
        return {"available": False, "reason": str(error)}

    values, positions = _usable(decoded)
    usable = values[positions]
    if len(usable) < 200:
        return {"available": False, "reason": "too few coefficients to test"}

    message = _extract_from(decoded)
    data = bits_to_bytes((usable[:3200] & 1).tolist())
    run = best = 0
    for byte in data:
        run = run + 1 if 32 <= byte < 127 else 0
        best = max(best, run)
    looks_text = best >= 10

    # histogram test on growing prefixes: a message at the start of the file
    # only equalises the start
    quality_mean = float(np.mean(decoded["info"]["qt"][decoded["comps"][0]["tq"]]))
    uniformity, why_skipped = None, None
    if quality_mean < MIN_QUANT_MEAN:
        why_skipped = "very high JPEG quality: clean files look uniform too, test not reliable"
    elif len(usable) < MIN_SAMPLE:
        why_skipped = "too few usable coefficients for the histogram test"
    else:
        scores = []
        for fraction in (0.1, 0.2, 0.4, 0.7, 1.0):
            part = usable[:int(len(usable) * fraction)]
            if len(part) >= MIN_SAMPLE:
                value = _pair_ratio(part)
                if value is not None:
                    scores.append(value)
        if scores:
            uniformity = min(scores)
        else:
            why_skipped = "not enough value pairs for the histogram test"

    suspicious_stats = uniformity is not None and uniformity < 5
    return {"available": True, "coefficients": int(values.size),
            "usable": int(len(usable)), "message": message,
            "looks_text": looks_text,
            "uniformity": None if uniformity is None else round(uniformity, 2),
            "histogram_skipped": why_skipped,
            "suspicious": bool(message is not None or looks_text or suspicious_stats)}