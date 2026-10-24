import struct
import zlib

from core.file_checks import detect_type
from core.jpg_checks import run_jpg_checks


# ---------------------------------------------------------------- PNG
PNG_STANDARD = {
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP",
    b"sBIT", b"sRGB", b"bKGD", b"hIST", b"pHYs", b"sPLT", b"eXIf", b"tIME",
    b"tEXt", b"zTXt", b"iTXt", b"acTL", b"fcTL", b"fdAT", b"cICP",
}


def check_png(data):
    findings, layout = [], []
    pos = 8
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        crc_stored = data[pos + 8 + length:pos + 12 + length]
        name = ctype.decode("latin-1")
        if not layout or layout[-1] != name:       # show repeated IDAT once
            layout.append(name)

        if len(body) < length or len(crc_stored) < 4:
            findings.append(("warning", f"Chunk {name} runs past the end of the file"))
            break

        crc = struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF)
        if crc != crc_stored:
            findings.append(("warning", f"Chunk {name} at offset {pos} has a wrong "
                                        f"checksum (it may have been edited)"))
        if ctype not in PNG_STANDARD:
            findings.append(("warning", f"Unknown chunk {name} at offset {pos} "
                                        f"({length} bytes)"))
        if ctype in (b"tEXt", b"zTXt"):
            keyword, _, rest = body.partition(b"\x00")
            if ctype == b"zTXt":
                try:
                    rest = zlib.decompress(rest[1:])
                except zlib.error:
                    rest = b"(cannot decompress)"
            level = "suspicious" if length > 1000 else "warning"
            findings.append((level, f"{name} chunk '{keyword.decode('latin-1')}' "
                                    f"({length} bytes): {rest[:60]!r}"))
        if ctype == b"iTXt":
            keyword = body.partition(b"\x00")[0].decode("latin-1")
            findings.append(("warning", f"iTXt chunk '{keyword}' ({length} bytes)"))

        pos += 12 + length
        if ctype == b"IEND":
            break
    return layout, findings


# ---------------------------------------------------------------- BMP
def check_bmp(data):
    layout = ["file header", "info header", "pixel data"]
    findings = []
    if len(data) < 54:
        return layout, [("warning", "BMP header is too short")]

    declared = struct.unpack("<I", data[2:6])[0]
    res1, res2 = struct.unpack("<HH", data[6:10])
    offset = struct.unpack("<I", data[10:14])[0]
    dib = struct.unpack("<I", data[14:18])[0]
    width, height = struct.unpack("<ii", data[18:26])
    bpp = struct.unpack("<H", data[28:30])[0]
    comp = struct.unpack("<I", data[30:34])[0]

    if res1 or res2:
        findings.append(("warning", f"Reserved header fields are not zero "
                                    f"({res1}, {res2})"))
    if declared and len(data) > declared:
        extra = data[declared:]
        findings.append(("suspicious", f"{len(extra)} bytes after the end of the "
                                       f"BMP (offset {declared}): {extra[:40]!r}"))
    if declared and len(data) < declared:
        findings.append(("warning", "File is shorter than its header says"))

    if bpp in (24, 32) and comp == 0 and dib >= 40:
        expected = 14 + dib
        if offset > expected:
            gap = data[expected:offset]
            level = "suspicious" if any(gap) else "warning"
            findings.append((level, f"{len(gap)} unused bytes between the header "
                                    f"and the pixel data: {gap[:20]!r}"))
    if bpp == 24 and comp == 0 and width > 0:
        row = ((width * 3 + 3) // 4) * 4
        pad = row - width * 3
        if pad:
            rows = abs(height)
            bad = 0
            for r in range(rows):
                start = offset + r * row + width * 3
                if any(data[start:start + pad]):
                    bad += 1
            if bad:
                findings.append(("suspicious", f"Row padding bytes are not zero in "
                                               f"{bad} of {rows} rows"))
    return layout, findings


# ---------------------------------------------------------------- GIF
GIF_KNOWN_APPS = [b"NETSCAPE2.0", b"ANIMEXTS1.0", b"XMP DataXMP", b"ICCRGBG1012"]


def check_gif(data):
    findings, layout = [], ["header"]
    if len(data) < 13:
        return layout, [("warning", "GIF header is too short")]
    flags = data[10]
    pos = 13
    if flags & 0x80:
        pos += 3 * 2 ** ((flags & 7) + 1)          # global colour table
    end = None

    while pos < len(data):
        b = data[pos]
        if b == 0x3B:                               # trailer
            end = pos + 1
            layout.append("trailer")
            break
        if b == 0x21:                               # extension block
            label = data[pos + 1] if pos + 1 < len(data) else 0
            offset = pos
            pos += 2
            body = bytearray()
            while pos < len(data) and data[pos] != 0:
                n = data[pos]
                body += data[pos + 1:pos + 1 + n]
                pos += 1 + n
            pos += 1
            if label == 0xFE:
                level = "suspicious" if len(body) > 200 else "warning"
                findings.append((level, f"Comment at offset {offset} "
                                        f"({len(body)} bytes): {bytes(body[:60])!r}"))
                layout.append("comment")
            elif label == 0xFF:
                ident = bytes(body[:11])
                layout.append("application")
                if ident not in GIF_KNOWN_APPS:
                    findings.append(("warning", f"Unknown application block at "
                                                f"offset {offset}: {ident!r}"))
            elif label == 0x01:
                findings.append(("warning", f"Plain-text block at offset {offset}"))
                layout.append("plain text")
            else:
                layout.append("extension")
        elif b == 0x2C:                             # image
            if pos + 10 > len(data):
                break
            f = data[pos + 9]
            pos += 10
            if f & 0x80:
                pos += 3 * 2 ** ((f & 7) + 1)       # local colour table
            pos += 1                                # LZW code size
            while pos < len(data) and data[pos] != 0:
                pos += 1 + data[pos]
            pos += 1
            layout.append("image")
        else:
            findings.append(("warning", f"Unexpected byte 0x{b:02X} at offset {pos}"))
            break

    if end is None:
        findings.append(("warning", "No GIF trailer found (file cut or damaged)"))
    elif end < len(data):
        extra = data[end:]
        findings.append(("suspicious", f"{len(extra)} bytes after the GIF trailer "
                                       f"(offset {end}): {extra[:40]!r}"))
    return layout, findings


# ---------------------------------------------------------------- WebP
WEBP_KNOWN = {b"VP8 ", b"VP8L", b"VP8X", b"ALPH", b"ANIM", b"ANMF",
              b"ICCP", b"EXIF", b"XMP "}


def check_webp(data):
    findings, layout = [], []
    declared = struct.unpack("<I", data[4:8])[0] + 8
    pos = 12
    while pos + 8 <= min(declared, len(data)):
        fourcc = data[pos:pos + 4]
        size = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        layout.append(fourcc.decode("latin-1"))
        if fourcc not in WEBP_KNOWN:
            findings.append(("warning", f"Unknown chunk {fourcc!r} at offset {pos} "
                                        f"({size} bytes)"))
        if fourcc in (b"EXIF", b"XMP "):
            findings.append(("warning", f"{fourcc.decode()} metadata chunk "
                                        f"({size} bytes)"))
        pos += 8 + size + (size & 1)
    if len(data) > declared:
        extra = data[declared:]
        findings.append(("suspicious", f"{len(extra)} bytes after the end of the "
                                       f"WebP (offset {declared}): {extra[:40]!r}"))
    if len(data) < declared:
        findings.append(("warning", "File is shorter than its header says"))
    return layout, findings


# ---------------------------------------------------------------- WAV
WAV_KNOWN = {b"fmt ", b"data", b"fact", b"LIST", b"cue ", b"smpl", b"bext",
             b"PEAK", b"JUNK", b"inst", b"plst", b"iXML", b"id3 ", b"ID3 "}


def check_wav(data):
    findings, layout = [], []
    declared = struct.unpack("<I", data[4:8])[0] + 8
    pos = 12
    while pos + 8 <= min(declared, len(data)):
        cid = data[pos:pos + 4]
        size = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        layout.append(cid.decode("latin-1"))
        if cid not in WAV_KNOWN:
            findings.append(("warning", f"Unknown chunk {cid!r} at offset {pos} "
                                        f"({size} bytes)"))
        if cid == b"LIST":
            body = data[pos + 8:pos + 8 + min(size, 80)]
            findings.append(("warning", f"LIST chunk ({size} bytes): {body!r}"))
        pos += 8 + size + (size & 1)
    if len(data) > declared:
        extra = data[declared:]
        findings.append(("suspicious", f"{len(extra)} bytes after the end of the "
                                       f"WAV (offset {declared}): {extra[:40]!r}"))
    return layout, findings


# ---------------------------------------------------------------- router
def check_format(path):
    """Look at what the file really is and run the matching checker."""
    with open(path, "rb") as f:
        data = f.read()
    real_type = detect_type(data)

    if real_type == "jpg":
        r = run_jpg_checks(path)
        return {"type": "jpg", "layout": r["layout"],
                "findings": r["findings"], "suspicious": r["suspicious"]}

    checkers = {"png": check_png, "bmp": check_bmp, "gif": check_gif,
                "webp": check_webp, "wav": check_wav}
    if real_type in checkers:
        layout, findings = checkers[real_type](data)
    elif real_type in ("tiff", "pdf", "heic"):
        from core.extra_formats import check_extra
        _, hits, _notes = check_extra(data)
        layout = []
        findings = [("suspicious", f"{h['where']}: {h['text']}") for h in hits]
    else:
        layout, findings = [], [("warning", "Unsupported or unknown file type")]

    return {"type": real_type, "layout": layout, "findings": findings,
            "suspicious": any(level == "suspicious" for level, _ in findings)}