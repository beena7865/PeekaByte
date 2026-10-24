"""TIFF, PDF and HEIC/AVIF support: find hidden text and odd structure."""
import re
from core.carve import find_text, tail_after_end


def sniff(data):
    """Return 'tiff', 'pdf', 'heic' or None from the file's first bytes."""
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[4:8] == b"ftyp" and data[8:12] in (
            b"heic", b"heix", b"mif1", b"msf1", b"avif", b"heim", b"hevc"):
        return "heic"
    return None


def check_pdf(data):
    out, notes = [], []
    from core.hide_extra import read_pdf_note
    note = read_pdf_note(data)
    if note is not None:
        out.append({"where": "hidden note after the PDF end", "text": note})
        data = data[:data.rfind(b"STG-PDF-HIDDEN:")]
    eofs = [m.end() for m in re.finditer(rb"%%EOF", data)]
    if eofs:
        tail = data[eofs[-1]:].strip()
        if len(tail) > 16:
            t = find_text(tail[:4000])
            out.append({"where": "data after the PDF end marker",
                        "text": t or "(binary data, %d bytes)" % len(tail)})
    if len(eofs) > 1:
        notes.append(f"PDF has {len(eofs)} saved revisions (older content may still be inside)")
    for m in re.finditer(rb"/(Subject|Keywords|Author|Title|Producer)\s*\(([^)]{8,300})\)", data):
        t = find_text(m.group(2))
        if t:
            out.append({"where": "PDF " + m.group(1).decode(), "text": t})
    for m in re.finditer(rb"%([\x20-\x7e]{12,})", data):          # comment lines
        if not m.group(1).startswith((b"PDF", b"%EOF", b"\xe2")):
            t = find_text(m.group(1))
            if t:
                out.append({"where": "PDF comment line", "text": t})
    if b"/EmbeddedFile" in data:
        notes.append("PDF contains an embedded file")
    if b"/JavaScript" in data or b"/JS" in data:
        notes.append("PDF contains JavaScript")
    return out, notes


def check_heic(data):
    out, notes = [], []
    pos, boxes = 0, []
    while pos + 8 <= len(data):
        size = int.from_bytes(data[pos:pos + 4], "big")
        kind = data[pos + 4:pos + 8]
        if size == 1:
            size = int.from_bytes(data[pos + 8:pos + 16], "big")
        if size == 0:
            size = len(data) - pos
        if size < 8:
            break
        boxes.append((kind, pos, size))
        pos += size
    for kind, p, size in boxes:
        if kind in (b"free", b"skip", b"uuid") and size > 32:
            t = find_text(data[p + 8:p + min(size, 4000)])
            out.append({"where": f"HEIC '{kind.decode()}' box",
                        "text": t or "(binary data, %d bytes)" % size})
    if boxes and pos < len(data):
        t = find_text(data[pos:pos + 4000])
        out.append({"where": "data after the last HEIC box",
                    "text": t or "(binary data, %d bytes)" % (len(data) - pos)})
    t = find_text(data[:4000]) if False else None
    for m in re.finditer(rb"Exif\x00\x00|<x:xmpmeta", data):
        t = find_text(data[m.end():m.end() + 1000])
        if t:
            out.append({"where": "HEIC metadata", "text": t})
    notes.append("HEIC pixels are lossy, so pixel-level hiding is not checked; "
                 "boxes, metadata and appended data were checked")
    return out, notes


def check_tiff(data):
    out, notes = [], []
    # TIFF text tags (ImageDescription, Software, Artist, Copyright, comments)
    try:
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(data))
        for tag, val in getattr(img, "tag_v2", {}).items():
            if isinstance(val, str):
                t = find_text(val.encode("latin-1", "ignore"))
                if t and tag in (270, 305, 315, 33432, 37510, 40092):
                    out.append({"where": f"TIFF tag {tag}", "text": t})
        notes.append(f"TIFF has {getattr(img, 'n_frames', 1)} page(s)")
    except Exception:
        pass
    t = find_text(data[-4000:]) if data else None
    return out, notes


def check_extra(data):
    """Return (kind, hits, notes) for tiff/pdf/heic, else (None, [], [])."""
    kind = sniff(data)
    if kind == "pdf":
        return (kind,) + check_pdf(data)
    if kind == "heic":
        return (kind,) + check_heic(data)
    if kind == "tiff":
        return (kind,) + check_tiff(data)
    return None, [], []