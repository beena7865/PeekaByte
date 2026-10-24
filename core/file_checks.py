import os
import struct

# first bytes of common file types -> short name
MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"BM", "bmp"),
]

# signatures of files that someone might hide inside an image
EMBEDDED = [
    (b"PK\x03\x04", "ZIP archive"),
    (b"%PDF-", "PDF document"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x89PNG\r\n\x1a\n", "second PNG image"),
]

def detect_type(data):
    """Work out the real file type from its first bytes."""
    for sig, name in MAGIC:
        if data.startswith(sig):
            return name
    if data[:4] == b"RIFF":
        if data[8:12] == b"WAVE":
            return "wav"
        if data[8:12] == b"WEBP":
            return "webp"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[4:8] == b"ftyp" and data[8:12] in (
            b"heic", b"heix", b"mif1", b"msf1", b"avif", b"heim", b"hevc"):
        return "heic"
    return "unknown"


def check_extension(path, real_type):
    """Warn if the file extension does not match the real type."""
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    if ext == "jpeg":
        ext = "jpg"
    if ext == "tif":
        ext = "tiff"
    if ext in ("heif", "avif"):
        ext = "heic"
    if real_type == "unknown":
        return f"Unknown file type (extension .{ext})"
    if ext != real_type:
        return f"Extension .{ext} does not match real type: {real_type}"
    return None


def find_trailing_data(data, real_type):
    """Return (offset, length) of bytes after the official end of the image."""
    if real_type == "png":
        pos = 8                                   # skip the PNG header
        while pos + 8 <= len(data):
            length = struct.unpack(">I", data[pos:pos + 4])[0]
            chunk_type = data[pos + 4:pos + 8]
            pos += 12 + length                    # length + type + data + crc
            if chunk_type == b"IEND":
                if pos < len(data):
                    return pos, len(data) - pos
                return None
        return None
    if real_type == "jpg":
        end = data.rfind(b"\xff\xd9")             # JPEG end marker
        if end != -1 and end + 2 < len(data):
            return end + 2, len(data) - end - 2
    return None


def find_embedded_files(data):
    """Look for signatures of other file types inside the file."""
    found = []
    for sig, name in EMBEDDED:
        start = 1                                 # skip offset 0 (the file itself)
        while True:
            i = data.find(sig, start)
            if i == -1:
                break
            found.append((i, name))
            start = i + 1
    return found


def run_file_checks(path):
    with open(path, "rb") as f:
        data = f.read()

    findings = []
    real_type = detect_type(data)

    msg = check_extension(path, real_type)
    if msg:
        findings.append(("warning", msg))

    trailing = find_trailing_data(data, real_type)
    if trailing:
        offset, length = trailing
        preview = data[offset:offset + 40]
        findings.append(("suspicious",
                         f"{length} bytes after the end of the image "
                         f"(offset {offset}): {preview!r}"))

    for offset, name in find_embedded_files(data):
        findings.append(("suspicious", f"Possible {name} at offset {offset}"))

    return {
        "type": real_type,
        "size": len(data),
        "findings": findings,
        "suspicious": any(level == "suspicious" for level, _ in findings),
    }