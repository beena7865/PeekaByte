"""
PeekaByte — File Format Fingerprinter
Detects mismatched file extensions by checking magic bytes.
E.g. a file named .jpg that is actually a .png inside.
"""


SIGNATURES = {
    # Images
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"BM": "BMP",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"RIFF": "RIFF",  # could be WAV or WEBP — check further
    b"II\x2a\x00": "TIFF (little-endian)",
    b"MM\x00\x2a": "TIFF (big-endian)",

    # Audio
    b"\xff\xfb": "MP3",
    b"\xff\xf3": "MP3",
    b"\xff\xf2": "MP3",
    b"ID3": "MP3 (ID3 tag)",
    b"fLaC": "FLAC",
    b"OggS": "OGG",

    # Archives
    b"PK\x03\x04": "ZIP/DOCX/XLSX/PPTX",
    b"PK\x05\x06": "ZIP (empty)",
    b"Rar!\x1a\x07": "RAR",
    b"\x1f\x8b": "GZIP",
    b"7z\xbc\xaf\x27\x1c": "7-Zip",

    # Documents
    b"%PDF": "PDF",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "Microsoft Office (OLE2)",

    # Executables
    b"MZ": "Windows Executable (EXE/DLL)",
    b"\x7fELF": "Linux Executable (ELF)",

    # Video
    b"\x00\x00\x00\x18ftypmp4": "MP4",
    b"\x00\x00\x00\x1cftypisom": "MP4 (ISOM)",
    b"\x00\x00\x00\x20ftypisom": "MP4",
    b"\x1aE\xdf\xa3": "MKV/WebM",
}

# Which extensions normally go with which format
EXPECTED_EXTENSIONS = {
    "PNG": [".png"],
    "JPEG": [".jpg", ".jpeg", ".jfif"],
    "BMP": [".bmp"],
    "GIF": [".gif"],
    "TIFF (little-endian)": [".tif", ".tiff"],
    "TIFF (big-endian)": [".tif", ".tiff"],
    "MP3": [".mp3"],
    "MP3 (ID3 tag)": [".mp3"],
    "FLAC": [".flac"],
    "OGG": [".ogg", ".oga"],
    "WAV": [".wav"],
    "WEBP": [".webp"],
    "ZIP/DOCX/XLSX/PPTX": [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt"],
    "ZIP (empty)": [".zip"],
    "RAR": [".rar"],
    "GZIP": [".gz", ".tgz"],
    "7-Zip": [".7z"],
    "PDF": [".pdf"],
    "Microsoft Office (OLE2)": [".doc", ".xls", ".ppt", ".msg"],
    "Windows Executable (EXE/DLL)": [".exe", ".dll", ".sys"],
    "Linux Executable (ELF)": [".elf", ".so", ".bin"],
    "MP4": [".mp4", ".m4a", ".m4v"],
    "MP4 (ISOM)": [".mp4", ".m4a", ".m4v"],
    "MKV/WebM": [".mkv", ".webm"],
}


def identify_format(data):
    """
    Identify the actual file format from magic bytes.
    Returns the format name string, or "Unknown".
    """
    # Check RIFF subtypes first
    if data[:4] == b"RIFF" and len(data) >= 12:
        if data[8:12] == b"WAVE":
            return "WAV"
        if data[8:12] == b"WEBP":
            return "WEBP"
        return "RIFF (unknown)"

    # Check MP4 variants (offset varies)
    if len(data) >= 12:
        for offset in [4, 8]:
            chunk = data[offset:offset+4]
            if chunk == b"ftyp":
                return "MP4"

    # Check standard signatures (longest match first)
    for sig, fmt in sorted(SIGNATURES.items(), key=lambda x: -len(x[0])):
        if data[:len(sig)] == sig:
            return fmt

    return "Unknown"


def check_extension_match(data, filename):
    """
    Check if a file's extension matches its actual content.

    Returns dict:
        "actual_format": str — what the file really is
        "claimed_extension": str — what the extension says
        "match": bool — True if they agree
        "suspicious": bool — True if mismatch is suspicious
        "note": str — human-readable explanation
    """
    ext = ""
    if "." in filename:
        ext = "." + filename.rsplit(".", 1)[-1].lower()

    actual = identify_format(data)

    result = {
        "actual_format": actual,
        "claimed_extension": ext or "(no extension)",
        "match": True,
        "suspicious": False,
        "note": "",
    }

    if actual == "Unknown":
        result["note"] = "Could not identify the file format from its header bytes."
        return result

    if not ext:
        result["match"] = False
        result["note"] = f"File has no extension but contains {actual} data."
        return result

    expected = EXPECTED_EXTENSIONS.get(actual, [])

    if not expected:
        result["note"] = f"File format: {actual}. No extension check available for this format."
        return result

    if ext in expected:
        result["match"] = True
        result["note"] = f"Extension {ext} matches the actual format ({actual})."
        return result

    # Mismatch!
    result["match"] = False
    result["suspicious"] = True
    result["note"] = (f"MISMATCH: File extension is {ext} but the actual content is {actual}. "
                      f"Expected extensions for {actual}: {', '.join(expected)}. "
                      f"This file may have been renamed to hide its true type.")
    return result