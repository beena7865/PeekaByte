"""
PeekaByte — File Carver
Scans raw bytes of a file to find and extract hidden files embedded inside it.
"""

import io
import struct


# Signatures to search for (magic bytes, name, extension)
SIGNATURES = [
    # Archives
    (b"PK\x03\x04", "ZIP Archive", ".zip"),
    (b"PK\x05\x06", "ZIP Archive (empty)", ".zip"),
    (b"Rar!\x1a\x07", "RAR Archive", ".rar"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", ".7z"),
    (b"\x1f\x8b", "GZIP Archive", ".gz"),

    # Documents
    (b"%PDF", "PDF Document", ".pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Microsoft Office (old)", ".doc"),

    # Images
    (b"\x89PNG\r\n\x1a\n", "PNG Image", ".png"),
    (b"\xff\xd8\xff", "JPEG Image", ".jpg"),
    (b"GIF87a", "GIF Image", ".gif"),
    (b"GIF89a", "GIF Image", ".gif"),
    (b"BM", "BMP Image", ".bmp"),
    (b"RIFF", "RIFF (WAV/WEBP)", ".wav"),

    # Executables
    (b"MZ", "Windows Executable", ".exe"),
    (b"\x7fELF", "Linux Executable", ".elf"),

    # Audio
    (b"ID3", "MP3 Audio (ID3)", ".mp3"),
    (b"fLaC", "FLAC Audio", ".flac"),
    (b"OggS", "OGG Audio", ".ogg"),

    # Video
    (b"\x1aE\xdf\xa3", "MKV/WebM Video", ".mkv"),

    # Other
    (b"SQLite format 3", "SQLite Database", ".db"),
]

# End markers for common formats
END_MARKERS = {
    "jpeg": b"\xff\xd9",
    "png": b"IEND\xae\x42\x60\x82",
    "gif": b"\x00\x3b",
    "pdf_eof": b"%%EOF",
}


def find_host_end(data, filename):
    """
    Find where the host file's actual data ends.
    Everything after this position is potentially hidden content.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext in ("jpg", "jpeg"):
        # JPEG ends at last FFD9
        pos = data.rfind(END_MARKERS["jpeg"])
        if pos > 0:
            return pos + 2
    elif ext == "png":
        # PNG ends after IEND chunk
        pos = data.find(END_MARKERS["png"])
        if pos > 0:
            return pos + 8  # IEND + CRC
    elif ext == "gif":
        # GIF ends at 00 3B
        pos = data.rfind(END_MARKERS["gif"])
        if pos > 0:
            return pos + 2
    elif ext == "pdf":
        # PDF ends at %%EOF
        pos = data.rfind(END_MARKERS["pdf_eof"])
        if pos > 0:
            return pos + 5
    elif ext == "bmp":
        # BMP size is stored in header at offset 2 (4 bytes, little-endian)
        if len(data) >= 6:
            bmp_size = struct.unpack_from("<I", data, 2)[0]
            if 0 < bmp_size < len(data):
                return bmp_size

    return None


def scan_for_signatures(data, start_pos):
    """
    Scan the data starting from start_pos looking for known file signatures.
    Returns list of (position, name, extension, size_estimate).
    """
    found = []

    for sig, name, ext in SIGNATURES:
        pos = start_pos
        while True:
            pos = data.find(sig, pos)
            if pos < 0 or pos < start_pos:
                break

            # Estimate size of the found file
            size = len(data) - pos

            # For some formats, try to find the end
            if ext == ".jpg":
                end = data.find(b"\xff\xd9", pos + 2)
                if end > pos:
                    size = end - pos + 2
            elif ext == ".png":
                end = data.find(b"IEND\xae\x42\x60\x82", pos + 8)
                if end > pos:
                    size = end - pos + 8
            elif ext == ".pdf":
                end = data.find(b"%%EOF", pos + 4)
                if end > pos:
                    size = end - pos + 5
            elif ext == ".zip":
                # ZIP has an end-of-central-directory marker
                eocd = data.find(b"PK\x05\x06", pos + 4)
                if eocd > pos:
                    size = eocd - pos + 22  # minimum EOCD size

            # Skip tiny matches (probably false positives)
            if size < 20:
                pos += len(sig)
                continue

            found.append({
                "position": pos,
                "name": name,
                "extension": ext,
                "size": size,
                "data": data[pos:pos + size],
            })

            pos += len(sig)

    # Sort by position
    found.sort(key=lambda x: x["position"])

    # Remove duplicates at same position
    unique = []
    seen_positions = set()
    for f in found:
        if f["position"] not in seen_positions:
            seen_positions.add(f["position"])
            unique.append(f)

    return unique


def carve_file(data, filename):
    """
    Main carving function. Analyzes a file for hidden embedded files.

    Returns dict:
        "host_format": str — what the main file is
        "host_size": int — where the host file data ends
        "file_size": int — actual file size
        "trailing_bytes": int — bytes after the host data
        "has_trailing": bool — True if there's extra data
        "carved_files": list of dict with name, extension, position, size, data
        "note": str
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    file_size = len(data)

    result = {
        "host_format": ext.upper() or "Unknown",
        "host_size": file_size,
        "file_size": file_size,
        "trailing_bytes": 0,
        "has_trailing": False,
        "carved_files": [],
        "note": "",
    }

    # Find where the host file ends
    host_end = find_host_end(data, filename)

    if host_end is None:
        # Can't determine host end — scan entire file for embedded signatures
        # Skip the first signature (which is the file itself)
        all_found = scan_for_signatures(data, 100)

        # Filter out the host file itself
        filtered = []
        for f in all_found:
            # Skip if it's at position 0 (the host file itself)
            if f["position"] < 50:
                continue
            filtered.append(f)

        if filtered:
            result["carved_files"] = filtered
            result["note"] = (f"Could not determine where the {ext.upper()} data ends, "
                              f"but found {len(filtered)} embedded file(s) inside.")
        else:
            result["note"] = (f"Could not determine where the {ext.upper()} data ends. "
                              "No embedded files detected by signature scan.")
        return result

    # We know where the host ends
    result["host_size"] = host_end
    trailing = file_size - host_end
    result["trailing_bytes"] = trailing

    if trailing < 10:
        result["note"] = "File ends cleanly — no trailing data found."
        return result

    result["has_trailing"] = True

    # Scan the trailing data for known file signatures
    carved = scan_for_signatures(data, host_end)

    if carved:
        result["carved_files"] = carved
        result["note"] = (f"Found {trailing:,} bytes of trailing data after the {ext.upper()} "
                          f"content ends at position {host_end:,}. "
                          f"Detected {len(carved)} hidden file(s).")
    else:
        # Unknown trailing data — save it as raw
        result["carved_files"] = [{
            "position": host_end,
            "name": "Unknown data blob",
            "extension": ".bin",
            "size": trailing,
            "data": data[host_end:],
        }]
        result["note"] = (f"Found {trailing:,} bytes of unidentified trailing data "
                          f"after position {host_end:,}. Saved as raw binary.")

    return result