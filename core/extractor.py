"""
PeekaByte — Universal Data Extractor
Tries every known method to extract hidden data from files.
"""

import struct
import io
import re

import logging
logging.basicConfig(level=logging.DEBUG)

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


def _bytes_to_text(data):
    """Try to decode bytes as readable text."""
    if not data:
        return None
    # Try UTF-8
    try:
        text = data.decode("utf-8", errors="ignore")
        # Filter to printable chars
        clean = "".join(c for c in text if c.isprintable() or c in "\n\r\t")
        if len(clean) > 3:
            return clean.strip()
    except Exception:
        pass
    return None

def _is_readable(text):
    """Check if text has enough readable characters to be meaningful."""
    if not text or len(text) < 8:
        return False
    # Must have mostly normal English/readable characters
    normal = sum(1 for c in text if c.isascii() and (c.isalpha() or c.isspace() or c.isdigit()))
    ratio = normal / len(text)
    if ratio < 0.75:
        return False
    # Must have actual words (at least 2 words with 3+ letters)
    words = [w for w in text.split() if len(w) >= 3 and w.isalpha()]
    return len(words) >= 2



def extract_metadata_text(data, filename):
    """Extract hidden text from file metadata: EXIF, PNG chunks, JPEG comments."""
    findings = []
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # ---- PNG text chunks (tEXt, iTXt, zTXt) ----
    if data[:4] == b"\x89PNG":
        pos = 8
        while pos < len(data) - 8:
            try:
                chunk_len = struct.unpack(">I", data[pos:pos + 4])[0]
                chunk_type = data[pos + 4:pos + 8].decode("ascii", errors="ignore")
                chunk_data = data[pos + 8:pos + 8 + chunk_len]

                if chunk_type in ("tEXt", "iTXt"):
                    text = _bytes_to_text(chunk_data)
                    if text and len(text) > 2:
                        # Split keyword and value
                        parts = text.split("\x00", 1)
                        if len(parts) == 2:
                            key, value = parts
                            if value.strip():
                                findings.append({
                                    "method": f"PNG {chunk_type} chunk",
                                    "key": key,
                                    "value": value.strip()[:2000],
                                })
                        else:
                            findings.append({
                                "method": f"PNG {chunk_type} chunk",
                                "key": "text",
                                "value": text[:2000],
                            })
                elif chunk_type == "zTXt":
                    try:
                        import zlib
                        null_pos = chunk_data.find(b"\x00")
                        if null_pos > 0:
                            key = chunk_data[:null_pos].decode("ascii", errors="ignore")
                            compressed = chunk_data[null_pos + 2:]  # skip null + compression method
                            decompressed = zlib.decompress(compressed)
                            text = _bytes_to_text(decompressed)
                            if text:
                                findings.append({
                                    "method": "PNG zTXt chunk (compressed)",
                                    "key": key,
                                    "value": text[:2000],
                                })
                    except Exception:
                        pass

                pos += 12 + chunk_len
                if chunk_type == "IEND":
                    break
            except Exception:
                break

    # ---- JPEG COM markers (comments) ----
    if data[:2] == b"\xff\xd8":
        pos = 2
        while pos < len(data) - 4:
            if data[pos] != 0xFF:
                pos += 1
                continue
            marker = data[pos + 1]
            if marker == 0xD9:  # EOI
                break
            if marker == 0xFE:  # COM marker
                length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                comment = data[pos + 4:pos + 2 + length]
                text = _bytes_to_text(comment)
                if text and len(text) > 1:
                    findings.append({
                        "method": "JPEG comment marker",
                        "key": "comment",
                        "value": text[:2000],
                    })
                pos += 2 + length
            elif marker in (0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
                            0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF):
                # APP markers - check for hidden text in EXIF
                length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                app_data = data[pos + 4:pos + 2 + length]
                # Look for EXIF UserComment
                if b"UserComment" in app_data or b"ImageDescription" in app_data:
                    text = _bytes_to_text(app_data)
                    if text:
                        # Extract readable parts
                        readable = re.findall(r'[\x20-\x7E]{8,}', text)
                        for r in readable:
                            if not r.startswith(("Exif", "http", "Adobe", "ICC_PROFILE")):
                                findings.append({
                                    "method": "EXIF metadata field",
                                    "key": "user data",
                                    "value": r[:2000],
                                })
                pos += 2 + length
            elif marker == 0xDA:  # SOS - start of scan data
                break
            else:
                try:
                    length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                    pos += 2 + length
                except Exception:
                    pos += 2
        # Also look for text after JPEG end
        eoi_pos = data.rfind(b"\xff\xd9")
        if eoi_pos > 0 and eoi_pos + 2 < len(data):
            trailing = data[eoi_pos + 2:]
            text = _bytes_to_text(trailing)
            if text and _is_readable(text):
                findings.append({
                    "method": "Text after JPEG end marker",
                    "key": "trailing text",
                    "value": text[:2000],
                })

    # ---- PDF metadata ----
    if data[:5] == b"%PDF-":
        # Look for metadata strings
        text = data.decode("latin-1", errors="ignore")
        for tag in ("Title", "Author", "Subject", "Keywords", "Creator", "Producer"):
            pattern = f"/{tag}\\s*\\(([^)]+)\\)"
            matches = re.findall(pattern, text)
            for m in matches:
                if m.strip() and len(m.strip()) > 1:
                    findings.append({
                        "method": "PDF metadata",
                        "key": tag,
                        "value": m.strip()[:500],
                    })


    logging.debug(f"Metadata findings for {filename}: {findings}")
    return findings


def extract_lsb_multi(data, filename):
    """Try extracting LSB data using multiple bit orders and channel orders."""
    if not HAS_PIL:
        return []

    findings = []
    try:
        img = Image.open(io.BytesIO(data))
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGB")
        pixels = list(img.getdata())
        width, height = img.size
    except Exception:
        return []

    # Different channel orders to try
    orders = [
        ("RGB sequential", [0, 1, 2]),
        ("Red only", [0]),
        ("Green only", [1]),
        ("Blue only", [2]),
        ("BGR sequential", [2, 1, 0]),
        ("RG only", [0, 1]),
        ("RB only", [0, 2]),
    ]

    for order_name, channels in orders:
        bits = []
        for pixel in pixels:
            for ch in channels:
                bits.append(pixel[ch] & 1)
            if len(bits) >= 8000:  # Read first 1000 bytes
                break

        # Convert bits to bytes
        extracted = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            extracted.append(byte)
            # Stop at null terminator
            if byte == 0 and i > 16:
                break

        text = _bytes_to_text(bytes(extracted))
        if text and _is_readable(text) and len(text) > 4:
            findings.append({
                "method": f"LSB extraction ({order_name})",
                "key": "hidden message",
                "value": text[:2000],
            })

    # ---- Column-first reading (instead of row-first) ----
    try:
        bits = []
        for x in range(width):
            for y in range(height):
                pixel = img.getpixel((x, y))
                for ch in [0, 1, 2]:
                    bits.append(pixel[ch] & 1)
                if len(bits) >= 8000:
                    break
            if len(bits) >= 8000:
                break

        extracted = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            extracted.append(byte)
            if byte == 0 and i > 16:
                break

        text = _bytes_to_text(bytes(extracted))
        if text and _is_readable(text) and len(text) > 4:
            findings.append({
                "method": "LSB extraction (column-first RGB)",
                "key": "hidden message",
                "value": text[:2000],
            })
    except Exception:
        pass

    # ---- 2-bit and 3-bit extraction ----
    for num_bits in [2, 3]:
        bits = []
        for pixel in pixels:
            for ch in [0, 1, 2]:
                for b in range(num_bits):
                    bits.append((pixel[ch] >> b) & 1)
            if len(bits) >= 8000:
                break

        extracted = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            extracted.append(byte)
            if byte == 0 and i > 16:
                break

        text = _bytes_to_text(bytes(extracted))
        if text and _is_readable(text) and len(text) > 4:
            findings.append({
                "method": f"LSB extraction ({num_bits}-bit depth, RGB)",
                "key": "hidden message",
                "value": text[:2000],
            })

    logging.debug(f"LSB findings for {filename}: {findings}")
    return findings


def extract_trailing_data(data, filename):
    """Extract and decode data found after the file's end marker."""
    findings = []

    # Find end of file markers
    end_pos = None

    # JPEG
    if data[:2] == b"\xff\xd8":
        pos = data.rfind(b"\xff\xd9")
        if pos > 0:
            end_pos = pos + 2

    # PNG
    elif data[:4] == b"\x89PNG":
        pos = data.find(b"IEND")
        if pos > 0:
            end_pos = pos + 8  # IEND + CRC

    # GIF
    elif data[:3] in (b"GIF"):
        pos = data.rfind(b"\x3b")
        if pos > 0:
            end_pos = pos + 1

    # BMP
    elif data[:2] == b"BM":
        try:
            file_size = struct.unpack("<I", data[2:6])[0]
            if file_size < len(data):
                end_pos = file_size
        except Exception:
            pass

    # PDF
    elif data[:5] == b"%PDF-":
        pos = data.rfind(b"%%EOF")
        if pos > 0:
            end_pos = pos + 5

    if end_pos and end_pos < len(data):
        trailing = data[end_pos:]
        if len(trailing) > 2:
            # Try as plain text
            text = _bytes_to_text(trailing)
            if text and _is_readable(text):
                findings.append({
                    "method": "Trailing data (plain text)",
                    "key": f"{len(trailing)} bytes after file end",
                    "value": text[:2000],
                })

            # Try XOR with single byte keys
            for key in range(1, 256):
                decoded = bytes(b ^ key for b in trailing[:500])
                text = _bytes_to_text(decoded)
                if text and _is_readable(text) and len(text) > 8:
                    findings.append({
                        "method": f"Trailing data (XOR key: {key} / 0x{key:02X})",
                        "key": f"decoded with single-byte XOR",
                        "value": text[:2000],
                    })
                    break  # Show only first working key

            # Try Base64 decode
            try:
                import base64
                decoded = base64.b64decode(trailing[:2000])
                text = _bytes_to_text(decoded)
                if text and _is_readable(text):
                    findings.append({
                        "method": "Trailing data (Base64 decoded)",
                        "key": "base64 hidden message",
                        "value": text[:2000],
                    })
            except Exception:
                pass

            # Try reversed bytes
            reversed_data = trailing[:500][::-1]
            text = _bytes_to_text(reversed_data)
            if text and _is_readable(text) and len(text) > 8:
                findings.append({
                    "method": "Trailing data (reversed bytes)",
                    "key": "reversed hidden message",
                    "value": text[:2000],
                })

    logging.debug(f"Trailing data findings for {filename}: {findings}")
    return findings


def extract_stego_signatures(data, filename):
    """Look for known steganography tool signatures and try to extract."""
    findings = []

    # OpenStego signature
    if b"openstego" in data.lower() or b"\x00\x00OSED" in data:
        findings.append({
            "method": "Tool signature detected",
            "key": "OpenStego",
            "value": "This file was created with OpenStego. Use OpenStego software to extract the hidden data.",
        })

    # Steghide
    if b"steghide" in data.lower():
        findings.append({
            "method": "Tool signature detected",
            "key": "Steghide",
            "value": "This file was created with Steghide. Use 'steghide extract -sf filename' to extract.",
        })

    # SilentEye
    if b"SilentEye" in data:
        findings.append({
            "method": "Tool signature detected",
            "key": "SilentEye",
            "value": "This file was created with SilentEye. Use SilentEye software to extract.",
        })

    # Snow (whitespace steganography)
    if b"snow" in data.lower() and b"\t " in data:
        findings.append({
            "method": "Tool signature detected",
            "key": "Snow/Whitespace Stego",
            "value": "Whitespace steganography detected (tabs and spaces encode data).",
        })

    # Check for PK header in trailing data (ZIP hidden after image)
    for sig_name, sig_bytes in [("ZIP archive", b"PK\x03\x04"),
                                 ("RAR archive", b"Rar!\x1a\x07"),
                                 ("7-Zip archive", b"7z\xbc\xaf\x27\x1c"),
                                 ("PDF document", b"%PDF-"),
                                 ("PNG image", b"\x89PNG"),
                                 ("JPEG image", b"\xff\xd8\xff")]:
        # Find after position 100 (skip the host file header)
        pos = data.find(sig_bytes, 100)
        if pos > 100:
            findings.append({
                "method": "Embedded file detected",
                "key": sig_name,
                "value": f"Found {sig_name} signature at byte position {pos:,}. Use the File Carver tab to extract it.",
            })

    logging.debug(f"Stego signature findings for {filename}: {findings}")
    return findings


def extract_audio_lsb(data, filename):
    """Extract LSB data from audio files."""
    findings = []
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext != "wav" or data[:4] != b"RIFF":
        return findings

    try:
        import wave
        wav = wave.open(io.BytesIO(data), "rb")
        frames = wav.readframes(wav.getnframes())
        sample_width = wav.getsampwidth()
        wav.close()

        if sample_width == 2:  # 16-bit audio
            bits = []
            for i in range(0, min(len(frames) - 1, 16000), 2):
                sample = struct.unpack("<h", frames[i:i + 2])[0]
                bits.append(sample & 1)

            extracted = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                extracted.append(byte)
                if byte == 0 and i > 16:
                    break

            text = _bytes_to_text(bytes(extracted))
            if text and _is_readable(text) and len(text) > 4:
                findings.append({
                    "method": "Audio LSB extraction (16-bit)",
                    "key": "hidden message in audio",
                    "value": text[:2000],
                })

        elif sample_width == 1:  # 8-bit audio
            bits = []
            for i in range(min(len(frames), 8000)):
                bits.append(frames[i] & 1)

            extracted = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                extracted.append(byte)
                if byte == 0 and i > 16:
                    break

            text = _bytes_to_text(bytes(extracted))
            if text and _is_readable(text) and len(text) > 4:
                findings.append({
                    "method": "Audio LSB extraction (8-bit)",
                    "key": "hidden message in audio",
                    "value": text[:2000],
                })
    except Exception:
        pass

    logging.debug(f"Audio LSB findings for {filename}: {findings}")
    return findings



def extract_all(data, filename):
    """
    Run ALL extraction methods and return combined results.
    Returns list of dicts: [{method, key, value}, ...]
    """
    all_findings = []

    # 1. Metadata extraction
    try:
        all_findings.extend(extract_metadata_text(data, filename))
    except Exception:
        pass

    # 2. Multi-order LSB extraction (images only)
    try:
        all_findings.extend(extract_lsb_multi(data, filename))
    except Exception:
        pass

    # 3. Trailing data extraction
    try:
        all_findings.extend(extract_trailing_data(data, filename))
    except Exception:
        pass

    # 4. Stego tool signatures
    try:
        all_findings.extend(extract_stego_signatures(data, filename))
    except Exception:
        pass

    # 5. Audio LSB extraction
    try:
        all_findings.extend(extract_audio_lsb(data, filename))
    except Exception:
        pass

    # Remove duplicates (same value from different methods)
    seen_values = set()
    unique = []
    for f in all_findings:
        val = f["value"][:100]
        if val not in seen_values:
            seen_values.add(val)
            unique.append(f)

    logging.debug(f"Total unique findings for {filename}: {unique}")
    return unique