import struct

MARKER_NAMES = {
    0xC0: "SOF0 (baseline)", 0xC1: "SOF1", 0xC2: "SOF2 (progressive)",
    0xC4: "DHT (Huffman tables)", 0xDB: "DQT (quantization tables)",
    0xDA: "SOS (start of scan)", 0xDD: "DRI (restart interval)",
    0xFE: "COM (comment)",
}

# identifiers that normal programs put in APPn segments
KNOWN_APP = [
    (b"JFIF\x00", "JFIF"),
    (b"JFXX\x00", "JFIF extension"),
    (b"Exif\x00\x00", "Exif metadata"),
    (b"http://ns.adobe.com/xap/1.0/\x00", "XMP metadata"),
    (b"ICC_PROFILE\x00", "ICC colour profile"),
    (b"Adobe", "Adobe"),
    (b"Photoshop 3.0", "Photoshop"),
    (b"MPF\x00", "Multi-picture"),
]


def marker_name(marker):
    if marker in MARKER_NAMES:
        return MARKER_NAMES[marker]
    if 0xE0 <= marker <= 0xEF:
        return f"APP{marker - 0xE0}"
    return f"marker 0x{marker:02X}"


def skip_scan(data, pos):
    """Skip the compressed image data that follows a SOS segment."""
    while True:
        pos = data.find(b"\xff", pos)
        if pos == -1 or pos + 1 >= len(data):
            return len(data)
        nxt = data[pos + 1]
        if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:   # stuffed byte / restart marker
            pos += 2
        elif nxt == 0xFF:                          # fill byte
            pos += 1
        else:
            return pos                             # a real marker


def parse_jpeg(data):
    """Walk through the JPEG. Returns (segments, end_offset, problems).
    Each segment is (marker, offset, payload)."""
    segments, problems = [], []
    if data[:2] != b"\xff\xd8":
        return segments, None, ["File does not start with the JPEG marker FFD8"]
    pos, end_offset = 2, None
    while pos + 1 < len(data):
        if data[pos] != 0xFF:
            problems.append(f"Unexpected byte 0x{data[pos]:02X} at offset {pos} "
                            f"where a marker should be")
            break
        marker = data[pos + 1]
        if marker == 0xFF:                         # fill byte
            pos += 1
            continue
        if marker == 0xD9:                         # end of image
            end_offset = pos + 2
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD8:   # no length field
            pos += 2
            continue
        if pos + 4 > len(data):
            problems.append("File ends in the middle of a segment header")
            break
        length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        payload = data[pos + 4:pos + 2 + length]
        segments.append((marker, pos, payload))
        pos += 2 + length
        if marker == 0xDA:
            pos = skip_scan(data, pos)
    return segments, end_offset, problems


def read_quant_tables(payload):
    """Return a list of (table_id, values) from one DQT segment."""
    tables, i = [], 0
    while i < len(payload):
        precision, table_id = payload[i] >> 4, payload[i] & 15
        size = 64 * (2 if precision else 1)
        values = list(payload[i + 1:i + 1 + size])
        tables.append((table_id, values))
        i += 1 + size
    return tables


def run_jpg_checks(path):
    with open(path, "rb") as f:
        data = f.read()

    segments, end_offset, problems = parse_jpeg(data)
    findings = [("warning", p) for p in problems]
    layout = [marker_name(m) for m, _, _ in segments]

    # 1. data after the end-of-image marker
    if end_offset is None and not problems:
        findings.append(("warning", "No end-of-image marker (file cut or damaged)"))
    if end_offset is not None and end_offset < len(data):
        extra = data[end_offset:]
        findings.append(("suspicious",
                         f"{len(extra)} bytes after the end-of-image marker "
                         f"(offset {end_offset}): {extra[:40]!r}"))

    seen_tables = set()
    for marker, offset, payload in segments:
        # 2. comments
        if marker == 0xFE and payload:
            text = payload.decode("latin-1")
            level = "suspicious" if len(payload) > 200 else "warning"
            findings.append((level, f"Comment segment at offset {offset} "
                                    f"({len(payload)} bytes): {text[:60]!r}"))
        # 3. APPn segments with unknown content
        if 0xE0 <= marker <= 0xEF:
            if not any(payload.startswith(sig) for sig, _ in KNOWN_APP):
                findings.append(("warning",
                                 f"Unknown {marker_name(marker)} segment at offset "
                                 f"{offset} ({len(payload)} bytes): {payload[:20]!r}"))
        # 4. quantization tables
        if marker == 0xDB:
            for table_id, values in read_quant_tables(payload):
                if table_id > 3:
                    findings.append(("warning", f"Invalid quantization table id {table_id}"))
                if table_id in seen_tables:
                    findings.append(("warning",
                                     f"Quantization table {table_id} is defined more "
                                     f"than once (offset {offset})"))
                seen_tables.add(table_id)

    return {
        "layout": layout,
        "size": len(data),
        "findings": findings,
        "suspicious": any(level == "suspicious" for level, _ in findings),
    }