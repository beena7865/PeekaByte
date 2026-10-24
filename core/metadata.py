"""Metadata inspector (the exiftool-style check): reads EXIF tags, GPS
coordinates and any text saved inside the file's own metadata fields, with
no external binaries required."""
import io

from PIL import ExifTags, Image
from PIL.ExifTags import GPSTAGS


def _deg(dms, ref):
    try:
        d, m, s = (float(x) for x in dms)
    except Exception:
        return None
    val = d + m / 60 + s / 3600
    if ref in ("S", "W"):
        val = -val
    return round(val, 6)


def _gps(gps_ifd):
    tags = {GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
    lat = _deg(tags.get("GPSLatitude", ()), tags.get("GPSLatitudeRef", "N"))
    lon = _deg(tags.get("GPSLongitude", ()), tags.get("GPSLongitudeRef", "E"))
    if lat is None or lon is None:
        return None
    return {"lat": lat, "lon": lon,
            "maps_url": f"https://www.google.com/maps?q={lat},{lon}"}


def read_metadata(data):
    """Return {"tags": [(name, value)], "gps": dict|None, "note": str}."""
    out = {"tags": [], "gps": None, "note": ""}
    try:
        img = Image.open(io.BytesIO(data))
    except Exception:
        out["note"] = "This file is not an image, so there is no EXIF metadata to read."
        return out
    try:
        exif = img.getexif()
    except Exception:
        exif = None
    if not exif:
        out["note"] = "No EXIF metadata was found in this file."
        return out
    gps_ifd = exif.get_ifd(0x8825) if 0x8825 in exif else {}
    for tag_id, value in exif.items():
        if tag_id == 0x8825:
            continue
        name = ExifTags.TAGS.get(tag_id, f"Tag {tag_id}")
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8", "replace").strip("\x00").strip()
            except Exception:
                value = repr(value)
        value = str(value).strip()
        if value and len(value) < 300:
            out["tags"].append((name, value))
    if gps_ifd:
        out["gps"] = _gps(gps_ifd)
    if not out["tags"] and not out["gps"]:
        out["note"] = "This file has an EXIF block but no readable fields."
    return out