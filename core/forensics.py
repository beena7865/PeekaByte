"""Forensic photo timeline — extracts EXIF metadata to show when a photo
was taken, what device captured it, where, and flags signs of tampering."""
import io
import datetime


def _tag_name(tag_id):
    NAMES = {
        0x010f: "Camera Make",
        0x0110: "Camera Model",
        0x0131: "Software",
        0x9003: "Date Taken (Original)",
        0x9004: "Date Created (Digitized)",
        0x0132: "Date Modified",
    }
    return NAMES.get(tag_id, None)


def _parse_dt(val):
    if not val:
        return None
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.datetime.strptime(str(val).strip(), fmt)
        except ValueError:
            continue
    return None


def _dms_to_dec(dms, ref):
    try:
        d, m, s = float(dms[0]), float(dms[1]), float(dms[2])
        dec = d + m/60 + s/3600
        if ref in ("S", "W"):
            dec = -dec
        return round(dec, 6)
    except Exception:
        return None

def _extract_thumbnail(data: bytes):
    """Extract embedded thumbnail from JPEG EXIF if present."""
    try:
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(data))
        exif = img.getexif()
        if not exif:
            return None
        ifd = exif.get_ifd(0x8769)  # ExifIFD
        # thumbnail is stored in IFD1
        thumb = img.getexif().get_ifd(1)
        if not thumb:
            return None
        thumb_offset = thumb.get(0x0201)  # JPEGInterchangeFormat
        thumb_length = thumb.get(0x0202)  # JPEGInterchangeFormatLength
        if thumb_offset and thumb_length:
            thumb_data = data[thumb_offset:thumb_offset + thumb_length]
            if thumb_data[:3] == b"\xff\xd8\xff":
                return thumb_data
    except Exception:
        pass
    return None


def _compare_thumbnail(main_data: bytes, thumb_data: bytes) -> dict:
    """Compare thumbnail vs main image to detect post-capture editing."""
    try:
        from PIL import Image
        import io
        import numpy as np
        main = Image.open(io.BytesIO(main_data)).convert("RGB").resize((64, 64))
        thumb = Image.open(io.BytesIO(thumb_data)).convert("RGB").resize((64, 64))
        a = np.array(main).astype(np.int16)
        b = np.array(thumb).astype(np.int16)
        diff = np.abs(a - b).mean()
        return {
            "match": diff < 10,
            "diff_score": round(float(diff), 2),
            "edited": diff >= 10,
        }
    except Exception:
        return None

def _size_anomaly(data: bytes, img) -> dict:
    """Flag if file size is suspiciously large for its dimensions."""
    try:
        w, h = img.size
        pixels = w * h
        file_size = len(data)
        # rough expected size: 3 bytes per pixel compressed ~10x for JPEG
        expected_max = pixels * 3 / 5
        ratio = file_size / max(pixels, 1)
        anomaly = file_size > expected_max * 3
        return {
            "file_size": file_size,
            "dimensions": f"{w}x{h}",
            "ratio": round(ratio, 4),
            "anomaly": anomaly,
        }
    except Exception:
        return None


def _metadata_consistency(tags: dict) -> list:
    """Cross-check metadata fields for contradictions."""
    issues = []
    dt_taken = _parse_dt(tags.get("Date Taken (Original)"))
    dt_modified = _parse_dt(tags.get("Date Modified"))
    dt_digitized = _parse_dt(tags.get("Date Created (Digitized)"))

    if dt_taken and dt_modified:
        if dt_modified < dt_taken:
            issues.append("⚠️ Modified date is before capture date — timestamps manipulated.")
    if dt_taken and dt_digitized:
        diff = abs((dt_taken - dt_digitized).total_seconds())
        if diff > 3600:
            issues.append(f"ℹ️ Capture and digitized timestamps differ by "
                         f"{int(diff//3600)}h — possible timezone issue or manipulation.")
    return issues

def photo_timeline(data: bytes) -> dict:
    result = {
        "supported":   False,
        "format_note": "",
        "timeline":    [],
        "gps":         None,
        "tampering":   [],
        "device":      None,
    }

    if data[:3] == b"\xff\xd8\xff":
        result["format_note"] = "JPEG — full EXIF timeline available."
        result["supported"] = True
    elif data[:4] in (b"II*\x00", b"MM\x00*"):
        result["format_note"] = "TIFF — full EXIF timeline available."
        result["supported"] = True
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        result["format_note"] = ("PNG — limited metadata. Cameras rarely embed GPS or "
                                 "full timestamps in PNG.")
        result["supported"] = True
    elif data[:2] == b"BM":
        result["format_note"] = "BMP format has no metadata standard. No timeline available."
        return result
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        result["format_note"] = "GIF format has no EXIF support. No timeline available."
        return result
    else:
        result["format_note"] = "This file format does not carry EXIF metadata. No timeline available."
        return result

    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        exif = img.getexif()
    except Exception as e:
        result["format_note"] += f" (Could not read EXIF: {e})"
        return result

    if not exif:
        result["format_note"] += " No EXIF data found in this file."
        return result

    tags = {}
    for tag_id, val in exif.items():
        name = _tag_name(tag_id)
        if name:
            tags[name] = str(val).strip()

    make  = tags.get("Camera Make", "")
    model = tags.get("Camera Model", "")
    sw    = tags.get("Software", "")
    if make or model or sw:
        result["device"] = {"make": make, "model": model, "software": sw}

    dt_taken    = _parse_dt(tags.get("Date Taken (Original)"))
    dt_digitized = _parse_dt(tags.get("Date Created (Digitized)"))
    dt_modified = _parse_dt(tags.get("Date Modified"))

    def add(label, dt, flagged=False, note=""):
        if dt:
            result["timeline"].append({
                "label": label,
                "value": dt.strftime("%Y-%m-%d  %H:%M:%S"),
                "flagged": flagged,
                "note": note,
            })

    add("📸 Photo taken", dt_taken)
    add("💾 Digitized",   dt_digitized)
    add("✏️  Last modified", dt_modified)

        # size anomaly check
    try:
        from PIL import Image as _Img
        _img = _Img.open(io.BytesIO(data))
        size_check = _size_anomaly(data, _img)
        if size_check and size_check["anomaly"]:
            result["tampering"].append(
                f"⚠️ File size ({size_check['file_size']:,} bytes) is unusually large "
                f"for a {size_check['dimensions']} image — may contain hidden data.")
        result["size_check"] = size_check
    except Exception:
        result["size_check"] = None

    # metadata consistency
    consistency_issues = _metadata_consistency(tags)
    result["tampering"].extend(consistency_issues)

    if sw:
        editors = ["photoshop","gimp","lightroom","affinity","paint","snapseed","facetune"]
        flagged = any(x in sw.lower() for x in editors)
        result["timeline"].append({
            "label":   "🖥️  Processing software",
            "value":   sw,
            "flagged": flagged,
            "note":    "Image editing software detected — file may have been processed after capture." if flagged else "",
        })

    if dt_taken and dt_modified and dt_modified < dt_taken:
        result["tampering"].append(
            "⚠️  Modified timestamp is EARLIER than capture timestamp — metadata has been altered.")
    if dt_taken and dt_modified:
        gap = abs((dt_modified - dt_taken).total_seconds())
        if gap > 86400:
            days = int(gap // 86400)
            result["tampering"].append(
                f"ℹ️  {days} day(s) between photo capture and last modification — "
                "steganography or editing may have occurred in this window.")

    try:
        gps_ifd = exif.get_ifd(0x8825)
        if gps_ifd:
            lat_dms = gps_ifd.get(2)
            lat_ref = gps_ifd.get(1, "N")
            lon_dms = gps_ifd.get(4)
            lon_ref = gps_ifd.get(3, "E")
            if lat_dms and lon_dms:
                lat = _dms_to_dec(lat_dms, lat_ref)
                lon = _dms_to_dec(lon_dms, lon_ref)
                if lat is not None and lon is not None:
                    result["gps"] = {
                        "lat": lat, "lon": lon,
                        "maps_url": f"https://maps.google.com/?q={lat},{lon}",
                    }
    except Exception:
        pass

    # thumbnail extraction and comparison
    thumb_data = _extract_thumbnail(data)
    if thumb_data:
        result["thumbnail"] = thumb_data
        cmp = _compare_thumbnail(data, thumb_data)
        if cmp:
            result["thumb_match"] = cmp
            if cmp["edited"]:
                result["tampering"].append(
                    f"⚠️  Embedded thumbnail does not match the main image "
                    f"(difference score: {cmp['diff_score']}) — "
                    "the photo was likely edited after it was taken.")
    else:
        result["thumbnail"] = None
        result["thumb_match"] = None  
           
    return result