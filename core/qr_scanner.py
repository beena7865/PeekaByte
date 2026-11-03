"""
PeekaByte — QR Code Scanner (OpenCV version)
Detect and decode QR codes hidden inside images.
"""

import io
from PIL import Image

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

import numpy as np


def identify_qr_type(text):
    t = text.strip()
    details = []

    if t.lower().startswith("upi://"):
        qtype = "UPI Payment"
        parts = t.split("?")
        if len(parts) > 1:
            for p in parts[1].split("&"):
                if "=" in p:
                    key, val = p.split("=", 1)
                    labels = {"pa": "UPI ID", "pn": "Payee Name", "am": "Amount",
                              "cu": "Currency", "tn": "Note", "mc": "Merchant Code",
                              "tr": "Transaction Ref", "url": "URL", "mode": "Mode"}
                    from urllib.parse import unquote
                    details.append((labels.get(key.lower(), key), unquote(val)))
        return {"type": qtype, "details": details}

    if t.lower().startswith(("http://", "https://", "www.")):
        return {"type": "Website URL", "details": [("URL", t)]}

    if t.upper().startswith("WIFI:"):
        inner = t[5:].rstrip(";")
        for part in inner.split(";"):
            if ":" in part:
                key, val = part.split(":", 1)
                labels = {"S": "Network Name (SSID)", "T": "Security", "P": "Password", "H": "Hidden"}
                details.append((labels.get(key, key), val))
        return {"type": "WiFi Network", "details": details}

    if t.upper().startswith("BEGIN:VCARD"):
        for line in t.split("\n"):
            line = line.strip()
            if ":" in line and not line.startswith(("BEGIN", "END", "VERSION")):
                key, val = line.split(":", 1)
                labels = {"FN": "Full Name", "TEL": "Phone", "EMAIL": "Email",
                          "ORG": "Organization", "TITLE": "Title", "ADR": "Address",
                          "URL": "Website", "NOTE": "Note", "BDAY": "Birthday"}
                details.append((labels.get(key.split(";")[0], key), val))
        return {"type": "Contact Card (vCard)", "details": details}

    if t.lower().startswith("mailto:"):
        email = t[7:].split("?")[0]
        details.append(("Email", email))
        if "?" in t:
            for p in t.split("?")[1].split("&"):
                if "=" in p:
                    k, v = p.split("=", 1)
                    details.append((k.capitalize(), v))
        return {"type": "Email", "details": details}

    if t.lower().startswith("tel:"):
        return {"type": "Phone Number", "details": [("Number", t[4:])]}

    if t.lower().startswith(("sms:", "smsto:")):
        rest = t.split(":", 1)[1]
        if "?" in rest:
            number, params = rest.split("?", 1)
            details.append(("Number", number))
            for p in params.split("&"):
                if "=" in p:
                    k, v = p.split("=", 1)
                    details.append((k.capitalize(), v))
        else:
            details.append(("Number", rest))
        return {"type": "SMS", "details": details}

    if "wa.me" in t.lower() or "whatsapp" in t.lower():
        return {"type": "WhatsApp Link", "details": [("Link", t)]}

    if t.lower().startswith("geo:"):
        coords = t[4:].split("?")[0]
        return {"type": "Location (GPS)", "details": [("Coordinates", coords),
                ("Google Maps", f"https://www.google.com/maps?q={coords}")]}

    if t.lower().startswith("bitcoin:"):
        addr = t[8:].split("?")[0]
        details.append(("Address", addr))
        if "?" in t:
            for p in t.split("?")[1].split("&"):
                if "=" in p:
                    k, v = p.split("=", 1)
                    details.append((k.capitalize(), v))
        return {"type": "Bitcoin Payment", "details": details}

    if t.upper().startswith("BEGIN:VEVENT"):
        for line in t.split("\n"):
            line = line.strip()
            if ":" in line and not line.startswith(("BEGIN", "END")):
                key, val = line.split(":", 1)
                labels = {"SUMMARY": "Event", "DTSTART": "Start", "DTEND": "End",
                          "LOCATION": "Location", "DESCRIPTION": "Description"}
                details.append((labels.get(key, key), val))
        return {"type": "Calendar Event", "details": details}

    if len(t) > 0:
        return {"type": "Plain Text", "details": [("Content", t)]}

    return {"type": "Unknown", "details": []}


def detect_qr_scam(text, qr_info):
    import re
    warnings = []
    t = text.strip().lower()
    qtype = qr_info.get("type", "")

    short_domains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
                     "buff.ly", "ow.ly", "rebrand.ly", "cutt.ly", "shorturl.at"]
    for domain in short_domains:
        if domain in t:
            warnings.append(f"Uses shortened URL ({domain}) - the real destination is hidden. "
                            "Could redirect to a phishing or malware site.")

    if t.startswith(("http://", "https://")) or "www." in t:
        if "http://" in t and "https://" not in t:
            warnings.append("Uses HTTP (not HTTPS) - connection is not secure.")
        suspicious_words = ["login", "signin", "verify", "update", "secure", "account",
                           "confirm", "banking", "password", "credential"]
        for word in suspicious_words:
            if word in t:
                warnings.append(f"URL contains '{word}' - common in phishing pages.")
                break
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', t):
            warnings.append("URL uses an IP address instead of a domain name - suspicious.")
        fakes = {"paytm": ["paytnn", "paytni", "paytrn", "paytm-secure", "paytm-verify"],
                 "phonepe": ["phonpe", "phonepay", "phonepe-secure"],
                 "google": ["g00gle", "googie", "gooogle"],
                 "amazon": ["amaz0n", "arnazon", "amazom"],
                 "flipkart": ["fl1pkart", "flipkartt", "fllpkart"],
                 "sbi": ["sb1", "sbi-secure", "onlinesbi-verify"]}
        for real, fakes_list in fakes.items():
            for fake in fakes_list:
                if fake in t:
                    warnings.append(f"URL contains '{fake}' - looks like a misspelling of '{real}' (phishing trick).")

    if qtype == "UPI Payment":
        for label, value in qr_info.get("details", []):
            if label == "Amount" and value:
                try:
                    amount = float(value)
                    if amount > 10000:
                        warnings.append(f"UPI QR requests a large amount (Rs {amount:,.0f}). Verify before paying.")
                except ValueError:
                    pass
            if label == "UPI ID" and value:
                if "@" not in value:
                    warnings.append("UPI ID format looks invalid - missing @ symbol.")
                if any(x in value.lower() for x in ["refund", "cashback", "prize", "winner", "lottery"]):
                    warnings.append("UPI ID contains suspicious keyword (refund/cashback/prize scam).")
        if "mode=01" in text or "mode=collect" in text.lower():
            warnings.append("This QR initiates a COLLECT request - it takes money FROM you, not sends it to you!")

    if qtype == "WiFi Network":
        for label, value in qr_info.get("details", []):
            if label == "Security" and value.upper() == "NONE":
                warnings.append("This WiFi has NO password - anyone can intercept your data.")
            if label == "Network Name (SSID)" and value:
                fake_names = ["free wifi", "free internet", "airport wifi", "hotel wifi"]
                if value.lower() in fake_names:
                    warnings.append(f"Network name '{value}' mimics a public hotspot - could be an evil twin attack.")

    if t.endswith((".exe", ".apk", ".msi", ".bat", ".cmd", ".ps1", ".sh")):
        warnings.append("QR code links to an executable/app download - could install malware.")

    return warnings


def scan_qr(data):
    if not HAS_CV2:
        return {"found": False, "codes": [], "count": 0,
                "note": "QR scanning not available. Install opencv: pip install opencv-python"}

    try:
        img = Image.open(io.BytesIO(data))
    except Exception:
        return {"found": False, "codes": [], "count": 0, "note": "Could not open as image."}

    img_array = np.array(img)
    if len(img_array.shape) == 3 and img_array.shape[2] == 4:
        img_array = cv2.cvtColor(img_array, cv2.COLOR_RGBA2BGR)
    elif len(img_array.shape) == 3:
        img_array = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)

    results = []
    detector = cv2.QRCodeDetector()

    # Try original image
    retval, decoded_info, points, _ = detector.detectAndDecodeMulti(img_array)
    if retval and decoded_info:
        for i, text in enumerate(decoded_info):
            if text:
                pts = points[i] if points is not None and i < len(points) else None
                results.append({"text": text, "points": pts})

    # Try grayscale
    if not results:
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        retval, decoded_info, points, _ = detector.detectAndDecodeMulti(gray)
        if retval and decoded_info:
            for i, text in enumerate(decoded_info):
                if text:
                    pts = points[i] if points is not None and i < len(points) else None
                    results.append({"text": text, "points": pts})

    # Try enhanced contrast
    if not results:
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        enhanced = cv2.equalizeHist(gray)
        retval, decoded_info, points, _ = detector.detectAndDecodeMulti(enhanced)
        if retval and decoded_info:
            for i, text in enumerate(decoded_info):
                if text:
                    pts = points[i] if points is not None and i < len(points) else None
                    results.append({"text": text, "points": pts})

    # Try pyzbar as fallback (much better with real-world photos)
    if not results and HAS_PYZBAR:
        try:
            pyz_results = pyzbar_decode(Image.open(io.BytesIO(data)))
            for obj in pyz_results:
                text = obj.data.decode("utf-8", errors="replace")
                if text:
                    results.append({"text": text, "points": None})
        except Exception:
            pass
    if not results:
        return {"found": False, "codes": [], "count": 0,
                "note": "No QR codes found in this image."}

    codes = []
    for r in results:
        decoded_data = r["text"]
        pts = r.get("points")
        if pts is not None:
            try:
                x, y = int(pts[0][0]), int(pts[0][1])
                position = f"at ({x}, {y})"
            except Exception:
                position = "position detected"
        else:
            position = "position unknown"

        qr_info = identify_qr_type(decoded_data)
        scam_warnings = detect_qr_scam(decoded_data, qr_info)
        codes.append({
            "type": "QRCODE",
            "data": decoded_data,
            "position": position,
            "qr_type": qr_info["type"],
            "details": qr_info["details"],
            "scam_warnings": scam_warnings,
        })

    return {
        "found": True,
        "codes": codes,
        "count": len(codes),
        "note": f"Found {len(codes)} QR code(s) in this image.",
    }


def draw_qr_boxes(data):
    if not HAS_CV2:
        return None
    try:
        img = Image.open(io.BytesIO(data)).convert("RGB")
    except Exception:
        return None

    img_array = np.array(img)
    bgr = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)

    detector = cv2.QRCodeDetector()
    retval, decoded_info, points, _ = detector.detectAndDecodeMulti(bgr)
    if not retval or points is None:
        return None

    from PIL import ImageDraw
    draw = ImageDraw.Draw(img)
    for i, pts in enumerate(points):
        if pts is not None and len(pts) >= 4:
            corners = [(int(p[0]), int(p[1])) for p in pts]
            for j in range(4):
                draw.line([corners[j], corners[(j+1) % 4]], fill="#ff4f9a", width=3)
            draw.text((corners[0][0], corners[0][1] - 18), f"#{i+1}", fill="#ff4f9a")
    return img
