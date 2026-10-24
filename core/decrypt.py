"""
PeekaByte — Decrypt / Password Cracker
Cracks password-protected files (PDF, ZIP, DOCX, XLSX)
and extracts password-protected steganography.
"""

import os
import io
import zipfile
import tempfile

# --- PDF cracking ---
try:
    import pikepdf
    HAS_PIKE = True
except ImportError:
    HAS_PIKE = False

# --- Office cracking ---
try:
    import msoffcrypto
    HAS_OFFICE = True
except ImportError:
    HAS_OFFICE = False

# --- Stego extraction ---
try:
    from core.secure import unseal
    HAS_STEGO_PW = True
except ImportError:
    HAS_STEGO_PW = False

try:
    from core.audio import extract_audio
    HAS_AUDIO = True
except ImportError:
    HAS_AUDIO = False

WORDLIST_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists")

# Auto-extract rockyou.zip if rockyou.txt doesn't exist
_rockyou_txt = os.path.join(WORDLIST_DIR, "rockyou.txt")
_rockyou_zip = os.path.join(WORDLIST_DIR, "rockyou.zip")
if not os.path.exists(_rockyou_txt) and os.path.exists(_rockyou_zip):
    try:
        import zipfile
        with zipfile.ZipFile(_rockyou_zip, "r") as z:
            z.extractall(WORDLIST_DIR)
    except Exception:
        pass

_cached_passwords = None

def _load_passwords(max_passwords=5000000):
    """Load passwords from all wordlist files in the wordlists folder."""
    global _cached_passwords
    if _cached_passwords is not None:
        return _cached_passwords
    passwords = []

    # Built-in top passwords (always available)
    builtin = [
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
        "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine", "ashley",
        "123123", "654321", "passw0rd", "shadow", "123456789", "1234567890",
        "admin", "letmein", "welcome", "login", "princess", "starwars",
        "password1", "password123", "1234", "12345", "123", "1", "0000",
        "test", "guest", "access", "hello", "charlie", "donald", "batman",
        "", # try empty password
    ]
    passwords.extend(builtin)

    # Load from wordlist files
    if os.path.isdir(WORDLIST_DIR):
        for fname in sorted(os.listdir(WORDLIST_DIR)):
            fpath = os.path.join(WORDLIST_DIR, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            pw = line.strip()
                            if pw and len(pw) < 50:
                                passwords.append(pw)
                                if len(passwords) >= max_passwords:
                                    break
                except Exception:
                    pass
            if len(passwords) >= max_passwords:
                break

    # Remove duplicates but keep order
    seen = set()
    unique = []
    for pw in passwords:
        if pw not in seen:
            seen.add(pw)
            unique.append(pw)
    _cached_passwords = unique
    return unique           


def detect_file_type(data, filename):
    """Detect what kind of protected file this is."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    name_lower = filename.lower()

    # Check by magic bytes
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:2] == b"PK":
        if ext in ("docx", "doc"):
            return "docx"
        if ext in ("xlsx", "xls"):
            return "xlsx"
        if ext in ("pptx", "ppt"):
            return "pptx"
        return "zip"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        # OLE2 format — old Office
        if ext in ("doc", "docx"):
            return "docx"
        if ext in ("xls", "xlsx"):
            return "xlsx"
        return "office_old"
    if data[:4] == b"Rar!":
        return "rar"

    # Check for image/audio (stego)
    if ext in ("png", "bmp", "jpg", "jpeg", "webp", "gif", "tif", "tiff"):
        return "image_stego"
    if ext in ("wav", "mp3", "flac", "ogg", "m4a", "aac", "mp4"):
        return "audio_stego"

    return ext if ext else "unknown"


def is_pdf_encrypted(data):
    """Check if a PDF is password-protected."""
    if not HAS_PIKE:
        return None
    try:
        pikepdf.open(io.BytesIO(data))
        return False  # opened fine, not encrypted
    except pikepdf._core.PasswordError:
        return True
    except Exception:
        return None


def crack_pdf(data, password_list, progress_callback=None):
    """Try passwords on a PDF. Returns (password, text) or (None, None)."""
    if not HAS_PIKE:
        return None, "pikepdf not installed. Run: pip install pikepdf"

    for i, pw in enumerate(password_list):
        if progress_callback and i % 1000 == 0:
            progress_callback(i, len(password_list))
        try:
            pdf = pikepdf.open(io.BytesIO(data), password=pw)
            # Extract text
            text_parts = []
            for page in pdf.pages:
                try:
                    text_parts.append(page.extract_text() if hasattr(page, 'extract_text') else "")
                except Exception:
                    pass
            pdf.close()
            text = "\n".join(text_parts).strip()
            if not text:
                text = "(PDF opened but no text could be extracted - may contain images only)"
            # Save decrypted PDF bytes
            out = io.BytesIO()
            pdf.save(out)
            pdf.close()
            return pw, text, out.getvalue()
        except pikepdf._core.PasswordError:
            continue
        except Exception:
            continue
    return None, None, None


def is_zip_encrypted(data):
    """Check if a ZIP is password-protected."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if info.flag_bits & 0x1:  # encrypted flag
                    return True
            # Try reading first file
            try:
                first = z.infolist()[0]
                z.read(first)
                return False
            except RuntimeError:
                return True
    except Exception:
        return None


def crack_zip(data, password_list, progress_callback=None):
    """Try passwords on a ZIP. Returns (password, file_list) or (None, None)."""
    for i, pw in enumerate(password_list):
        if progress_callback and i % 100 == 0:
            progress_callback(i, len(password_list))
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                pw_bytes = pw.encode("utf-8") if pw else None
                z.extractall(path=tempfile.mkdtemp(), pwd=pw_bytes)
                files = [f.filename for f in z.infolist()]
                return pw, files
        except (RuntimeError, Exception):
            continue
    return None, None


def is_office_encrypted(data):
    """Check if an Office file (docx/xlsx/pptx) is encrypted."""
    if not HAS_OFFICE:
        return None
    try:
        f = io.BytesIO(data)
        office_file = msoffcrypto.OfficeFile(f)
        return office_file.is_encrypted()
    except Exception:
        return None


def crack_office(data, password_list, progress_callback=None):
    """Try passwords on an Office file. Returns (password, status) or (None, None)."""
    if not HAS_OFFICE:
        return None, "msoffcrypto-tool not installed. Run: pip install msoffcrypto-tool"

    for i, pw in enumerate(password_list):
        if progress_callback and i % 100 == 0:
            progress_callback(i, len(password_list))
        try:
            f = io.BytesIO(data)
            office_file = msoffcrypto.OfficeFile(f)
            office_file.load_key(password=pw)
            output = io.BytesIO()
            office_file.decrypt(output)
            return pw, "File decrypted successfully", output.getvalue()
        except Exception:
            continue
    return None, None


def try_stego_extract(data, filename, password=None):
    """
    Try to extract hidden data from an image/audio file.
    If password is given, try that. Otherwise try without password.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    results = []

    # Try audio extraction (WAV only)
    if ext == "wav" and HAS_AUDIO:
        try:
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            text = extract_audio(tmp_path)
            os.unlink(tmp_path)
            if text:
                # Check if it's encrypted (from secure.seal)
                if HAS_STEGO_PW and password:
                    try:
                        decrypted = unseal(text, password)
                        results.append(("Audio LSB (with password)", decrypted))
                    except Exception:
                        results.append(("Audio LSB (encrypted)", "Data found but password is wrong or not encrypted with PeekaByte."))
                elif HAS_STEGO_PW:
                    try:
                        decrypted = unseal(text, "")
                        results.append(("Audio LSB (no password)", decrypted))
                    except Exception:
                        results.append(("Audio LSB", text))
                else:
                    results.append(("Audio LSB", text))
        except Exception:
            pass

    # Try image LSB extraction
    if ext in ("png", "bmp", "tiff", "tif"):
        try:
            from core.deep import deep_scan
            deep = deep_scan(data)
            if deep.get("leads"):
                for where, text in deep["leads"]:
                    if password and HAS_STEGO_PW:
                        try:
                            decrypted = unseal(text, password)
                            results.append((f"Image LSB - {where} (decrypted)", decrypted))
                        except Exception:
                            results.append((f"Image LSB - {where} (encrypted)", "Data found but password is wrong."))
                    else:
                        results.append((f"Image LSB - {where}", text))
        except Exception:
            pass

    return results


def crack_stego(data, filename, password_list, progress_callback=None):
    """Try passwords on hidden stego data. Returns (password, text) or (None, None)."""
    if not HAS_STEGO_PW:
        return None, None

    # First extract the raw hidden data
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    raw_text = None

    if ext == "wav":
        try:
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            raw_text = extract_audio(tmp_path)
            os.unlink(tmp_path)
        except Exception:
            pass
    elif ext in ("png", "bmp", "tiff", "tif"):
        try:
            from core.deep import deep_scan
            deep = deep_scan(data)
            if deep.get("leads"):
                raw_text = deep["leads"][0][1]
        except Exception:
            pass

    if not raw_text:
        return None, None

    # Try each password
    for i, pw in enumerate(password_list):
        if progress_callback and i % 100 == 0:
            progress_callback(i, len(password_list))
        try:
            decrypted = unseal(raw_text, pw)
            if decrypted:
                return pw, decrypted
        except Exception:
            continue

    return None, None


def full_decrypt(data, filename, user_password=None, progress_callback=None, only_user_password=False, custom_passwords=None):
    """
    Main function: detect file type, try to crack/extract.

    Returns dict with:
        file_type: str
        encrypted: bool
        cracked: bool
        password: str or None
        content: str or None
        method: str
        attempts: int
        stego_results: list
    """
    ftype = detect_file_type(data, filename)
    if only_user_password and user_password:
        passwords = [user_password]
    elif custom_passwords:
        passwords = custom_passwords + _load_passwords()
        # Remove duplicates keeping order
        seen = set()
        unique = []
        for p in passwords:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        passwords = unique
    else:
        passwords = _load_passwords()
        if user_password:
            passwords = [user_password] + [p for p in passwords if p != user_password]
    total = len(passwords)


    result = {
        "file_type": ftype,
        "encrypted": False,
        "cracked": False,
        "password": None,
        "content": None,
        "decrypted_bytes": None,
        "method": "",
        "attempts": 0,
        "total_passwords": total,
        "stego_results": [],
    }

   

    # --- PDF ---
    if ftype == "pdf":
        encrypted = is_pdf_encrypted(data)
        result["encrypted"] = encrypted
        if encrypted:
            result["method"] = "PDF password dictionary attack"
            pw, text, dec_bytes = crack_pdf(data, passwords, progress_callback)
            result["attempts"] = total
            if pw is not None:
                result["cracked"] = True
                result["password"] = pw
                result["content"] = text
                result["decrypted_bytes"] = dec_bytes
        elif encrypted is False:
            result["method"] = "PDF is not password-protected"
            result["content"] = "This PDF is not encrypted. Open it normally."

    # --- ZIP ---
    elif ftype == "zip":
        encrypted = is_zip_encrypted(data)
        result["encrypted"] = encrypted
        if encrypted:
            result["method"] = "ZIP password dictionary attack"
            pw, files = crack_zip(data, passwords, progress_callback)
            result["attempts"] = total
            if pw is not None:
                result["cracked"] = True
                result["password"] = pw
                result["content"] = "Files inside: " + ", ".join(files)

    # --- Office (DOCX, XLSX, PPTX) ---
    elif ftype in ("docx", "xlsx", "pptx", "office_old"):
        encrypted = is_office_encrypted(data)
        result["encrypted"] = encrypted
        if encrypted:
            result["method"] = f"{ftype.upper()} password dictionary attack"
            pw, status, dec_bytes = crack_office(data, passwords, progress_callback)
            result["attempts"] = total
            if pw is not None:
                result["cracked"] = True
                result["password"] = pw
                result["content"] = status
                result["decrypted_bytes"] = dec_bytes

    # --- Image stego ---
    elif ftype == "image_stego":
        result["method"] = "Steganography extraction + password attack"
        # Try direct extraction
        stego = try_stego_extract(data, filename, user_password)
        result["stego_results"] = stego
        if stego:
            result["cracked"] = True
            result["content"] = stego[0][1] if stego else None
        else:
            # Try password attack on stego
            pw, text = crack_stego(data, filename, passwords, progress_callback)
            result["attempts"] = total
            if pw is not None:
                result["cracked"] = True
                result["password"] = pw
                result["content"] = text
                result["stego_results"] = [("Decrypted with dictionary attack", text)]

    # --- Audio stego ---
    elif ftype == "audio_stego":
        result["method"] = "Audio steganography extraction + password attack"
        stego = try_stego_extract(data, filename, user_password)
        result["stego_results"] = stego
        if stego:
            result["cracked"] = True
            result["content"] = stego[0][1] if stego else None
        else:
            pw, text = crack_stego(data, filename, passwords, progress_callback)
            result["attempts"] = total
            if pw is not None:
                result["cracked"] = True
                result["password"] = pw
                result["content"] = text
                result["stego_results"] = [("Decrypted with dictionary attack", text)]

    # --- RAR ---
    elif ftype == "rar":
        result["encrypted"] = True
        result["method"] = "RAR cracking not supported yet"
        result["content"] = "RAR password cracking requires the 'unrar' tool. Use ZIP or PDF instead."

    # --- Unknown ---
    else:
        result["method"] = f"File type '{ftype}' — no cracking method available"

    return result