"""Password protection for hidden messages.

The message is encrypted BEFORE it is hidden. Without the password the hidden
bytes are random-looking and cannot be read. Standard library only:
PBKDF2-HMAC-SHA256 (key stretching), an HMAC-SHA256 keystream (encryption)
and an HMAC tag (so a wrong password or a changed file is detected)."""
import base64
import hashlib
import hmac
import os

PREFIX = "STGPW1:"
ITER = 200_000


def _keys(password, salt):
    k = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITER, 64)
    return k[:32], k[32:]


def _stream(key, nonce, n):
    out, i = bytearray(), 0
    while len(out) < n:
        out += hmac.new(key, nonce + i.to_bytes(8, "big"), hashlib.sha256).digest()
        i += 1
    return bytes(out[:n])


def is_sealed(text):
    return isinstance(text, str) and text.startswith(PREFIX)


def seal(text, password):
    """Encrypt text with a password. Returns plain ASCII to hide."""
    if not password:
        return text
    salt, nonce = os.urandom(16), os.urandom(16)
    ek, mk = _keys(password, salt)
    raw = text.encode("utf-8")
    ct = bytes(a ^ b for a, b in zip(raw, _stream(ek, nonce, len(raw))))
    tag = hmac.new(mk, salt + nonce + ct, hashlib.sha256).digest()[:16]
    return PREFIX + base64.b64encode(salt + nonce + ct + tag).decode("ascii")


def unseal(sealed, password):
    """Return the text, or None if the password is wrong or the data was changed."""
    try:
        blob = base64.b64decode(sealed[len(PREFIX):])
        salt, nonce, ct, tag = blob[:16], blob[16:32], blob[32:-16], blob[-16:]
        ek, mk = _keys(password, salt)
        good = hmac.new(mk, salt + nonce + ct, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, good):
            return None
        return bytes(a ^ b for a, b in zip(ct, _stream(ek, nonce, len(ct)))).decode("utf-8")
    except Exception:
        return None