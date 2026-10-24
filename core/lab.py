"""Stego Lab: attacks a freshly hidden file the way real life does, and
reports whether the hidden message survives each attack."""
import io
import os
import tempfile

from PIL import Image, ImageEnhance, ImageFilter

from core import lsb


def _same(im):
    return im, "png", {}


def _jpeg(q):
    def run(im):
        return im, "jpg", {"quality": q}
    return run


def _half(im):
    w, h = im.size
    return im.resize((max(w // 2, 1), max(h // 2, 1))).resize((w, h)), "png", {}


def _blur(im):
    return im.filter(ImageFilter.GaussianBlur(1)), "png", {}


def _crop(im):
    w, h = im.size
    return im.crop((1, 1, w, h)), "png", {}


def _bright(im):
    return ImageEnhance.Brightness(im).enhance(1.02), "png", {}


ATTACKS = [
    ("Saved again as PNG (lossless)", _same),
    ("Sent as a JPEG, quality 95", _jpeg(95)),
    ("Sent as a JPEG, quality 75 (typical for chat apps)", _jpeg(75)),
    ("Shrunk to half size and back", _half),
    ("Slightly blurred", _blur),
    ("Cropped by one pixel", _crop),
    ("Brightness changed by 2%", _bright),
]


def survival(file_bytes, secret):
    """Return [(attack name, True/False)] for a pixel-hidden image."""
    rows = []
    im = Image.open(io.BytesIO(file_bytes)).convert("RGB")
    with tempfile.TemporaryDirectory() as folder:
        for name, attack in ATTACKS:
            ok = False
            try:
                out, ext, kwargs = attack(im.copy())
                path = os.path.join(folder, "attacked." + ext)
                out.save(path, **kwargs)
                ok = (lsb.extract(path) == secret)
            except Exception:
                ok = False
            rows.append((name, ok))
    return rows