import os
import tempfile

from core import audio, dct, lsb, hide_extra
from core.full_scan import full_analyze


def _write_temp(data, filename, folder):
    path = os.path.join(folder, os.path.basename(filename) or "upload")
    with open(path, "wb") as f:
        f.write(data)
    return path


def hide_message(data, filename, text):
    """Hide text in an uploaded image or WAV. Returns (bytes, download_name)."""
    if not text.strip():
        raise ValueError("Please type a message to hide.")
    stem, ext = os.path.splitext(os.path.basename(filename))
    ext = ext.lower()
    with tempfile.TemporaryDirectory() as folder:
        src = _write_temp(data, "input" + ext, folder)
        if ext == ".wav":
            out_name = stem + "_stego.wav"
            out = os.path.join(folder, out_name)
            audio.embed_audio(src, text, out)
        elif ext in (".jpg", ".jpeg"):
            out_name = stem + "_stego.jpg"
            out = os.path.join(folder, out_name)
            try:
                dct.embed_jpeg(src, text, out)    # hides in the JPEG coefficients
            except dct.JpegError:
                out_name = stem + "_stego.png"    # progressive or huge JPEG: use PNG
                out = os.path.join(folder, out_name)
                lsb.embed(src, text, out)
        elif ext in (".png", ".bmp", ".webp", ".gif"):
            out_name = stem + "_stego.png"        # always lossless PNG
            out = os.path.join(folder, out_name)
            lsb.embed(src, text, out)
        elif ext in (".tif", ".tiff"):
            out_name = stem + "_stego.tiff"
            out = os.path.join(folder, out_name)
            hide_extra.hide_tiff(src, text, out)
        elif ext == ".pdf":
            out_name = stem + "_stego.pdf"
            out = os.path.join(folder, out_name)
            hide_extra.hide_pdf(src, text, out)
        else:
            raise ValueError("Please upload a PNG, JPG, BMP, WEBP, GIF or WAV file.")
        with open(out, "rb") as f:
            return f.read(), out_name


def analyze_bytes(data, filename):
    """Analyze an uploaded file and return the report dictionary."""
    with tempfile.TemporaryDirectory() as folder:
        path = _write_temp(data, filename, folder)
        return full_analyze(path)