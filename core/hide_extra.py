"""Hide a message in TIFF (pixels, lossless) or PDF (after the end marker)."""
import os
import tempfile

from PIL import Image

from core import lsb

PDF_MARK = b"STG-PDF-HIDDEN:"


def hide_tiff(src, text, out):
    """Same LSB method as PNG, saved as an uncompressed TIFF (lossless)."""
    with tempfile.TemporaryDirectory() as folder:
        tmp = os.path.join(folder, "step.png")
        lsb.embed(src, text, tmp)
        Image.open(tmp).convert("RGB").save(out, format="TIFF", compression="raw")


def hide_pdf(src, text, out):
    """Append the message after the PDF's end marker; the PDF still opens."""
    with open(src, "rb") as f:
        data = f.read()
    if not data.startswith(b"%PDF-"):
        raise ValueError("This is not a valid PDF file.")
    note = PDF_MARK + b" " + text.encode("utf-8") + b"\n"
    with open(out, "wb") as f:
        f.write(data.rstrip(b"\r\n") + b"\n" + note)


def read_pdf_note(data):
    """Return the hidden note text if the PDF carries one, else None."""
    i = data.rfind(PDF_MARK)
    if i == -1 or i < data.rfind(b"%%EOF"):
        return None
    line = data[i + len(PDF_MARK):].split(b"\n")[0]
    return line.decode("utf-8", "replace").strip()