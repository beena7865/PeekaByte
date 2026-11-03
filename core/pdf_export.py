"""
PeekaByte - PDF Report Generator
Builds a styled PDF from the analysis results stored in session_state.
"""

from fpdf import FPDF
from datetime import datetime
import hashlib
import os
import tempfile

def safe(text):
    """Replace Unicode characters that Helvetica cannot print."""
    text = (str(text)
            .replace("\u2014", "-")
            .replace("\u2013", "-")
            .replace("\u2018", "'")
            .replace("\u2019", "'")
            .replace("\u201c", '"')
            .replace("\u201d", '"')
            .replace("\u2026", "...")
            .replace("\u00b0", " deg"))
    return text.encode("ascii", "ignore").decode("ascii")

class PeekaBytePDF(FPDF):

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=25)
        # Candy/pastel palette
        self.PINK = (255, 182, 193)
        self.LAVENDER = (200, 180, 230)
        self.MINT = (152, 224, 196)
        self.DARK = (60, 60, 80)
        self.RED = (220, 80, 80)
        self.GREEN = (80, 180, 120)
        self.ORANGE = (240, 160, 60)
        self.GRAY = (140, 140, 140)

    def header(self):
        self.set_fill_color(*self.PINK)
        self.rect(0, 0, 210, 18, "F")
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*self.DARK)
        self.set_y(4)
        self.cell(0, 10, "PeekaByte  -  Steganography Analysis Report", align="C")
        self.ln(16)

    def footer(self):
        self.set_y(-20)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*self.GRAY)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        self.cell(0, 10, f"PeekaByte Report  |  Page {self.page_no()}/{{nb}}  |  {stamp}", align="C")

    def section(self, title):
        self.set_font("Helvetica", "B", 12)
        self.set_fill_color(*self.LAVENDER)
        self.set_text_color(*self.DARK)
        self.cell(0, 9, f"  {title}", ln=True, fill=True)
        self.ln(3)

    def row(self, label, value, color=None):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*self.DARK)
        self.cell(60, 7, f"  {label}:")
        self.set_font("Helvetica", "", 10)
        if color:
            self.set_text_color(*color)
        self.cell(0, 7, safe(str(value))[:120], ln=True)
        self.set_text_color(*self.DARK)

    def verdict_box(self, text):
        t = text.upper()
        if "CLEAN" in t or "SAFE" in t or "NO " in t:
            color = self.GREEN
        elif "SUSPICIOUS" in t or "WARNING" in t:
            color = self.ORANGE
        else:
            color = self.RED
        self.set_font("Helvetica", "B", 14)
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.cell(0, 12, f"  VERDICT:  {t}", ln=True, fill=True)
        self.set_text_color(*self.DARK)
        self.ln(4)

    def add_pil_image(self, pil_img, w=90):
        if self.get_y() > 220:
            self.add_page()
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            pil_img.save(f, format="PNG")
            path = f.name
        try:
            self.image(path, x=10, w=w)
            self.ln(5)
        finally:
            os.unlink(path)

    def add_bytes_image(self, img_bytes, w=90):
        if self.get_y() > 220:
            self.add_page()
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(img_bytes)
            path = f.name
        try:
            self.image(path, x=10, w=w)
            self.ln(5)
        finally:
            os.unlink(path)


def build_pdf(filename, filesize, report, meta=None, pic=None,
              png_check=None, deep=None):
    """
    Build the full analysis PDF.

    Parameters
    ----------
    filename  : str           - original file name
    filesize  : int           - file size in bytes
    report    : dict          - from analyze_bytes(), has "stages", "verdict", etc.
    meta      : dict or None  - from read_metadata()
    pic       : dict or None  - from find_picture()
    png_check : dict or None  - from check_png()
    deep      : dict or None  - from deep_scan()

    Returns
    -------
    bytes : the PDF content
    """
    pdf = PeekaBytePDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    # ---- Overall verdict ----
    overall = report.get("verdict", "")
    if not overall:
        # Build verdict from stages
        statuses = [s.get("status", "").lower() for s in report.get("stages", [])]
        if any("found" in s or "fail" in s for s in statuses):
            overall = "Hidden data detected"
        elif any("warning" in s or "suspicious" in s for s in statuses):
            overall = "Suspicious"
        else:
            overall = "Clean"
    pdf.verdict_box(overall)

    # ---- File info ----
    pdf.section("File Information")
    pdf.row("Filename", filename)
    if filesize > 1_048_576:
        size_str = f"{filesize:,} bytes ({filesize / 1_048_576:.2f} MB)"
    elif filesize > 1024:
        size_str = f"{filesize:,} bytes ({filesize / 1024:.1f} KB)"
    else:
        size_str = f"{filesize:,} bytes"
    pdf.row("File Size", size_str)
    pdf.row("Scan Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    pdf.ln(3)

    # ---- Analysis stages ----
    stages = report.get("stages", [])
    if stages:
        pdf.section("Analysis Results")
        for stage in stages:
            name = stage.get("name", "Unknown")
            status = stage.get("status", "-")
            summary = stage.get("summary", "")
            # Pick color based on status
            s_low = status.lower()
            if "found" in s_low or "fail" in s_low:
                color = pdf.RED
            elif "warning" in s_low or "suspicious" in s_low:
                color = pdf.ORANGE
            elif "clean" in s_low or "pass" in s_low or "ok" in s_low:
                color = pdf.GREEN
            else:
                color = pdf.DARK
            pdf.row(name, f"{status} - {summary}" if summary else status, color)
        pdf.ln(3)

    # ---- Deep scan ----
    if deep:
        pdf.section("Deep Scan")
        if deep.get("note"):
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, f"  {safe(deep['note'])}")
        elif deep.get("leads"):
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, f"  Found {len(deep['leads'])} possible hidden content fragment(s).")
            for where, text in deep["leads"]:
                preview = safe(text[:200].replace("\n", " "))
                pdf.row(f"Source: {safe(where)}", preview)
        else:
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, "  No readable text or hidden file found in common bit layouts.")
        # Add bit-plane images
        if deep.get("images"):
            pdf.ln(2)
            pdf.set_font("Helvetica", "I", 9)
            pdf.cell(0, 6, "  Bit-plane visualizations:", ln=True)
            for title, img_data in deep["images"][:4]:  # max 4 to keep PDF size down
                pdf.set_font("Helvetica", "", 8)
                pdf.cell(0, 5, f"    {title}", ln=True)
                try:
                    pdf.add_bytes_image(img_data, w=80)
                except Exception:
                    pass
        pdf.ln(3)

    # ---- Hidden picture ----
    if pic and pic.get("found"):
        pdf.section("Hidden Picture Detected")
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, f"  {safe(pic.get('why', 'A hidden image was found in the bit planes.'))}")
        for title, img_data in pic.get("images", [])[:2]:
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(0, 5, f"    {title}", ln=True)
            try:
                pdf.add_bytes_image(img_data, w=100)
            except Exception:
                pass
        pdf.ln(3)

    # ---- PNG check ----
    if png_check:
        pdf.section("PNG Structure Check")
        if png_check.get("ok"):
            pdf.row("Status", "Valid - signature, chunks and CRCs are correct", pdf.GREEN)
        else:
            pdf.row("Status", "Problems found", pdf.RED)
            for p in png_check.get("problems", []):
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(5)
                pdf.multi_cell(0, 6, f"- {p}")
        pdf.ln(3)

    # ---- Metadata / EXIF ----
    if meta:
        pdf.section("EXIF Metadata")
        if meta.get("note") and not meta.get("tags") and not meta.get("gps"):
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, f"  {safe(meta['note'])}")
        if meta.get("gps"):
            g = meta["gps"]
            pdf.row("GPS Location", f"{g['lat']}, {g['lon']}")
            pdf.row("Google Maps", g.get("maps_url", "N/A"))
        if meta.get("tags"):
            for tag_name, tag_value in meta["tags"]:
                pdf.row(str(tag_name), str(tag_value)[:100])
        pdf.ln(3)

    # ---- Footer disclaimer ----
    pdf.ln(5)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*pdf.GRAY)
    pdf.multi_cell(0, 5,
        "This report was generated by PeekaByte Steganography Analyzer. "
        "Results are based on statistical analysis and may need expert review. "
        "For educational and forensic research purposes.")

    return bytes(pdf.output())

def export_any_tab(tab_name, filename, data_dict):
    """
    Universal PDF export for any tab.
    
    tab_name: str - "Forensics", "Compare", "Decrypt", "QR Scanner", etc.
    filename: str - uploaded file name
    data_dict: dict - key-value pairs to display
    """
    pdf = PeekaBytePDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.section(f"PeekaByte - {tab_name} Report")
    pdf.row("Source File", safe(filename))

    from datetime import datetime
    pdf.row("Report Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    pdf.ln(3)

    for key, value in data_dict.items():
      try:
        if key.startswith("__section__"):
            pdf.section(safe(str(value)))
        elif key.startswith("__error__"):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_x(10)
            pdf.multi_cell(0, 6, safe("Warning: " + str(value))[:200])
        elif key.startswith("__success__"):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_x(10)
            pdf.multi_cell(0, 6, safe("Result: " + str(value))[:200])
        elif key.startswith("__warning__"):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_x(10)
            pdf.multi_cell(0, 6, safe("Alert: " + str(value))[:200])
        elif key.startswith("__list__"):
            items = value if isinstance(value, list) else [value]
            for item in items:
                pdf.set_font("Helvetica", "", 9)
                pdf.set_x(10)
                pdf.multi_cell(0, 6, safe(f"  - {item}")[:200])
        elif key.startswith("__space__"):
            pdf.ln(4)
        else:
            pdf.set_font("Helvetica", "", 10)
            pdf.set_x(10)
            pdf.multi_cell(0, 6, safe(str(key) + ": " + str(value))[:250])
      except Exception:
            continue

    pdf.ln(5)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*pdf.GRAY)
    pdf.multi_cell(0, 5, "Generated by PeekaByte v1.0 - Steganography Detection & Digital Forensics Toolkit")

    return bytes(pdf.output())