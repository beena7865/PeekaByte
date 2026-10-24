from core.analyzer import analyze
from core.carve import carve
from core.extra_formats import check_extra

OLD = "Unsupported or unknown file type"


def _relabel(obj, new_text):
    """Walk the report and replace the old 'unsupported' wording."""
    if isinstance(obj, str):
        return obj.replace(OLD, new_text)
    if isinstance(obj, list):
        return [_relabel(x, new_text) for x in obj]
    if isinstance(obj, dict):
        return {k: _relabel(v, new_text) for k, v in obj.items()}
    return obj

def _relabel_text(obj, old, new):
    if isinstance(obj, str):
        return obj.replace(old, new)
    if isinstance(obj, list):
        return [_relabel_text(x, old, new) for x in obj]
    if isinstance(obj, tuple):
        return tuple(_relabel_text(x, old, new) for x in obj)
    if isinstance(obj, dict):
        return {k: _relabel_text(v, old, new) for k, v in obj.items()}
    return obj

def full_analyze(path):
    """Normal analysis + real-text search + TIFF/PDF/HEIC support."""
    try:
        report = analyze(path)
    except Exception:
        report = {"file": path, "type": "unknown", "size": 0, "stages": [],
                  "hidden_message": None, "score": 0,
                  "verdict": "No strong evidence", "notes": []}

    data = open(path, "rb").read()
    kind, extra_hits, extra_notes = check_extra(data)

    hits = carve(path) + extra_hits
    report["carved"] = hits

    if kind:
        report = _relabel(report, f"{kind.upper()} file: checked by the extra-format module")
        report["type"] = kind
        if kind in ("pdf", "heic"):
            why = ("a PDF has no pixels; its structure was checked instead"
                   if kind == "pdf" else
                   "HEIC pixels are lossy; structure, metadata and appended data were checked instead")
            for old in ("not applicable to this file type",
                        "not applicable (lossy or palette format)",
                        "not applicable (lossy, palette or audio)"):
                report = _relabel_text(report, old, why)

    real = [h for h in hits if not h["text"].startswith("(")]
    other = [h for h in hits if h["text"].startswith("(")]

    if real and not report.get("hidden_message"):
        report["hidden_message"] = real[0]["text"]
        report["score"] = max(report.get("score", 0), 90)
        report["verdict"] = "Likely contains hidden data"
    elif other and report.get("score", 0) < 60:
        report["score"] = max(report.get("score", 0), 60)
        report["verdict"] = "Likely contains hidden data"

    notes = report.get("notes")
    if not isinstance(notes, list):
        notes = []
    for h in hits:
        notes.append(f"Found via {h['where']}: {h['text']}")
    notes.extend(extra_notes)
    report["notes"] = notes
    return report