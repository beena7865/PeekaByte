from pathlib import Path

from core import audio, dct, lsb
from core.file_checks import run_file_checks
from core.formats import check_format

LOSSLESS_IMAGES = {"png", "bmp", "tiff"}       # webp is checked separately (lossless only)


def _stage(name, status, summary, details=None):
    return {"name": name, "status": status, "summary": summary,
            "details": details or []}


def _status_from(findings):
    levels = [level for level, _ in findings]
    if "suspicious" in levels:
        return "suspicious"
    return "warning" if "warning" in levels else "ok"


# ----------------------------------------------------------- stage 1
def stage_file_level(path):
    r = run_file_checks(path)
    status = _status_from(r["findings"])
    summary = {"ok": "nothing unusual",
               "warning": "something unusual",
               "suspicious": "extra data found in the file"}[status]
    points = {"ok": 0, "warning": 10, "suspicious": 60}[status]
    return (_stage("File-level checks", status, summary,
                   [m for _, m in r["findings"]]), points, r["type"], r["size"])


# ----------------------------------------------------------- stage 2
def stage_format(path, already_suspicious):
    r = check_format(path)
    status = _status_from(r["findings"])
    summary = {"ok": "structure looks normal",
               "warning": "unusual parts in the structure",
               "suspicious": "suspicious data in the structure"}[status]
    points = {"ok": 0, "warning": 10, "suspicious": 0 if already_suspicious else 60}[status]
    if any("Comment segment" in m for _, m in r["findings"]):
        points = max(points, 35)       # a comment can hold a hidden note
    details = [m for _, m in r["findings"]]
    if r["layout"]:
        details.append("layout: " + ", ".join(r["layout"][:12]))
    return _stage(f"Format checks ({r['type'].upper()})", status, summary, details), points, r


# ----------------------------------------------------------- stage 3
def stage_extract(path, real_type, lossless):
    if real_type == "wav":
        message = audio.extract_audio(path)
    elif lossless:
        message = lsb.extract(path)
    else:
        return _stage("Hidden-message extraction", "skipped",
                      "not applicable to this file type"), 0, None
    if message is None:
        return _stage("Hidden-message extraction", "ok",
                      "no message in this tool's format"), 0, None
    return (_stage("Hidden-message extraction", "suspicious",
                   f"hidden message found ({len(message)} characters)",
                   [message[:200] + ("..." if len(message) > 200 else "")]),
            100, message)


# ----------------------------------------------------------- stage 4
def stage_lsb_analysis(path, real_type, lossless):
    if real_type == "wav":
        looks_text = audio.audio_looks_like_text(path)
        details = ["readable text in the last bits: " + ("yes" if looks_text else "no"),
                   "note: statistics are not reliable for audio, so only the text test is used"]
        status = "suspicious" if looks_text else "ok"
        return (_stage("LSB analysis", status,
                       "readable text in the last bits" if looks_text else "nothing found",
                       details), 50 if looks_text else 0)
    if not lossless:
        return _stage("LSB analysis", "skipped",
                      "not applicable (lossy or palette format)"), 0

    looks_text = lsb.lsb_looks_like_text(path)
    agreement = lsb.lsb_agreement(path)
    chi = lsb.chi_square_score(path)
    points, notes = 0, []
    details = [f"readable text in the last bits: {'yes' if looks_text else 'no'}",
               f"neighbour agreement of last bits: {agreement:.3f} (about 0.5 = random)",
               f"chi-square score: {chi:.3f} (near 1 = suspiciously even)"]
    if looks_text:
        points += 50
        notes.append("readable text")
    if agreement < 0.52:
        points += 10          # weak signal: many clean photos look like this too
        notes.append("last bits look random (weak signal)")
    if chi > 0.5:
        points += 15
        notes.append("chi-square even")
    status = "suspicious" if looks_text else ("warning" if points >= 15 else "ok")
    summary = ", ".join(notes) if notes else "nothing found"
    return _stage("LSB analysis", status, summary, details), points


# ----------------------------------------------------------- JPEG stage
def stage_jpeg_dct(path):
    """DCT-coefficient analysis. Returns (extraction stage, dct stage, points, message)."""
    name = "DCT analysis (JPEG)"
    try:
        r = dct.dct_check(path)
    except Exception as error:
        r = {"available": False, "reason": str(error)[:150]}
    if not r["available"]:
        return (_stage("Hidden-message extraction", "skipped", "could not read JPEG coefficients"),
                _stage(name, "skipped", r["reason"]), 0, None)

    message = r["message"]
    if message is None:
        extraction = _stage("Hidden-message extraction", "ok",
                            "no message in this tool's format")
    else:
        extraction = _stage("Hidden-message extraction", "suspicious",
                            f"hidden message found ({len(message)} characters)",
                            [message[:200] + ("..." if len(message) > 200 else "")])

    u = r["uniformity"]
    details = [f"usable coefficients: {r['usable']:,} (of {r['coefficients']:,})",
               f"readable text in the coefficient last bits: {'yes' if r['looks_text'] else 'no'}"]
    if u is None:
        details.append("histogram test skipped: " + r["histogram_skipped"])
    else:
        details.append(f"histogram uniformity: {u} (natural JPEGs score 7 or more, "
                       "last bits overwritten by a message score about 1)")
    points, notes = 0, []
    if message is not None:
        points += 100
    if r["looks_text"]:
        points += 50
        notes.append("readable text")
    if u is not None and u < 3:
        points += 60
        notes.append("coefficient histogram looks overwritten")
    elif u is not None and u < 5:
        points += 35
        notes.append("coefficient histogram looks partly overwritten")
    status = "suspicious" if (message is not None or r["looks_text"] or (u is not None and u < 3)) else (
        "warning" if (u is not None and u < 5) else "ok")
    if notes:
        summary = ", ".join(notes)
    elif u is None:
        summary = "histogram test not applicable to this file"
    else:
        summary = "histogram looks natural"
    return extraction, _stage(name, status, summary, details), points, message


# ----------------------------------------------------------- stage 5
def stage_cnn(path, lossless):
    name = "Machine learning (CNN)"
    if not lossless:
        return _stage(name, "skipped", "not applicable (lossy, palette or audio)"), 0
    try:
        from core.ml_detector import cnn_check
        r = cnn_check(path)
    except Exception as error:
        return _stage(name, "skipped", "model not available", [str(error)[:150]]), 0
    if not r["available"]:
        return _stage(name, "skipped", r["reason"]), 0
    details = [f"crops checked: {r['crops']}",
               f"share of crops flagged: {r['flagged_share']:.0%}",
               f"mean score: {r['mean_score']} (threshold {r['threshold']})"]
    if r["suspicious"]:
        points = 50 if r["flagged_share"] > 0.6 else 40
        return _stage(name, "suspicious",
                      f"{r['flagged_share']:.0%} of crops look like stego", details), points
    return _stage(name, "ok", f"{r['flagged_share']:.0%} of crops flagged (below the alarm level)", details), 0


# ----------------------------------------------------------- main
def analyze(path):
    path = str(path)
    stages, score = [], 0

    s1, p1, real_type, size = stage_file_level(path)
    stages.append(s1)
    score += p1

    s2, p2, fmt = stage_format(path, s1["status"] == "suspicious")
    stages.append(s2)
    score += p2

    lossless = real_type in LOSSLESS_IMAGES or (
        real_type == "webp" and "VP8L" in fmt["layout"])

    notes = []
    if real_type == "jpg":
        s3, s_dct, p_dct, message = stage_jpeg_dct(path)
        stages.append(s3)
        stages.append(_stage("LSB analysis", "skipped",
                             "not applicable to JPEG (see DCT analysis)"))
        stages.append(s_dct)
        stages.append(_stage("Machine learning (CNN)", "skipped",
                             "not applicable (lossy, palette or audio)"))
        score += p_dct
        notes.append("JPEG: pixel LSB tests do not apply (compression rewrites the pixels), "
                     "so the hidden-data tests run on the DCT coefficients instead. "
                     "Only baseline JPEG files up to about 8 megapixels can be analysed.")
    else:
        s3, p3, message = stage_extract(path, real_type, lossless)
        stages.append(s3)
        score += p3
        for stage_fn in (lambda: stage_lsb_analysis(path, real_type, lossless),
                         lambda: stage_cnn(path, lossless)):
            try:
                stage, points = stage_fn()
            except Exception as error:
                stage, points = _stage("Analysis step", "error", str(error)[:150]), 0
            stages.append(stage)
            score += points
    score = min(score, 100)
    if message is not None or score >= 60:
        verdict = "Likely contains hidden data"
    elif score >= 30:
        verdict = "Suspicious - needs a closer look"
    else:
        verdict = "No strong evidence of hidden data"

    return {"file": Path(path).name, "type": real_type, "size": size,
            "stages": stages, "hidden_message": message, "score": score,
            "verdict": verdict, "notes": notes}


def format_report(r):
    """Turn a report into plain text."""
    lines = [f"File: {r['file']}  |  type: {r['type']}  |  {r['size']:,} bytes", ""]
    for s in r["stages"]:
        lines.append(f"[{s['status'].upper():10s}] {s['name']}: {s['summary']}")
        for d in s["details"]:
            lines.append(f"      - {d}")
    for n in r["notes"]:
        lines.append(f"NOTE: {n}")
    lines.append("")
    if r["hidden_message"] is not None:
        lines.append(f"Hidden message: {r['hidden_message'][:200]!r}")
    lines.append(f"Score: {r['score']}/100  ->  {r['verdict']}")
    return "\n".join(lines)