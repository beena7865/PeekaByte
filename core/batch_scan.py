"""
PeekaByte — Batch Scanner
Upload multiple files, get a ranked suspicion table.
"""

from core.service import analyze_bytes
from core.picture_scan import find_picture, boost_report
import hashlib


def scan_batch(files):
    """
    Scan multiple files and return ranked results.

    Parameters
    ----------
    files : list of (filename, file_bytes) tuples

    Returns
    -------
    list of dict, sorted by suspicion (most suspicious first)
    """
    results = []

    for filename, data in files:
        try:
            report = analyze_bytes(data, filename)
            try:
                pic = find_picture(data)
                report = boost_report(report, pic)
            except Exception:
                pass

            # Build verdict
            verdict = report.get("verdict", "")
            if not verdict:
                statuses = [s.get("status", "").lower() for s in report.get("stages", [])]
                if any("found" in s or "fail" in s for s in statuses):
                    verdict = "Hidden data detected"
                elif any("warning" in s or "suspicious" in s for s in statuses):
                    verdict = "Suspicious"
                else:
                    verdict = "Clean"

            score = int(report.get("score", 0) or 0)
            sha = hashlib.sha256(data).hexdigest()

            # Stage summary
            stage_flags = []
            for stage in report.get("stages", []):
                s = stage.get("status", "").lower()
                if "found" in s or "fail" in s or "warning" in s or "suspicious" in s:
                    stage_flags.append(f"{stage.get('name', '?')}: {stage.get('status', '?')}")

            results.append({
                "filename": filename,
                "size": len(data),
                "sha256": sha,
                "verdict": verdict,
                "score": score,
                "flags": stage_flags,
                "flag_count": len(stage_flags),
                "report": report,
            })

        except Exception as e:
            results.append({
                "filename": filename,
                "size": len(data),
                "sha256": "",
                "verdict": f"Error: {e}",
                "score": 0,
                "flags": [],
                "flag_count": 0,
                "report": None,
            })

    # Sort: most suspicious first (by score descending, then flag count)
    results.sort(key=lambda r: (r["score"], r["flag_count"]), reverse=True)
    return results