"""
PeekaByte — Audit Log
Saves one row per scan: filename, time, verdict, file size, file hash.
Stored in a CSV file at D:\stego-project\scan_history.csv
"""

import csv
import os
import hashlib
from datetime import datetime

LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scan_history.csv")
COLUMNS = ["timestamp", "filename", "file_size", "sha256", "verdict", "stages_summary"]


def _ensure_file():
    """Create the CSV with headers if it does not exist yet."""
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(COLUMNS)


def log_scan(filename, file_size, file_bytes, report):
    """
    Append one row to the audit log.

    Parameters
    ----------
    filename   : str   — original file name
    file_size  : int   — size in bytes
    file_bytes : bytes — raw file content (used to compute hash)
    report     : dict  — from analyze_bytes(), has "stages" and optionally "verdict"
    """
    _ensure_file()

    sha = hashlib.sha256(file_bytes).hexdigest()

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

    # One-line summary of all stages
    parts = []
    for stage in report.get("stages", []):
        name = stage.get("name", "?")
        status = stage.get("status", "?")
        parts.append(f"{name}: {status}")
    summary = " | ".join(parts)

    row = [
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        filename,
        file_size,
        sha,
        verdict,
        summary,
    ]

    with open(LOG_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(row)


def read_log():
    """
    Read all log entries.

    Returns
    -------
    list of dict — each dict has keys matching COLUMNS, newest first
    """
    _ensure_file()
    rows = []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    rows.reverse()  # newest first
    return rows


def clear_log():
    """Delete all log entries (keeps the header)."""
    with open(LOG_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(COLUMNS)