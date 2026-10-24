"""
PeekaByte — Case Manager
Group scanned files under named cases.
Stored in a JSON file at D:\stego-project\cases.json
"""

import json
import os
from datetime import datetime

CASES_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cases.json")


def _load():
    """Load cases from disk."""
    if not os.path.exists(CASES_PATH):
        return {"cases": []}
    with open(CASES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data):
    """Write cases to disk."""
    with open(CASES_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def create_case(name, description=""):
    """Create a new case. Returns the case ID."""
    data = _load()
    case_id = f"CASE-{len(data['cases']) + 1:03d}"
    case = {
        "id": case_id,
        "name": name,
        "description": description,
        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "files": [],
    }
    data["cases"].append(case)
    _save(data)
    return case_id


def list_cases():
    """Return all cases, newest first."""
    data = _load()
    return list(reversed(data["cases"]))


def get_case(case_id):
    """Return a single case by ID, or None."""
    data = _load()
    for case in data["cases"]:
        if case["id"] == case_id:
            return case
    return None


def add_file_to_case(case_id, filename, file_size, sha256, verdict, stages_summary):
    """Add a scanned file entry to a case."""
    data = _load()
    for case in data["cases"]:
        if case["id"] == case_id:
            entry = {
                "filename": filename,
                "file_size": file_size,
                "sha256": sha256,
                "verdict": verdict,
                "stages_summary": stages_summary,
                "scanned": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            case["files"].append(entry)
            _save(data)
            return True
    return False


def delete_case(case_id):
    """Delete a case by ID."""
    data = _load()
    data["cases"] = [c for c in data["cases"] if c["id"] != case_id]
    _save(data)


def case_names_for_dropdown():
    """Return a list of 'ID - Name' strings for a dropdown, plus 'No case' option."""
    cases = list_cases()
    options = ["No case (standalone scan)"]
    for c in cases:
        options.append(f"{c['id']} - {c['name']}")
    return options