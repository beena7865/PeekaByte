import sys
from core.full_scan import full_analyze

for f in sys.argv[1:]:
    r = full_analyze(f)
    hits = r.get("carved", [])
    print(f"\n=== {f}   ({r.get('type')})")
    if not hits:
        print("No readable hidden text found.")
    for h in hits:
        print(f"[{h['where']}]\n   {h['text']}")