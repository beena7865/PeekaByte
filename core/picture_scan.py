"""Hidden-picture finder.

A natural photo gets smoother as you go up the bit layers: the last bit is
noise (neighbours agree about 50% of the time) and the higher bits agree more
and more. A picture hidden in the last bits breaks that rule: a low layer is
SMOOTHER than the layer above it. That is impossible for camera noise, so it
is strong evidence. The finder measures this, decides how many layers hold
the picture, and rebuilds the picture so you can read it."""
import io

import numpy as np
from PIL import Image, ImageOps

MAX_SIDE = 1200          # work on a reduced copy for speed
DROP = 0.15              # a lower layer must be this much smoother than the one above
MIN_CONTENT = 0.003      # a layer that is almost one colour carries no picture
SMOOTH_MIN = 0.65        # the smoother layer must itself be clearly smooth


def _agree(plane):
    h = (plane[:, 1:] == plane[:, :-1]).mean()
    v = (plane[1:, :] == plane[:-1, :]).mean()
    return float((h + v) / 2)


def _content(plane):
    m = float(plane.mean())
    return min(m, 1 - m)


def _png(arr):
    buf = io.BytesIO()
    Image.fromarray(arr.astype(np.uint8)).save(buf, format="PNG", compress_level=3)
    return buf.getvalue()


def find_picture(data):
    """Return {"found": bool, "layers": n, "profile": [...], "images": [(title, png)], "why": str}."""
    out = {"found": False, "layers": 0, "profile": [], "images": [], "why": ""}
    try:
        img = Image.open(io.BytesIO(data))
        fmt = img.format
        img.load()
    except Exception:
        return out
    if fmt not in ("PNG", "BMP", "TIFF", "GIF", "WEBP"):
        out["why"] = "Lossy format: bit layers are not reliable, so the picture finder was skipped."
        return out
    img = img.convert("RGB")
    arr = np.array(img)
    step = max(1, max(arr.shape[:2]) // MAX_SIDE)
    arr = arr[::step, ::step]
    if min(arr.shape[:2]) < 16:
        return out

    prof, cont = [], []
    for k in range(8):
        planes = [((arr[:, :, c] >> k) & 1) for c in range(3)]
        prof.append(round(float(np.mean([_agree(p) for p in planes])), 3))
        cont.append(float(np.mean([_content(p) for p in planes])))
    out["profile"] = prof

    top = -1
    for k in range(0, 4):                       # the picture lives in the lowest layers
        if cont[k] < MIN_CONTENT:
            continue
        if prof[k] >= SMOOTH_MIN and prof[k] - prof[k + 1] > DROP:
            top = k
    if top < 0:
        return out

    n = top + 1
    out["found"] = True
    out["layers"] = n
    out["why"] = (f"Bit layer {top + 1} (counting the last bit as layer 1) is much smoother "
                  f"({prof[top]:.2f}) than the layer above it ({prof[top + 1]:.2f}). "
                  "Camera noise never does that. A hidden picture is stored in the last "
                  f"{n} bit layer{'s' if n > 1 else ''}.")
    mask = (1 << n) - 1
    rec = ((arr.astype(np.int32) & mask) << (8 - n)).astype(np.uint8)
    gray = rec.mean(axis=2)
    out["images"] = [
        (f"Hidden picture rebuilt from the last {n} bit layer{'s' if n > 1 else ''} (colour)",
         _png(np.array(ImageOps.autocontrast(Image.fromarray(rec))))),
        ("Same picture in grey, easier to read",
         _png(np.array(ImageOps.autocontrast(Image.fromarray(gray.astype(np.uint8)))))),
    ]
    return out


def boost_report(report, pic):
    """Make the main verdict reflect a found hidden picture."""
    if not pic.get("found"):
        return report
    report["score"] = max(int(report.get("score", 0) or 0), 88)
    report["verdict"] = "Likely contains hidden data"
    stages = list(report.get("stages", []))
    stages.append({"name": "Hidden picture finder", "status": "suspicious",
                   "summary": f"a picture is stored in the last {pic['layers']} bit layer(s)",
                   "details": [pic["why"],
                               "smoothness of bit layers 1 to 8: " +
                               ", ".join(f"{v:.2f}" for v in pic["profile"])]})
    report["stages"] = stages
    notes = list(report.get("notes", []))
    notes.append("A hidden picture was found. It is shown below under 'Hidden picture'.")
    report["notes"] = notes
    return report