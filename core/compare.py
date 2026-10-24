import io
import numpy as np
from PIL import Image, ImageOps

def _load(data, size=None):
    img = Image.open(io.BytesIO(data)).convert("RGB")
    if size and img.size != size:
        img = img.resize(size)
    return np.array(img).astype(np.int16)

def compare_images(original, suspect):
    out = {"ok": False, "resized": False, "percent_changed": 0.0,
          "max_channel_diff": 0, "heatmap": None, "note": ""}
    try:
        a = _load(original)
    except Exception:
        out["note"] = "The original file is not a readable image."
        return out
    try:
        b = _load(suspect, size=(a.shape[1], a.shape[0]))
    except Exception:
        out["note"] = "The suspect file is not a readable image."
        return out
    if Image.open(io.BytesIO(suspect)).convert("RGB").size != (a.shape[1], a.shape[0]):
        out["resized"] = True
    diff = np.abs(a - b)
    changed = (diff.max(axis=2) > 0)
    out["percent_changed"] = round(100 * changed.mean(), 2)
    out["max_channel_diff"] = int(diff.max())
    out["ok"] = True
    heat = np.zeros((*changed.shape, 3), dtype=np.uint8)
    scale = np.clip(diff.max(axis=2).astype(np.float32) / max(diff.max(), 1) * 255, 0, 255)
    heat[:, :, 0] = scale.astype(np.uint8)
    base = np.array(ImageOps.grayscale(Image.fromarray(a.astype(np.uint8))))
    heat[:, :, 1] = (base * 0.25).astype(np.uint8)
    heat[:, :, 2] = (base * 0.25).astype(np.uint8)
    buf = io.BytesIO()
    Image.fromarray(heat).save(buf, format="PNG")
    out["heatmap"] = buf.getvalue()
    if out["percent_changed"] == 0:
        out["note"] = "No pixels differ. These files are visually identical."
    elif out["resized"] and out["percent_changed"] > 60:
        out["note"] = ("The files are different sizes and the suspect was resized to compare, "
                       "so this percentage includes resizing softness, not just hidden data.")
    elif out["percent_changed"] < 5:
        out["note"] = ("A small, scattered set of pixels changed. This is typical of LSB "
                       "steganography, which only touches the least significant bits.")
    else:
        out["note"] = "A large portion of the image changed. This looks like more than steganography alone."
    return out