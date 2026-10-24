import json
from pathlib import Path

import numpy as np
import torch
from PIL import Image

from ml.train import StegoNet

ROOT = Path(__file__).resolve().parent.parent
PATCH = 128                 # crop size the CNN was trained on
MAX_CROPS = 64              # look at no more than this many crops per image
FLAG_SHARE = 0.25           # flag the image if this share of crops look suspicious
BATCH = 16

_cache = {}


def _load():
    """Load the trained model and its threshold once."""
    if "model" not in _cache:
        model = StegoNet()
        model.load_state_dict(torch.load(ROOT / "ml" / "model.pt"))
        model.eval()
        info = json.loads((ROOT / "ml" / "threshold.json").read_text())
        _cache["model"] = model
        _cache["threshold"] = info["threshold"]
    return _cache["model"], _cache["threshold"]


def crop_positions(width, height, max_crops=MAX_CROPS):
    """Top-left corners of 128x128 crops that tile the image (no resizing)."""
    xs = list(range(0, width - PATCH + 1, PATCH))
    ys = list(range(0, height - PATCH + 1, PATCH))
    positions = [(x, y) for y in ys for x in xs]
    if len(positions) > max_crops:                  # keep evenly spaced crops
        pick = np.linspace(0, len(positions) - 1, max_crops).astype(int)
        positions = [positions[i] for i in pick]
    return positions


def cnn_check(path):
    """Run the CNN on crops of an image and summarise the result."""
    img = Image.open(path).convert("RGB")
    positions = crop_positions(img.width, img.height)
    if not positions:
        return {"available": False,
                "reason": f"image is smaller than {PATCH}x{PATCH} pixels"}

    arr = np.array(img, dtype=np.uint8)
    crops = np.stack([arr[y:y + PATCH, x:x + PATCH] for x, y in positions])
    x = torch.from_numpy(crops.transpose(0, 3, 1, 2).copy())      # (N, 3, H, W)

    model, threshold = _load()
    scores = []
    with torch.no_grad():
        for i in range(0, len(x), BATCH):
            logits = model(x[i:i + BATCH].float())
            scores.append((logits[:, 1] - logits[:, 0]).numpy())
    scores = np.concatenate(scores)

    share = float((scores > threshold).mean())
    return {"available": True,
            "crops": len(positions),
            "flagged_share": round(share, 3),
            "mean_score": round(float(scores.mean()), 3),
            "threshold": round(float(threshold), 3),
            "suspicious": share > FLAG_SHARE}