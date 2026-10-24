import json
from pathlib import Path

import numpy as np
import torch

from train import MODEL_PATH, StegoNet, auc_score, read_split

THRESHOLD_PATH = Path("ml/threshold.json")
MAX_FPR = 0.10          # allow about 10% of clean images to be flagged


def scores(model, x, batch=128):
    """Raw model score: higher means more likely to contain hidden data."""
    model.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(x), batch):
            logits = model(x[i:i + batch].float())
            out.append(logits[:, 1] - logits[:, 0])
    return torch.cat(out).numpy()


def pick_threshold(values, labels, max_fpr):
    """Threshold that flags at most about max_fpr of the clean images."""
    return float(np.quantile(values[labels == 0], 1 - max_fpr))


def show(values, labels, rates, threshold):
    flagged = values > threshold
    print(f"  accuracy: {(flagged == (labels == 1)).mean():.3f}")
    print(f"  clean images wrongly flagged: {flagged[labels == 0].mean():.3f}")
    print(f"  stego images found: {flagged[labels == 1].mean():.3f}")
    for low, high in [(0.1, 0.3), (0.3, 0.6), (0.6, 1.01)]:
        pick = (labels == 1) & (rates >= low) & (rates < high)
        if pick.sum():
            print(f"  message size {int(low * 100)}-{min(int(high * 100), 100)}%: "
                  f"found {flagged[pick].mean():.3f}")


def main():
    model = StegoNet()
    model.load_state_dict(torch.load(MODEL_PATH))

    x_val, y_val, r_val = read_split("val")
    val_scores = scores(model, torch.from_numpy(x_val))
    threshold = pick_threshold(val_scores, y_val, MAX_FPR)
    print(f"chosen threshold: {threshold:.3f}  (the old default was 0.0)")

    x_test, y_test, r_test = read_split("test")
    test_scores = scores(model, torch.from_numpy(x_test))
    print("\nTest results with the old threshold (0.0):")
    show(test_scores, y_test, r_test, 0.0)
    print("\nTest results with the new threshold:")
    show(test_scores, y_test, r_test, threshold)
    print(f"\nAUC: {auc_score(test_scores, y_test):.3f}")

    THRESHOLD_PATH.write_text(json.dumps({"threshold": threshold}))
    print("Saved", THRESHOLD_PATH)


if __name__ == "__main__":
    main()