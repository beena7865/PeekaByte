import random
import re
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from PIL import Image

DATA = Path("ml/dataset")
MODEL_PATH = Path("ml/model.pt")
EPOCHS = 15
BATCH = 32
LR = 1e-3

random.seed(0)
np.random.seed(0)
torch.manual_seed(0)


# ------------------------------------------------------------ data
def read_split(split):
    """Read every image of one split. Returns (images, labels, rates).
    labels: 0 = clean, 1 = stego. rates: share of the image filled (0 for clean)."""
    images, labels, rates = [], [], []
    for label, name in enumerate(["clean", "stego"]):
        for path in sorted((DATA / split / name).glob("*.png")):
            images.append(np.array(Image.open(path).convert("RGB"), dtype=np.uint8))
            labels.append(label)
            match = re.search(r"_r(\d{3})\.png$", path.name)
            rates.append(int(match.group(1)) / 100 if match else 0.0)
    x = np.stack(images).transpose(0, 3, 1, 2).copy()      # (N, 3, H, W)
    return x, np.array(labels), np.array(rates)


def auc_score(scores, labels):
    """Area under the ROC curve (1.0 = perfect, 0.5 = guessing)."""
    order = np.argsort(scores)
    ranks = np.empty(len(scores))
    ranks[order] = np.arange(1, len(scores) + 1)
    pos = labels == 1
    n_pos, n_neg = pos.sum(), (~pos).sum()
    return (ranks[pos].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def report(probs, labels, rates):
    """Print accuracy, AUC and the detection rate for small and large messages."""
    guess = probs > 0.5
    print(f"  accuracy: {(guess == (labels == 1)).mean():.3f}")
    print(f"  AUC:      {auc_score(probs, labels):.3f}")
    print(f"  clean images wrongly flagged: {guess[labels == 0].mean():.3f}")
    for low, high in [(0.1, 0.3), (0.3, 0.6), (0.6, 1.01)]:
        pick = (labels == 1) & (rates >= low) & (rates < high)
        if pick.sum():
            print(f"  stego found, message size {int(low*100)}-{min(int(high*100), 100)}%: "
                  f"{guess[pick].mean():.3f}  ({pick.sum()} images)")


# ------------------------------------------------------------ model
class StegoNet(nn.Module):
    def __init__(self):
        super().__init__()
        # fixed high-pass filter: removes the picture, keeps the tiny noise
        kernel = torch.tensor([[-1.,  2.,  -2.,  2., -1.],
                               [ 2., -6.,   8., -6.,  2.],
                               [-2.,  8., -12.,  8., -2.],
                               [ 2., -6.,   8., -6.,  2.],
                               [-1.,  2.,  -2.,  2., -1.]]) / 12.0
        self.highpass = nn.Conv2d(3, 3, 5, padding=2, bias=False, groups=3)
        self.highpass.weight.data = kernel.repeat(3, 1, 1, 1)    # shape (3, 1, 5, 5)
        self.highpass.weight.requires_grad_(False)

        def block(cin, cout, pool):
            layers = [nn.Conv2d(cin, cout, 3, padding=1),
                      nn.BatchNorm2d(cout), nn.ReLU()]
            if pool:
                layers.append(nn.MaxPool2d(2))
            return layers

        self.features = nn.Sequential(
            *block(3, 16, False),      # 128 x 128
            *block(16, 32, True),      # 64 x 64
            *block(32, 64, True),      # 32 x 32
            *block(64, 128, True),     # 16 x 16
        )
        self.pool = nn.AdaptiveAvgPool2d(1)
        self.classifier = nn.Linear(128, 2)

    def forward(self, x):
        x = self.highpass(x)
        x = torch.clamp(x, -3, 3)          # ignore big edges, keep small noise
        x = self.features(x)
        x = self.pool(x).flatten(1)
        return self.classifier(x)


def predict(model, x, batch=128):
    """Probability that each image contains hidden data."""
    model.eval()
    probs = []
    with torch.no_grad():
        for i in range(0, len(x), batch):
            out = model(x[i:i + batch].float())
            probs.append(torch.softmax(out, dim=1)[:, 1])
    return torch.cat(probs).numpy()


# ------------------------------------------------------------ training
def main():
    x_train, y_train, _ = read_split("train")
    x_val, y_val, _ = read_split("val")
    print(f"train: {len(x_train)} images, val: {len(x_val)} images")

    x_train, y_train = torch.from_numpy(x_train), torch.from_numpy(y_train)
    x_val = torch.from_numpy(x_val)

    model = StegoNet()
    opt = torch.optim.Adam([p for p in model.parameters() if p.requires_grad], lr=LR)
    loss_fn = nn.CrossEntropyLoss()
    best = 0.0

    for epoch in range(1, EPOCHS + 1):
        model.train()
        order = torch.randperm(len(x_train))
        total = 0.0
        for i in range(0, len(order), BATCH):
            idx = order[i:i + BATCH]
            xb, yb = x_train[idx].float(), y_train[idx]
            if random.random() < 0.5:                        # random flips / turns
                xb = torch.flip(xb, dims=[3])
            if random.random() < 0.5:
                xb = torch.flip(xb, dims=[2])
            xb = torch.rot90(xb, random.randint(0, 3), dims=[2, 3])
            opt.zero_grad()
            loss = loss_fn(model(xb), yb)
            loss.backward()
            opt.step()
            total += loss.item() * len(idx)

        val_acc = ((predict(model, x_val) > 0.5) == (y_val == 1)).mean()
        note = ""
        if val_acc > best:
            best = val_acc
            torch.save(model.state_dict(), MODEL_PATH)
            note = "  (saved)"
        print(f"epoch {epoch:2d}  loss {total / len(order):.4f}  "
              f"val accuracy {val_acc:.3f}{note}")

    # final exam on images the model has never seen
    print("\nTest results (best model):")
    model.load_state_dict(torch.load(MODEL_PATH))
    x_test, y_test, r_test = read_split("test")
    probs = predict(model, torch.from_numpy(x_test))
    report(probs, y_test, r_test)


if __name__ == "__main__":
    main()