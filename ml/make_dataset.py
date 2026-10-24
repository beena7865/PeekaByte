import io
import random
import shutil
from pathlib import Path

import numpy as np
from PIL import Image, ImageFilter

RAW = Path("ml/dataset/raw")        # put your photos here
OUT = Path("ml/dataset")            # train/val/test folders are made here
PATCH = 128                         # size of each small training image
PATCHES_PER_PHOTO = 20              # how many crops to take from each photo
MAX_SIDE = 512                      # shrink very large photos first
SPLITS = {"train": 0.70, "val": 0.15, "test": 0.15}
EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}

random.seed(42)
rng = np.random.default_rng(42)


def load_photo(path):
    img = Image.open(path).convert("RGB")
    scale = MAX_SIDE / max(img.size)
    if scale < 1:                                   # shrink big photos
        img = img.resize((round(img.width * scale), round(img.height * scale)),
                         Image.LANCZOS)
    return img


def random_patch(img):
    x = random.randint(0, img.width - PATCH)
    y = random.randint(0, img.height - PATCH)
    return np.array(img.crop((x, y, x + PATCH, y + PATCH)), dtype=np.uint8)


def degrade(patch):
    """Make a sharp photo look more like a poor real-world photo.
    This is applied BEFORE hiding data, so the clean and stego images
    stay a matched pair."""
    img = Image.fromarray(patch)
    if random.random() < 0.4:                       # blur
        img = img.filter(ImageFilter.GaussianBlur(random.uniform(0.5, 2.0)))
    if random.random() < 0.3:                       # soft, low resolution
        small = random.choice([64, 80, 96])
        img = img.resize((small, small), Image.BILINEAR)
        img = img.resize((PATCH, PATCH), Image.BILINEAR)
    if random.random() < 0.4:                       # JPEG compression damage
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=random.randint(30, 90))
        buf.seek(0)
        img = Image.open(buf).convert("RGB")
    arr = np.array(img, dtype=np.float32)
    if random.random() < 0.4:                       # camera noise
        arr += rng.normal(0, random.uniform(1, 6), arr.shape)
    if random.random() < 0.4:                       # darker / brighter / contrast
        arr = (arr - 128) * random.uniform(0.7, 1.3) + 128 + random.uniform(-40, 40)
    if random.random() < 0.1:                       # black and white photo
        arr[:] = arr.mean(axis=2, keepdims=True)
    return np.clip(arr, 0, 255).round().astype(np.uint8)


def make_stego(patch):
    """Hide a random message in the last bits. Returns (new array, rate)."""
    flat = patch.flatten().copy()
    rate = rng.uniform(0.1, 1.0)                    # share of values that carry data
    n = int(len(flat) * rate)
    bits = rng.integers(0, 2, n, dtype=np.uint8)
    if rng.random() < 0.5:
        positions = np.arange(n)                    # like our encoder: from the start
    else:
        positions = rng.choice(len(flat), n, replace=False)   # scattered around
    flat[positions] = (flat[positions] & 0xFE) | bits
    return flat.reshape(patch.shape), rate


def main():
    photos = sorted(p for p in RAW.iterdir() if p.suffix.lower() in EXTS)
    if len(photos) < 10:
        print(f"Found only {len(photos)} photos in {RAW}. Add at least 50.")
        return

    for split in SPLITS:                            # start fresh each time
        shutil.rmtree(OUT / split, ignore_errors=True)

    # split by PHOTO, so crops of one photo never land in two splits
    random.shuffle(photos)
    n_train = int(len(photos) * SPLITS["train"])
    n_val = int(len(photos) * SPLITS["val"])
    groups = {"train": photos[:n_train],
              "val": photos[n_train:n_train + n_val],
              "test": photos[n_train + n_val:]}

    for split, files in groups.items():
        for label in ("clean", "stego"):
            (OUT / split / label).mkdir(parents=True, exist_ok=True)
        count = 0
        for photo in files:
            try:
                img = load_photo(photo)
            except Exception as error:
                print("Skipped", photo.name, "-", error)
                continue
            if img.width < PATCH or img.height < PATCH:
                print("Skipped (too small):", photo.name)
                continue
            for k in range(PATCHES_PER_PHOTO):
                patch = degrade(random_patch(img))
                stego, rate = make_stego(patch)
                name = f"{photo.stem}_{k:02d}"
                Image.fromarray(patch).save(OUT / split / "clean" / f"{name}.png")
                Image.fromarray(stego).save(
                    OUT / split / "stego" / f"{name}_r{int(rate * 100):03d}.png")
                count += 1
        print(f"{split}: {len(files)} photos -> {count} clean + {count} stego images")


if __name__ == "__main__":
    main()