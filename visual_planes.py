import sys
import numpy as np
from PIL import Image

a = np.array(Image.open(sys.argv[1]).convert("RGBA"))
for i, name in enumerate("RGBA"):
    for plane in range(3):
        img = ((a[:, :, i] >> plane) & 1).astype(np.uint8) * 255
        Image.fromarray(img).save(f"plane_{name}{plane}.png")
print("Saved plane_R0.png ... plane_A2.png in this folder")