import numpy as np
from PIL import Image

MAGIC = b"STG1"   # a marker that says "a hidden message starts here"


def text_to_bits(text):
    """Turn a string into a list of 0s and 1s."""
    data = text.encode("utf-8")        # text -> bytes
    bits = []
    for byte in data:
        for ch in format(byte, "08b"): # byte -> "01001000"
            bits.append(int(ch))       # "0" -> 0, "1" -> 1
    return bits


def bits_to_text(bits):
    """Turn a list of 0s and 1s back into a string."""
    data = bytearray()
    for i in range(0, len(bits), 8):   # take 8 bits at a time
        value = 0
        for bit in bits[i:i + 8]:
            value = value * 2 + bit    # build the number from its bits
        data.append(value)
    return data.decode("utf-8", errors="replace")

def bytes_to_bits(data):
    """Turn bytes into a list of 0s and 1s."""
    bits = []
    for byte in data:
        for ch in format(byte, "08b"):
            bits.append(int(ch))
    return bits


def bits_to_bytes(bits):
    """Turn a list of 0s and 1s back into bytes."""
    data = bytearray()
    for i in range(0, len(bits) - len(bits) % 8, 8):
        value = 0
        for bit in bits[i:i + 8]:
            value = value * 2 + bit
        data.append(value)
    return bytes(data)


def embed(image_path, text, out_path):
    """Hide text inside an image and save it (PNG, BMP or lossless WebP)."""
    img = Image.open(image_path).convert("RGB")
    pixels = np.array(img, dtype=np.uint8)
    flat = pixels.flatten()

    message = text.encode("utf-8")
    length = len(message).to_bytes(4, "big")
    payload = MAGIC + length + message
    bits = bytes_to_bits(payload)

    if len(bits) > len(flat):
        raise ValueError("Message is too long for this image.")

    for i, bit in enumerate(bits):
        flat[i] = (flat[i] & 0xFE) | bit   # clear last bit, set ours

    stego = flat.reshape(pixels.shape)
    ext = out_path.lower().rsplit(".", 1)[-1]
    if ext == "png":
        Image.fromarray(stego).save(out_path, format="PNG")
    elif ext == "bmp":
        Image.fromarray(stego).save(out_path, format="BMP")
    elif ext == "webp":
        Image.fromarray(stego).save(out_path, format="WEBP", lossless=True)
    else:
        raise ValueError("Output must be .png, .bmp or .webp (lossless formats only).")

def extract(image_path):
    """Read hidden text from an image. Returns None if nothing is found."""
    img = Image.open(image_path).convert("RGB")
    flat = np.array(img, dtype=np.uint8).flatten()

    # read the first 8 bytes (64 bits): marker + length
    header = bits_to_bytes((flat[:64] & 1).tolist())
    if header[:4] != MAGIC:
        return None

    length = int.from_bytes(header[4:8], "big")
    total_bits = 64 + length * 8
    if total_bits > len(flat):
        return None

    body_bits = (flat[64:total_bits] & 1).tolist()
    return bits_to_bytes(body_bits).decode("utf-8", errors="replace")

def lsb_plane_image(image_path, out_path):
    """Save an image showing only the last bit of every pixel value.
    A hidden message shows up as random noise in the top rows."""
    img = Image.open(image_path).convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    plane = (arr & 1) * 255          # 0 stays black, 1 becomes white
    Image.fromarray(plane.astype(np.uint8)).save(out_path)


def chi_square_score(image_path):
    """Chi-square attack. Returns a number from 0 to 1.
    Near 1 means the image probably has LSB data hidden in it."""
    img = Image.open(image_path).convert("RGB")
    flat = np.array(img, dtype=np.uint8).flatten()
    counts = np.bincount(flat, minlength=256).astype(float)

    chi = 0.0
    k = 0
    for i in range(0, 256, 2):          # look at pairs (0,1), (2,3), ...
        a, b = counts[i], counts[i + 1]
        expected = (a + b) / 2
        if expected > 4:                # skip pairs with too few samples
            chi += (a - expected) ** 2 / expected
            k += 1
    if k < 2:
        return 0.0

    # p-value of the chi-square test. Near 1 means the pairs are
    # suspiciously equal, which is what LSB embedding produces.
    from math import erf, sqrt
    z = (chi - (k - 1)) / sqrt(2 * (k - 1))
    return float(0.5 * (1 - erf(z / sqrt(2))))


def lsb_looks_like_text(image_path, sample_bytes=400, min_run=10):
    """Look for a run of readable ASCII characters in the LSB stream."""
    img = Image.open(image_path).convert("RGB")
    flat = np.array(img, dtype=np.uint8).flatten()
    data = bits_to_bytes((flat[:sample_bytes * 8] & 1).tolist())

    run = best = 0
    for b in data:
        if 32 <= b < 127:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best >= min_run

def lsb_agreement(image_path):
    """How often neighbouring pixels share the same last bit.
    Flat or natural areas give high values. Hidden random data gives ~0.5."""
    arr = np.array(Image.open(image_path).convert("RGB"), dtype=np.uint8)
    lsb = arr & 1
    return float((lsb[:, 1:, :] == lsb[:, :-1, :]).mean())