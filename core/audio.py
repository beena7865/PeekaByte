import wave
import numpy as np
from core.lsb import MAGIC, bytes_to_bits, bits_to_bytes


def read_wav(path):
    """Read a 16-bit WAV file. Returns (params, samples as int16 array)."""
    with wave.open(path, "rb") as w:
        params = w.getparams()
        if params.sampwidth != 2:
            raise ValueError("Only 16-bit WAV files are supported.")
        frames = w.readframes(params.nframes)
    samples = np.frombuffer(frames, dtype="<i2").copy()
    return params, samples


def write_wav(path, params, samples):
    with wave.open(path, "wb") as w:
        w.setnchannels(params.nchannels)
        w.setsampwidth(params.sampwidth)
        w.setframerate(params.framerate)
        w.writeframes(samples.astype("<i2").tobytes())


def embed_audio(wav_path, text, out_path):
    """Hide text in the last bit of the audio samples."""
    params, samples = read_wav(wav_path)
    message = text.encode("utf-8")
    payload = MAGIC + len(message).to_bytes(4, "big") + message
    bits = np.array(bytes_to_bits(payload), dtype=np.int16)
    if len(bits) > len(samples):
        raise ValueError("Message is too long for this audio file.")
    samples[:len(bits)] = (samples[:len(bits)] & -2) | bits
    write_wav(out_path, params, samples)


def extract_audio(wav_path):
    """Read hidden text from a WAV file. Returns None if nothing is found."""
    params, samples = read_wav(wav_path)
    if len(samples) < 64:
        return None
    header = bits_to_bytes((samples[:64] & 1).tolist())
    if header[:4] != MAGIC:
        return None
    length = int.from_bytes(header[4:8], "big")
    total = 64 + length * 8
    if total > len(samples):
        return None
    body = bits_to_bytes((samples[64:total] & 1).tolist())
    return body.decode("utf-8", errors="replace")


def audio_looks_like_text(wav_path, sample_bytes=400, min_run=10):
    """Look for a run of readable ASCII characters in the LSB stream."""
    params, samples = read_wav(wav_path)
    data = bits_to_bytes((samples[:sample_bytes * 8] & 1).tolist())
    run = best = 0
    for b in data:
        if 32 <= b < 127:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best >= min_run