"""
PeekaByte — Audio Steganography Analyzer
Spectrogram, LSB analysis, silence detection for WAV/MP3/FLAC/OGG/MP4/AAC.
"""

import io
import wave
import tempfile
import os
import numpy as np

try:
    from scipy.signal import spectrogram as scipy_spectrogram
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

try:
    from pydub import AudioSegment
    HAS_PYDUB = True
except ImportError:
    HAS_PYDUB = False


def _audio_to_wav_samples(data, filename):
    """
    Convert any supported audio format to 16-bit mono samples + sample rate.
    Returns (samples as np.int16 array, sample_rate).
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext == "wav":
        buf = io.BytesIO(data)
        with wave.open(buf, "rb") as w:
            params = w.getparams()
            if params.sampwidth != 2:
                raise ValueError("Only 16-bit WAV is supported for direct analysis.")
            frames = w.readframes(params.nframes)
            samples = np.frombuffer(frames, dtype="<i2").copy()
            if params.nchannels == 2:
                samples = samples[::2]  # take left channel
            return samples, params.framerate

    # For all other formats, use pydub
    if not HAS_PYDUB:
        raise ValueError(f"Cannot read .{ext} files — install pydub and ffmpeg.")

    with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        audio = AudioSegment.from_file(tmp_path)
        audio = audio.set_channels(1).set_sample_width(2)  # mono, 16-bit
        raw = np.frombuffer(audio.raw_data, dtype="<i2").copy()
        return raw, audio.frame_rate
    finally:
        os.unlink(tmp_path)


def generate_spectrogram(data, filename):
    """
    Generate a spectrogram image from audio.
    Returns PNG image as bytes, or None if libraries are missing.
    """
    if not HAS_SCIPY or not HAS_MPL:
        return None

    samples, rate = _audio_to_wav_samples(data, filename)

    # Limit to first 30 seconds for performance
    max_samples = rate * 30
    if len(samples) > max_samples:
        samples = samples[:max_samples]

    # Compute spectrogram
    nperseg = min(1024, len(samples) // 4) if len(samples) > 256 else len(samples)
    if nperseg < 16:
        return None

    freqs, times, Sxx = scipy_spectrogram(samples, fs=rate, nperseg=nperseg)

    # Plot
    fig, ax = plt.subplots(figsize=(10, 4))
    Sxx_log = 10 * np.log10(Sxx + 1e-10)
    ax.pcolormesh(times, freqs, Sxx_log, shading="gouraud", cmap="magma")
    ax.set_ylabel("Frequency (Hz)")
    ax.set_xlabel("Time (seconds)")
    ax.set_title("Spectrogram — look for hidden text or patterns")
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()


def generate_lsb_spectrogram(data, filename):
    """
    Generate a spectrogram of ONLY the last bit of each sample.
    If data is hidden in LSBs, this will look different from random noise.
    Returns PNG image as bytes, or None.
    """
    if not HAS_SCIPY or not HAS_MPL:
        return None

    samples, rate = _audio_to_wav_samples(data, filename)

    max_samples = rate * 30
    if len(samples) > max_samples:
        samples = samples[:max_samples]

    # Extract just the LSBs and scale them up
    lsb_signal = (samples & 1).astype(np.float64) * 2 - 1  # convert 0/1 to -1/+1

    nperseg = min(1024, len(samples) // 4) if len(samples) > 256 else len(samples)
    if nperseg < 16:
        return None

    freqs, times, Sxx = scipy_spectrogram(lsb_signal, fs=rate, nperseg=nperseg)

    fig, ax = plt.subplots(figsize=(10, 4))
    Sxx_log = 10 * np.log10(Sxx + 1e-10)
    ax.pcolormesh(times, freqs, Sxx_log, shading="gouraud", cmap="inferno")
    ax.set_ylabel("Frequency (Hz)")
    ax.set_xlabel("Time (seconds)")
    ax.set_title("LSB-only spectrogram — patterns here suggest hidden data")
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()


def audio_lsb_chi_square(data, filename):
    """
    Chi-square test on audio sample LSBs.
    Returns dict with score (0-1), verdict, and details.
    """
    samples, rate = _audio_to_wav_samples(data, filename)

    if len(samples) < 100:
        return {"score": 0, "verdict": "Too short to analyze", "details": "File has fewer than 100 samples."}

    # Take up to 500,000 samples
    test_samples = samples[:500_000]

    # Count LSB values
    lsbs = test_samples & 1
    ones = int(np.sum(lsbs))
    zeros = len(lsbs) - ones
    total = len(lsbs)
    expected = total / 2

    # Chi-square: how far from 50/50?
    if expected == 0:
        return {"score": 0, "verdict": "Cannot compute", "details": "No samples."}

    chi2 = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected

    # A perfectly random LSB (like hidden data) gives chi2 close to 0
    # Natural audio has patterns in LSBs, giving higher chi2
    # But VERY low chi2 is suspicious — means LSBs are too perfectly random
    ratio = ones / total  # should be near 0.5 for hidden data

    if 0.495 <= ratio <= 0.505 and chi2 < 2:
        score = 0.85
        verdict = "Suspicious — LSBs are unusually close to 50/50 (typical of hidden data)"
    elif 0.49 <= ratio <= 0.51 and chi2 < 5:
        score = 0.5
        verdict = "Slightly suspicious — LSBs are fairly balanced"
    else:
        score = 0.1
        verdict = "Normal — LSB pattern is typical for natural audio"

    details = (f"Samples tested: {total:,} | "
               f"LSB ones: {ones:,} ({ratio:.4f}) | "
               f"LSB zeros: {zeros:,} ({1-ratio:.4f}) | "
               f"Chi-square: {chi2:.4f}")

    return {"score": score, "verdict": verdict, "details": details}


def detect_silence_anomaly(data, filename):
    """
    Check for suspicious silence or noise patterns.
    Returns dict with findings.
    """
    samples, rate = _audio_to_wav_samples(data, filename)

    findings = []
    duration = len(samples) / rate

    # Check for sections of near-zero amplitude (silence) that have non-zero LSBs
    chunk_size = rate  # 1-second chunks
    suspicious_chunks = 0
    total_chunks = 0

    for i in range(0, len(samples) - chunk_size, chunk_size):
        chunk = samples[i:i + chunk_size]
        amplitude = np.mean(np.abs(chunk))
        total_chunks += 1

        if amplitude < 50:  # very quiet section
            lsb_ones = np.sum(chunk & 1)
            lsb_ratio = lsb_ones / len(chunk)
            if 0.48 <= lsb_ratio <= 0.52:
                suspicious_chunks += 1

    if suspicious_chunks > 0:
        findings.append(
            f"Found {suspicious_chunks} silent section(s) with suspiciously balanced LSBs "
            f"(out of {total_chunks} total chunks). Data may be hidden in quiet parts."
        )

    # Check trailing silence
    tail = samples[-rate:] if len(samples) > rate else samples
    tail_amp = np.mean(np.abs(tail))
    if tail_amp < 10:
        tail_lsb_ratio = np.sum(tail & 1) / len(tail)
        if 0.48 <= tail_lsb_ratio <= 0.52:
            findings.append(
                "Trailing silence has balanced LSBs — possible data appended in silent section."
            )

    # Overall noise floor check
    overall_lsb = np.sum(samples & 1) / len(samples)
    findings.append(f"Overall LSB balance: {overall_lsb:.4f} (0.5 = perfectly balanced)")

    return {
        "duration": f"{duration:.1f} seconds",
        "total_samples": f"{len(samples):,}",
        "sample_rate": f"{rate:,} Hz",
        "findings": findings,
        "suspicious_silence": suspicious_chunks > 0,
    }


def analyze_audio_full(data, filename):
    """
    Run all audio steganography checks.
    Returns dict with all results.
    """
    result = {
        "supported": True,
        "spectrogram": None,
        "lsb_spectrogram": None,
        "lsb_chi": None,
        "silence": None,
        "error": None,
    }

    try:
        result["spectrogram"] = generate_spectrogram(data, filename)
    except Exception as e:
        result["error"] = f"Spectrogram failed: {e}"

    try:
        result["lsb_spectrogram"] = generate_lsb_spectrogram(data, filename)
    except Exception:
        pass

    try:
        result["lsb_chi"] = audio_lsb_chi_square(data, filename)
    except Exception as e:
        result["lsb_chi"] = {"score": 0, "verdict": f"Could not run: {e}", "details": ""}

    try:
        result["silence"] = detect_silence_anomaly(data, filename)
    except Exception as e:
        result["silence"] = {"findings": [f"Could not run: {e}"], "suspicious_silence": False}

    return result