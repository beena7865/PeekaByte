# PeekaByte
**Steganography Detection & Digital Forensics Toolkit**

PeekaByte is an all-in-one forensic analysis tool that detects hidden messages inside images, cracks encrypted files, scans QR codes for fraud, carves deleted files, and much more. Built for cybersecurity professionals, students, and researchers.

---

## Features

### 1. Analyze
Upload any image and run multiple steganography detection tests including LSB (Least Significant Bit) analysis, Chi-Square test, RS Analysis, and a trained CNN (Convolutional Neural Network) model. Get a final verdict on whether the image contains hidden data.

### 2. Hide Message
Hide secret text messages inside images using LSB steganography. Supports optional password protection for added security.

### 3. Compare
Upload two images side by side and compare them visually and statistically to spot differences that may indicate hidden data or tampering.

### 4. Forensics
Extract detailed metadata and EXIF data from images. Useful for investigating image origin, camera details, GPS location, timestamps, and modification history.

### 5. Decrypt
Crack password-protected files (images with hidden messages, PDFs, ZIP archives) using three methods:
- **Known Password** — enter the password directly
- **Dictionary Attack** — uses a wordlist of 4 million+ common passwords
- **Profile Attack (CUPP)** — generate custom passwords based on a person's name, birthdate, pet name, and other personal details

### 6. QR Scanner
Scan QR codes and analyze the URLs for phishing indicators, suspicious domains, and fraud patterns. Helps identify fake payment QR codes and scam links.

### 7. File Carver
Recover and extract embedded files hidden inside other files. Detects file signatures (magic bytes) to carve out images, PDFs, ZIPs, and other file types.

### 8. Malware Scan
Scan suspicious files by checking their hash against known malware databases. Helps identify potentially dangerous files.

### 9. Batch Scan
Upload and analyze multiple files at once. Runs steganography detection on all images in bulk and gives a summary report.

### 10. Scan History
View a log of all previous scans with timestamps, verdicts, file sizes, and SHA-256 hashes. Export the history as a PDF report.

### 11. Cases
Organize your forensic investigations into cases. Group related files, add descriptions, and generate full case reports in PDF format.

---

## How to Use

### Live App (Recommended)

PeekaByte is deployed on Streamlit Cloud — no installation needed!

👉 **[Open PeekaByte](https://peekabyte-abcgxaupbzdgal4dai2gng.streamlit.app/)**

Just click the link and start using it in your browser. Works on Windows, Linux, macOS, and mobile.

### Run Locally

1. Clone this repository:
   git clone https://github.com/beena7865/PeekaByte.git
   cd PeekaByte
2. Install dependencies:
   pip install -r requirements.txt
3. Run the app:
   streamlit run app.py
4. Open `http://localhost:8501` in your browser.

---

## Tech Stack

- **Language:** Python
- **Frontend:** Streamlit
- **Steganography Detection:** LSB Analysis, Chi-Square Test, RS Analysis
- **Machine Learning:** CNN model trained for stego detection
- **Password Cracking:** Dictionary attack, CUPP-style profile attack
- **File Analysis:** Magic byte detection, metadata extraction, hash comparison


---

## System Requirements

- Any modern web browser (Chrome, Firefox, Edge, Safari)
- For running locally: Python 3.8+

---

## Developer

**Beena Siddique**
B.Sc. Cyber Security — Chandigarh Group of Colleges, Landran

- GitHub: [@beena7865](https://github.com/beena7865)
---

## License

This project is proprietary. The executable is provided for personal and educational use only. Redistribution or reverse engineering of the tool is not permitted.
