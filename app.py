import os
import tempfile

import streamlit as st

from core import lab, lsb, secure, ui
from core.metadata import read_metadata
from core.png_repair import check_png, repair_png
from core.picture_scan import boost_report, find_picture
from core.deep import deep_scan
from core.service import analyze_bytes, hide_message
from core.compare import compare_images
from core.forensics import photo_timeline
from core.pdf_export import build_pdf
from core.audit_log import log_scan, read_log, clear_log
from core.case_manager import create_case, list_cases, get_case, add_file_to_case, delete_case, case_names_for_dropdown
from core.audio_stego import analyze_audio_full
from core.decrypt import full_decrypt
from core.profiler import generate_profile_passwords, profile_summary
from core.batch_scan import scan_batch
from core.fingerprint import check_extension_match
from core.qr_scanner import scan_qr, draw_qr_boxes
from core.carver import carve_file
from core.malware_scan import analyze_malware
from core.pdf_export import build_pdf

TYPES = ["png", "jpg", "jpeg", "bmp", "webp", "gif", "wav", "tif", "tiff", "pdf", "heic", "heif", "avif",
         "mp3", "flac", "ogg", "m4a", "aac", "mp4"]
MIME = {"png": "image/png", "jpg": "image/jpeg", "wav": "audio/wav",
        "tiff": "image/tiff", "pdf": "application/pdf"}

st.set_page_config(page_title="PeekaByte", layout="centered", page_icon="🔍")

st.markdown(ui.css(), unsafe_allow_html=True)
st.markdown(ui.hero(), unsafe_allow_html=True)

tab_scan, tab_hide, tab_compare, tab_forensics, tab_decrypt, tab_qr, tab_carve, tab_malware, tab_batch, tab_history, tab_cases = st.tabs(
    ["Analyze a file", "Hide a message", "Compare two files", "Forensics", "Decrypt", "QR Scanner", "File Carver", "Malware Scan", "Batch Scan", "Scan History", "Cases"])

def show_deep(result):
    """Deep scan: hidden text or files, and pictures that reveal hidden images."""
    st.markdown("### Deep scan")
    if result["note"]:
        st.info(result["note"])
        return
    if result["leads"]:
        st.success("Possible hidden content found in the low bits of the picture:")
        for where, text in result["leads"]:
            st.code(text, language=None)
            st.caption(f"Found in: {where}")
    else:
        st.info("No readable text or hidden file was found in any of the common bit "
                "layouts. If the sender used a password or a private method, the "
                "message cannot be read, only flagged.")
    with st.expander("Look for a hidden picture (bit-plane views)"):
        st.caption("These pictures show only the last bits of the image, made bright. "
                   "A readable picture or text in one of them is a hidden image. "
                   "Plain grey static means nothing is hidden there.")
        cols = st.columns(2)
        for i, (title, data) in enumerate(result["images"]):
            with cols[i % 2]:
                st.image(data, caption=title, use_container_width=True)

def show_png_check(result, data, name):
    """PNG structure check and repair (pcrt/pngcheck equivalent)."""
    st.markdown("### PNG structure check")
    if result["ok"]:
        st.success("PNG structure is valid: signature, chunk order and every CRC check out.")
        return
    st.error("This PNG has structural problems:")
    for p in result["problems"]:
        st.write(f"- {p}")
    fixed, notes = repair_png(data)
    st.caption("Repair attempted: " + " ".join(notes))
    fixed_name = name.rsplit(".", 1)[0] + "_repaired.png"
    st.download_button(f"Download repaired file ({fixed_name})", fixed,
                       file_name=fixed_name, mime="image/png")

def show_picture(pic):
    """Hidden picture finder: shows the rebuilt picture."""
    if not pic or not pic.get("found"):
        return
    st.markdown("### Hidden picture")
    st.success(pic["why"])
    cols = st.columns(2)
    for i, (title, img) in enumerate(pic["images"]):
        with cols[i % 2]:
            st.image(img, caption=title, use_container_width=True)

def show_metadata(meta):
    """Metadata inspector: EXIF tags and any GPS location."""
    st.markdown("### Metadata (EXIF)")
    if meta["note"] and not meta["tags"] and not meta["gps"]:
        st.info(meta["note"])
        return
    if meta["gps"]:
        g = meta["gps"]
        st.warning(f"This file's metadata records a location: {g['lat']}, {g['lon']}")
        st.markdown(f"[Open in Google Maps]({g['maps_url']})")
    if meta["tags"]:
        st.caption("Other EXIF fields found in this file:")
        for name, value in meta["tags"]:
            st.write(f"- **{name}:** {value}")

# ------------------------------------------------------------ analyze
with tab_scan:
    case_options = case_names_for_dropdown()
    selected_case = st.selectbox("Assign to case (optional)", case_options, key="scan_case")
    upload = st.file_uploader("Drop an image or WAV file to check", type=TYPES,
                              key="scan_file")
    if upload is not None:
        if st.button("Analyze file"):
            with st.spinner("Running all checks..."):
                try:
                    data = upload.getvalue()
                    report = analyze_bytes(data, upload.name)
                    try:
                        pic = find_picture(data)
                    except Exception:
                        pic = {"found": False}
                    report = boost_report(report, pic)
                    st.session_state["report"] = (upload.name, upload.size, report)
                    st.session_state["pic"] = (upload.name, upload.size, pic)
                    try:
                        meta = read_metadata(data)
                    except Exception:
                        meta = {"tags": [], "gps": None, "note": "The metadata check could not run."}
                    st.session_state["meta"] = (upload.name, upload.size, meta)
                    if upload.name.lower().endswith(".png"):
                        try:
                            png_result = check_png(data)
                        except Exception:
                            png_result = None
                        st.session_state["pngcheck"] = (upload.name, upload.size, png_result)
                    else:
                        st.session_state["pngcheck"] = None
                    try:
                        deep = deep_scan(data)
                    except Exception as error:
                        deep = {"leads": [], "images": [],
                                "note": f"The deep scan could not run: {error}"}
                    st.session_state["deep"] = (upload.name, upload.size, deep)
                    try:
                        log_scan(upload.name, upload.size, data, report)
                    except Exception:
                        pass
                    try:
                        if selected_case and not selected_case.startswith("No case"):
                            cid = selected_case.split(" - ")[0]
                            statuses = [s.get("status", "").lower() for s in report.get("stages", [])]
                            if any("found" in s or "fail" in s for s in statuses):
                                v = "Hidden data detected"
                            elif any("warning" in s or "suspicious" in s for s in statuses):
                                v = "Suspicious"
                            else:
                                v = "Clean"
                            import hashlib as _hl
                            sha = _hl.sha256(data).hexdigest()
                            parts = [f"{s.get('name','?')}: {s.get('status','?')}" for s in report.get("stages", [])]
                            add_file_to_case(cid, upload.name, upload.size, sha, v, " | ".join(parts))
                    except Exception:
                        pass
                except Exception as error:
                    st.session_state["report"] = None
                    st.session_state["deep"] = None
                    st.error(f"Could not analyze this file: {error}")
        saved = st.session_state.get("report")
        if saved and saved[0] == upload.name and saved[1] == upload.size:
            st.markdown(ui.report_html(saved[2]), unsafe_allow_html=True)
            pic_saved = st.session_state.get("pic")
            if pic_saved and pic_saved[0] == upload.name and pic_saved[1] == upload.size:
                show_picture(pic_saved[2])
            meta_saved = st.session_state.get("meta")
            if meta_saved and meta_saved[0] == upload.name and meta_saved[1] == upload.size:
                show_metadata(meta_saved[2])
            png_saved = st.session_state.get("pngcheck")
            if png_saved and png_saved[0] == upload.name and png_saved[1] == upload.size and png_saved[2]:
                show_png_check(png_saved[2], data, upload.name)
            deep_saved = st.session_state.get("deep")
            if deep_saved and deep_saved[0] == upload.name and deep_saved[1] == upload.size:
                show_deep(deep_saved[2])

            # ---- QR code scanner ----
            img_exts = (".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif", ".tif", ".tiff")
            if upload.name.lower().endswith(img_exts):
                qr = scan_qr(data)
                if qr and qr["found"]:
                    st.markdown("### QR Codes / Barcodes Found")
                    st.success(qr["note"])
                    for code in qr["codes"]:
                        st.write(f"**QR Type:** {code.get('qr_type', 'Unknown')} ({code['type']})")
                        if code.get("details"):
                            for label, value in code["details"]:
                                st.write(f"**{label}:** {value}")
                        else:
                            for label, value in code["details"]:
                                st.write(f"**{label}:** {value}")
                        if code.get("scam_warnings"):
                            for w in code["scam_warnings"]:
                                st.error(f"⚠️ SCAM WARNING: {w}")
                        else:
                            st.success("No scam indicators detected in this QR code.")
                        st.caption(code["position"])
                        st.markdown("---")
                    annotated = draw_qr_boxes(data)
                    if annotated:
                        st.image(annotated, caption="QR codes highlighted in pink",
                                 use_container_width=True)

            # ---- File format fingerprint ----
            fp = check_extension_match(data, upload.name)
            if fp and not fp["match"]:
                if fp["suspicious"]:
                    st.error(f"**File Format Mismatch:** {fp['note']}")
                else:
                    st.warning(f"**File Format Note:** {fp['note']}")
            elif fp and fp["match"] and fp["actual_format"] != "Unknown":
                st.caption(f"File format verified: {fp['actual_format']} matches {fp['claimed_extension']}")

            # ---- Audio steganography ----
            audio_exts = (".wav", ".mp3", ".flac", ".ogg", ".m4a", ".aac", ".mp4")
            if upload.name.lower().endswith(audio_exts):
                st.markdown("### Audio Steganography Analysis")
                with st.spinner("Analyzing audio..."):
                    try:
                        audio_result = analyze_audio_full(data, upload.name)
                        st.session_state["audio_result"] = (upload.name, audio_result)
                    except Exception as e:
                        st.warning(f"Audio analysis failed: {e}")
                        audio_result = None

                ar = st.session_state.get("audio_result")
                if ar and ar[0] == upload.name:
                    audio_result = ar[1]

                    # Spectrogram
                    if audio_result.get("spectrogram"):
                        st.image(audio_result["spectrogram"],
                                 caption="Full spectrogram — look for hidden text or unusual patterns",
                                 use_container_width=True)

                    # LSB spectrogram
                    if audio_result.get("lsb_spectrogram"):
                        st.image(audio_result["lsb_spectrogram"],
                                 caption="LSB-only spectrogram — patterns here suggest hidden data in the last bits",
                                 use_container_width=True)

                    # Chi-square result
                    chi = audio_result.get("lsb_chi")
                    if chi:
                        if chi["score"] > 0.7:
                            st.error(f"**LSB test:** {chi['verdict']}")
                        elif chi["score"] > 0.4:
                            st.warning(f"**LSB test:** {chi['verdict']}")
                        else:
                            st.success(f"**LSB test:** {chi['verdict']}")
                        st.caption(chi.get("details", ""))

                    # Silence check
                    silence = audio_result.get("silence")
                    if silence:
                        st.markdown("**Audio details:**")
                        st.write(f"Duration: {silence['duration']} | Samples: {silence['total_samples']} | Rate: {silence['sample_rate']}")
                        for finding in silence.get("findings", []):
                            if "suspicious" in finding.lower():
                                st.warning(finding)
                            else:
                                st.info(finding)

                    if audio_result.get("error"):
                        st.warning(audio_result["error"])
            st.markdown("---")
            try:
                pdf_bytes = build_pdf(
                    filename=upload.name,
                    filesize=upload.size,
                    report=saved[2],
                    meta=meta_saved[2] if meta_saved and meta_saved[0] == upload.name else None,
                    pic=pic_saved[2] if pic_saved and pic_saved[0] == upload.name else None,
                    png_check=png_saved[2] if png_saved and png_saved[0] == upload.name and png_saved[2] else None,
                    deep=deep_saved[2] if deep_saved and deep_saved[0] == upload.name else None,
                )
                pdf_name = upload.name.rsplit(".", 1)[0] + "_PeekaByte_Report.pdf"
                st.download_button(
                    label="📄 Download PDF Report",
                    data=pdf_bytes,
                    file_name=pdf_name,
                    mime="application/pdf",
                )
            except Exception as e:
                st.warning(f"PDF export failed: {e}")

# ------------------------------------------------------------ hide
with tab_hide:
    left, right = st.columns(2)
    with left:
        cover = st.file_uploader("Cover file (image or WAV)", type=TYPES, key="hide_file")
    with right:
        text = st.text_area("Message to hide", height=150, key="hide_text")
        password = st.text_input("Password (optional)", type="password", key="hide_pw",
                                 help="With a password the message is encrypted first. "
                                      "Without it, nobody can read the message, even with this tool.")
    if st.button("Hide message"):
        if cover is None:
            st.error("Upload a cover file first.")
        else:
            try:
                payload = secure.seal(text, password) if password else text
                st.session_state["hidden"] = hide_message(cover.getvalue(), cover.name, payload)
                st.session_state["hidden_text"] = payload
                st.session_state["hidden_pw"] = bool(password)
            except Exception as error:
                st.session_state["hidden"] = None
                st.error(str(error))
    saved = st.session_state.get("hidden")
    if saved:
        data, name = saved
        st.markdown(ui.hide_done(name), unsafe_allow_html=True)
        if st.session_state.get("hidden_pw"):
            st.info("Password protected. Keep the password safe: it cannot be recovered.")
        st.download_button(f"Download {name}", data, file_name=name,
                           mime=MIME.get(name.rsplit(".", 1)[-1].lower(), "application/octet-stream"))
        if name.lower().endswith((".png", ".bmp", ".tiff")):
            if st.button("Run Stego Lab on this file"):
                with st.spinner("Attacking the file the way real life does..."):
                    rep = analyze_bytes(data, name)
                    rows = lab.survival(data, st.session_state.get("hidden_text", ""))
                    st.session_state["lab"] = (name, rep, rows)
            lab_saved = st.session_state.get("lab")
            if lab_saved and lab_saved[0] == name:
                _, rep, rows = lab_saved
                st.markdown("### Stego Lab")
                st.markdown("**Stealth test.** The statistical checks, without reading the message:")
                for stage in rep.get("stages", []):
                    if stage["name"].startswith(("LSB", "Machine")):
                        st.write(f"- {stage['name']}: {stage['status']} ({stage['summary']})")
                st.markdown("**Survival test.** Does the message come back after this happens to the file?")
                for attack_name, ok in rows:
                    st.write(("SURVIVES - " if ok else "LOST - ") + attack_name)
    st.caption("Images are saved as PNG (a JPEG stays a JPEG). Do not screenshot, re-save or "
               "send the result through apps that recompress images, or the message is lost.")


# ------------------------------------------------------------ compare
with tab_compare:
    st.caption("Upload a file you believe is the original and a file you suspect was "
               "changed or has data hidden in it. This shows exactly which pixels differ.")
    c1, c2 = st.columns(2)
    with c1:
        orig_file = st.file_uploader("Original file", type=["png", "jpg", "jpeg", "bmp", "webp"],
                                     key="cmp_orig")
    with c2:
        sus_file = st.file_uploader("Suspect file", type=["png", "jpg", "jpeg", "bmp", "webp"],
                                    key="cmp_sus")
    if orig_file is not None and sus_file is not None and st.button("Compare"):
        with st.spinner("Comparing pixel by pixel..."):
            result = compare_images(orig_file.getvalue(), sus_file.getvalue())
        st.session_state["compare"] = result
        if result and result.get("ok"):
            try:
                compare_report = {
                    "verdict": "Pixels changed" if float(result.get("percent_changed", 0)) > 0 else "Identical",
                    "stages": [
                        {"name": "Pixels changed", "status": f"{result.get('percent_changed', 0)}%"},
                        {"name": "Compared against", "status": orig_file.name},
                    ]
                }
                log_scan(f"{sus_file.name} vs {orig_file.name}", sus_file.size, sus_file.getvalue(), compare_report)
            except Exception:
                pass
    result = st.session_state.get("compare")
    if result:
        if not result["ok"]:
            st.error(result["note"])
        else:
            st.metric("Pixels changed", f"{result['percent_changed']}%")
            if result["resized"]:
                st.warning("The two files were different sizes; the suspect file was "
                          "resized to the original's size before comparing.")
            st.info(result["note"])
            st.image(result["heatmap"], caption="Red = where the two files differ. "
                    "Brighter red means a bigger change at that pixel.",
                    use_container_width=True)

            # ---- Compare PDF export ----
            st.markdown("---")
            try:
                from core.pdf_export import PeekaBytePDF, safe
                pdf = PeekaBytePDF()
                pdf.alias_nb_pages()
                pdf.add_page()
                pdf.section("File Comparison Report")
                pdf.row("Original File", safe(orig_file.name))
                pdf.row("Suspect File", safe(sus_file.name))
                pdf.row("Pixels Changed", f"{result['percent_changed']}%")
                if result.get("resized"):
                    pdf.row("Note", "Files were different sizes - suspect was resized", pdf.ORANGE)
                pdf.row("Analysis", safe(result.get("note", "")))
                compare_pdf = bytes(pdf.output())
                st.download_button("📄 Download Comparison PDF", compare_pdf,
                                   file_name="Comparison_Report.pdf", mime="application/pdf")
            except Exception as e:
                st.warning(f"PDF export failed: {e}")

# ------------------------------------------------------------ forensics
with tab_forensics:
    st.caption("Upload any file to scan for hidden/embedded content, suspicious strings, "
               "and — for photos — a full forensic timeline showing when it was taken, "
               "edited, and where.")
    forensics_file = st.file_uploader(
        "Upload a file to inspect",
        type=["png","jpg","jpeg","bmp","webp","tif","tiff","gif",
              "pdf","zip","exe","mp3","wav","flac","ogg","mp4","avi"],
        key="forensics_upload")

    if forensics_file is not None and st.button("Run forensic scan"):
        data = forensics_file.getvalue()
        with st.spinner("Scanning..."):
            time = photo_timeline(data)
        st.session_state["forensics_time"] = time
        try:
            forensic_report = {
                "verdict": "Forensic scan complete",
                "stages": [
                    {"name": "Device info", "status": "found" if time.get("device") else "none"},
                    {"name": "Timestamps", "status": "found" if time.get("timeline") else "none"},
                    {"name": "GPS location", "status": "found" if time.get("gps") else "none"},
                    {"name": "Tampering", "status": "warning" if time.get("tampering") else "clean"},
                    {"name": "File size", "status": time.get("size_check", {}).get("verdict", "ok") if time.get("size_check") else "ok"},
                ]
            }
            log_scan(forensics_file.name, forensics_file.size, data, forensic_report)
        except Exception:
            pass

    time = st.session_state.get("forensics_time")


    if time:
        st.subheader("📅 Photo forensic timeline")
        st.caption(time["format_note"])

        if time.get("device"):
            d = time["device"]
            cols = st.columns(3)
            cols[0].metric("Make", d["make"] or "—")
            cols[1].metric("Model", d["model"] or "—")
            cols[2].metric("Software", d["software"] or "—")

        if time.get("timeline"):
            for event in time["timeline"]:
                if event["flagged"]:
                    st.warning(f"{event['label']}: **{event['value']}**  \n{event['note']}")
                else:
                    st.markdown(f"{event['label']}: **{event['value']}**")
        elif time["supported"]:
            st.info("No timestamp data found in this file's metadata.")

        if time.get("tampering"):
            st.subheader("🚨 Tampering indicators")
            for t in time["tampering"]:
                st.warning(t)

        if time.get("gps"):
            g = time["gps"]
            st.subheader("📍 GPS location")
            st.markdown(f"Lat: `{g['lat']}` — Lon: `{g['lon']}`")
            st.markdown(f"[Open in Google Maps]({g['maps_url']})")
        if time.get("size_check"):
            s = time["size_check"]
            st.subheader("📦 File size analysis")
            col1, col2 = st.columns(2)
            col1.metric("File size", f"{s['file_size']:,} bytes")
            col2.metric("Dimensions", s["dimensions"])
            if s["anomaly"]:
                st.warning("⚠️ File is unusually large for its dimensions — possible hidden data.")
            else:
                st.success("✅ File size is normal for its dimensions.")

        # ---- Forensics PDF export ----
        if time:
            st.markdown("---")
            try:
                from core.pdf_export import PeekaBytePDF, safe
                pdf = PeekaBytePDF()
                pdf.alias_nb_pages()
                pdf.add_page()
                pdf.section("Forensic Timeline Report")
                pdf.row("Filename", forensics_file.name)
                if time.get("device"):
                    d = time["device"]
                    pdf.row("Camera Make", safe(str(d.get("make", "-"))))
                    pdf.row("Camera Model", safe(str(d.get("model", "-"))))
                    pdf.row("Software", safe(str(d.get("software", "-"))))
                if time.get("timeline"):
                    pdf.section("Timeline")
                    for event in time["timeline"]:
                        color = pdf.ORANGE if event.get("flagged") else pdf.DARK
                        pdf.row(safe(event["label"]), safe(event["value"]), color)
                if time.get("tampering"):
                    pdf.section("Tampering Indicators")
                    for t_flag in time["tampering"]:
                        pdf.row("Warning", safe(t_flag), pdf.RED)
                if time.get("gps"):
                    g = time["gps"]
                    pdf.section("GPS Location")
                    pdf.row("Latitude", str(g["lat"]))
                    pdf.row("Longitude", str(g["lon"]))
                    pdf.row("Google Maps", safe(g.get("maps_url", "")))
                if time.get("size_check"):
                    s = time["size_check"]
                    pdf.section("File Size Analysis")
                    pdf.row("File Size", safe(str(s.get("size", ""))))
                    pdf.row("Dimensions", safe(str(s.get("dimensions", ""))))
                    pdf.row("Verdict", safe(str(s.get("verdict", ""))))
                forensic_pdf = bytes(pdf.output())
                fname = forensics_file.name.rsplit(".", 1)[0] + "_Forensics_Report.pdf"
                st.download_button("📄 Download Forensics PDF", forensic_pdf,
                                   file_name=fname, mime="application/pdf")
            except Exception as e:
                st.warning(f"PDF export failed: {e}")

# ------------------------------------------------------------ decrypt
with tab_decrypt:
    st.caption("Upload a password-protected file or a file with hidden data. "
               "The tool will try to crack it using a dictionary of common and leaked passwords.")

    decrypt_file = st.file_uploader(
        "Upload a file to crack",
        type=["pdf", "zip", "docx", "xlsx", "pptx", "doc", "xls",
              "png", "bmp", "jpg", "jpeg", "tiff", "tif", "webp",
              "wav", "mp3", "flac", "ogg", "m4a"],
        key="decrypt_upload")

    user_pw = st.text_input("Enter password (optional — leave blank to try cracking without it)",
                            type="password", key="decrypt_pw")

    with st.expander("Generate passwords from person info"):
        st.caption("Enter what you know about the person. The tool will generate "
                   "thousands of custom password guesses based on this info.")
        pc1, pc2 = st.columns(2)
        with pc1:
            p_name = st.text_input("First name", key="prof_name")
            p_surname = st.text_input("Last name", key="prof_surname")
            p_nick = st.text_input("Nickname / username", key="prof_nick")
            p_bday = st.text_input("Birthday (DD/MM/YYYY)", key="prof_bday")
            p_phone = st.text_input("Phone number", key="prof_phone")
            p_company = st.text_input("Company / School", key="prof_company")
        with pc2:
            p_partner = st.text_input("Partner / spouse name", key="prof_partner")
            p_partner_bday = st.text_input("Partner birthday (DD/MM/YYYY)", key="prof_partner_bday")
            p_pet = st.text_input("Pet name", key="prof_pet")
            p_city = st.text_input("City", key="prof_city")
            p_team = st.text_input("Favorite sports team", key="prof_team")
            p_band = st.text_input("Favorite band / artist", key="prof_band")
        p_extra = st.text_input("Any other words (comma separated)", key="prof_extra")

        if st.button("Generate password list", key="gen_profile"):
            profile = {
                "name": p_name, "surname": p_surname, "nickname": p_nick,
                "birthday": p_bday, "phone": p_phone, "company": p_company,
                "partner_name": p_partner, "partner_birthday": p_partner_bday,
                "pet_name": p_pet, "city": p_city, "favorite_team": p_team,
                "favorite_band": p_band,
                "extra_words": [w.strip() for w in p_extra.split(",") if w.strip()],
            }
            guesses = generate_profile_passwords(profile)
            st.session_state["profile_passwords"] = guesses
            st.success(f"Generated {len(guesses):,} custom password guesses!")
            st.caption(profile_summary(profile))

        if st.session_state.get("profile_passwords"):
            st.info(f"{len(st.session_state['profile_passwords']):,} custom passwords ready. "
                    "Click 'Extract with profile passwords' below to try them.")

    if decrypt_file is not None:
        col_a, col_b, col_c = st.columns(3)
        with col_a:
            btn_with_pw = st.button("Extract with password", disabled=not user_pw,
                                     key="decrypt_with_pw")
        with col_b:
            btn_no_pw = st.button("Extract without password",
                                   key="decrypt_no_pw")
        with col_c:
            has_profile = bool(st.session_state.get("profile_passwords"))
            btn_profile = st.button("Extract with profile passwords",
                                     disabled=not has_profile,
                                     key="decrypt_profile")

        if btn_with_pw or btn_no_pw or btn_profile:
            data = decrypt_file.getvalue()

            if btn_with_pw:
                with st.spinner("Trying your password..."):
                    result = full_decrypt(data, decrypt_file.name,
                                          user_password=user_pw,
                                          progress_callback=None,
                                          only_user_password=True)
            elif btn_profile:
                profile_pws = st.session_state.get("profile_passwords", [])
                progress = st.progress(0, text="Trying profile passwords...")

                def update_progress(current, total):
                    if total > 0:
                        pct = min(current / total, 1.0)
                        progress.progress(pct, text=f"Trying password {current:,} of {total:,}...")

                with st.spinner("Running profile attack..."):
                    result = full_decrypt(data, decrypt_file.name,
                                          user_password=None,
                                          progress_callback=update_progress,
                                          only_user_password=False,
                                          custom_passwords=profile_pws)
                progress.empty()
            else:
                progress = st.progress(0, text="Starting dictionary attack...")

                def update_progress(current, total):
                    if total > 0:
                        pct = min(current / total, 1.0)
                        progress.progress(pct, text=f"Trying password {current:,} of {total:,}...")

                with st.spinner("Running dictionary attack..."):
                    result = full_decrypt(data, decrypt_file.name,
                                          user_password=None,
                                          progress_callback=update_progress,
                                          only_user_password=False)
                progress.empty()

            st.session_state["decrypt_result"] = (decrypt_file.name, result)

        saved_dec = st.session_state.get("decrypt_result")
        if saved_dec and saved_dec[0] == decrypt_file.name:
            r = saved_dec[1]

            st.markdown("---")
            st.write(f"**File type detected:** {r['file_type']}")
            st.write(f"**Method:** {r['method']}")

            if r.get("encrypted") and not r.get("cracked"):
                st.error("Could not crack the password. The password is not in any of the wordlists.")
                if r.get("total_passwords", 0) == 1:
                    st.caption("The password you entered is incorrect.")
                elif r.get("attempts"):
                    st.caption(f"Tried {r['attempts']:,} passwords from {r['total_passwords']:,} in the dictionary.")
                st.info("You can add more password lists to D:\\stego-project\\wordlists\\ — "
                        "any .txt file with one password per line will be loaded automatically. "
                        "Try downloading rockyou.txt from GitHub for 14 million passwords.")

            elif r.get("cracked"):
                st.success("Successfully cracked / extracted!")
                if r.get("password"):
                    st.write(f"**Password found:** `{r['password']}`")

                ftype = r.get("file_type", "")
                dec = r.get("decrypted_bytes")

                # ---- Decrypt PDF export ----
                st.markdown("---")
                try:
                    from core.pdf_export import PeekaBytePDF, safe
                    pdf = PeekaBytePDF()
                    pdf.alias_nb_pages()
                    pdf.add_page()
                    pdf.section("Decryption Report")
                    pdf.row("Filename", safe(decrypt_file.name))
                    pdf.row("File Type", safe(r.get("file_type", "")))
                    pdf.row("Method", safe(r.get("method", "")))
                    pdf.row("Result", "Cracked" if r.get("cracked") else "Not cracked")
                    if r.get("password"):
                        pdf.row("Password Found", safe(r["password"]))
                    if r.get("content"):
                        pdf.section("Extracted Content")
                        pdf.set_font("Helvetica", "", 10)
                        content_text = safe(str(r["content"])[:2000])
                        pdf.multi_cell(0, 6, content_text)
                    if r.get("stego_results"):
                        pdf.section("Hidden Data")
                        for method, text in r["stego_results"]:
                            pdf.row(safe(method), safe(str(text)[:200]))
                    decrypt_pdf = bytes(pdf.output())
                    st.download_button("📄 Download Decrypt Report PDF", decrypt_pdf,
                                       file_name="Decrypt_Report.pdf", mime="application/pdf")
                except Exception as e:
                    st.warning(f"PDF export failed: {e}")

                # ---- Display PDF pages as images ----
                if ftype == "pdf" and dec:
                    try:
                        import fitz
                        doc = fitz.open(stream=dec, filetype="pdf")
                        st.write(f"**Pages:** {len(doc)}")
                        for i, page in enumerate(doc):
                            pix = page.get_pixmap(dpi=150)
                            img_bytes = pix.tobytes("png")
                            st.image(img_bytes, caption=f"Page {i+1}", use_container_width=True)
                        doc.close()
                    except Exception as e:
                        st.warning(f"Could not render pages: {e}")
                        if r.get("content"):
                            st.markdown("**Text content:**")
                            st.code(r["content"], language=None)
                    st.download_button("Download decrypted PDF", dec,
                                       file_name="decrypted.pdf", mime="application/pdf")

                # ---- Display Excel as table ----
                elif ftype == "xlsx" and dec:
                    try:
                        import pandas as pd
                        xls = pd.ExcelFile(io.BytesIO(dec))
                        for sheet in xls.sheet_names:
                            st.write(f"**Sheet: {sheet}**")
                            df = pd.read_excel(xls, sheet_name=sheet)
                            st.dataframe(df, use_container_width=True)
                    except Exception as e:
                        st.warning(f"Could not display spreadsheet: {e}")
                    st.download_button("Download decrypted Excel", dec,
                                       file_name="decrypted.xlsx",
                                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

                # ---- Display Word document ----
                elif ftype == "docx" and dec:
                    try:
                        from docx import Document as DocxDocument
                        doc = DocxDocument(io.BytesIO(dec))
                        for para in doc.paragraphs:
                            if para.text.strip():
                                st.write(para.text)
                    except Exception as e:
                        st.warning(f"Could not display document: {e}")
                    st.download_button("Download decrypted Word file", dec,
                                       file_name="decrypted.docx",
                                       mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document")

                # ---- Display PowerPoint ----
                elif ftype == "pptx" and dec:
                    try:
                        from pptx import Presentation
                        prs = Presentation(io.BytesIO(dec))
                        for i, slide in enumerate(prs.slides):
                            st.write(f"**Slide {i+1}:**")
                            for shape in slide.shapes:
                                if shape.has_text_frame:
                                    for para in shape.text_frame.paragraphs:
                                        if para.text.strip():
                                            st.write(para.text)
                            st.markdown("---")
                    except Exception as e:
                        st.warning(f"Could not display presentation: {e}")
                    st.download_button("Download decrypted PowerPoint", dec,
                                       file_name="decrypted.pptx",
                                       mime="application/vnd.openxmlformats-officedocument.presentationml.presentation")

                # ---- Display ZIP contents ----
                elif ftype == "zip":
                    if r.get("content"):
                        st.write(r["content"])
                    st.download_button("Download decrypted ZIP", data,
                                       file_name="decrypted.zip", mime="application/zip")

                # ---- Display image + hidden data ----
                elif ftype == "image_stego":
                    st.image(data, caption="Uploaded image", use_container_width=True)
                    if r.get("stego_results"):
                        st.markdown("**Hidden data found:**")
                        for method, text in r["stego_results"]:
                            st.write(f"**{method}:**")
                            st.code(text, language=None)

                # ---- Display audio + hidden data ----
                elif ftype == "audio_stego":
                    st.audio(data)
                    if r.get("stego_results"):
                        st.markdown("**Hidden data found:**")
                        for method, text in r["stego_results"]:
                            st.write(f"**{method}:**")
                            st.code(text, language=None)

                # ---- Fallback for anything else ----
                else:
                    if r.get("content"):
                        st.markdown("**Content:**")
                        st.code(r["content"], language=None)
                    if r.get("stego_results"):
                        st.markdown("**Hidden data found:**")
                        for method, text in r["stego_results"]:
                            st.write(f"**{method}:**")
                            st.code(text, language=None)

            elif r.get("encrypted") is False:
                st.success("This file is not password-protected. Open it normally.")

            else:
                if r.get("stego_results"):
                    st.markdown("**Hidden data found:**")
                    for method, text in r["stego_results"]:
                        st.write(f"**{method}:**")
                        st.code(text, language=None)
                elif r.get("content"):
                    st.info(r["content"])
                else:
                    st.info("No hidden data or password protection detected in this file.")

            # Log to audit
            try:
                verdict = "Cracked" if r.get("cracked") else "Not cracked"
                log_scan(decrypt_file.name, decrypt_file.size, data,
                         {"verdict": verdict, "stages": [
                             {"name": "Type", "status": r["file_type"]},
                             {"name": "Method", "status": r["method"]},
                             {"name": "Result", "status": verdict},
                         ]})
            except Exception:
                pass
# ------------------------------------------------------------ cases
with tab_cases:
    st.caption("Group scanned files into cases for organized investigations.")

    # --- Create new case ---
    with st.expander("Create a new case"):
        new_name = st.text_input("Case name", placeholder="e.g. WhatsApp Scam Images", key="case_name")
        new_desc = st.text_input("Description (optional)", placeholder="e.g. Images from suspect's phone", key="case_desc")
        if st.button("Create case"):
            if new_name.strip():
                cid = create_case(new_name.strip(), new_desc.strip())
                st.success(f"Created {cid}: {new_name.strip()}")
                st.rerun()
            else:
                st.error("Enter a case name.")


    # --- List all cases ---
    cases = list_cases()
    if not cases:
        st.info("No cases yet. Create one above, then assign scans to it from the Analyze tab.")
    else:
        st.metric("Total cases", len(cases))
        for case in cases:
            file_count = len(case.get("files", []))
            clean = sum(1 for f in case.get("files", []) if "clean" in f.get("verdict", "").lower())
            suspicious = file_count - clean
            title = f"{case['id']}: {case['name']}  ({file_count} files)"

            with st.expander(title):
                st.write(f"**Created:** {case['created']}")
                if case.get("description"):
                    st.write(f"**Description:** {case['description']}")
                col1, col2, col3 = st.columns(3)
                col1.metric("Files", file_count)
                col2.metric("Clean", clean)
                col3.metric("Flagged", suspicious)

                if case.get("files"):
                    st.markdown("---")
                    for f in case["files"]:
                        v = f.get("verdict", "Unknown")
                        if "clean" in v.lower():
                            icon = "✅"
                        elif "suspicious" in v.lower():
                            icon = "⚠️"
                        else:
                            icon = "🚨"
                        st.write(f"{icon} **{f['filename']}** — {v}")
                        st.caption(f"Size: {int(f.get('file_size', 0)):,} bytes | SHA-256: `{f.get('sha256', 'N/A')}` | Scanned: {f.get('scanned', 'N/A')}")
                        if f.get("stages_summary"):
                            for part in f["stages_summary"].split(" | "):
                                st.write(f"  - {part}")
                else:
                    st.info("No files scanned into this case yet. Go to the Analyze tab and select this case.")

                if st.button(f"Delete {case['id']}", key=f"del_{case['id']}"):
                    delete_case(case["id"])
                    st.rerun()

# ------------------------------------------------------------ qr scanner
with tab_qr:
    st.caption("Upload any image containing a QR code or barcode. "
               "The tool will decode it, identify what type it is, and check for scam indicators.")

    qr_file = st.file_uploader("Upload an image with a QR code",
                                type=["png", "jpg", "jpeg", "bmp", "webp", "gif", "tif", "tiff"],
                                key="qr_upload")

    if qr_file is not None and st.button("Scan QR Code", key="qr_go"):
        data = qr_file.getvalue()
        with st.spinner("Scanning for QR codes..."):
            qr = scan_qr(data)
            annotated = draw_qr_boxes(data)
        st.session_state["qr_result"] = (qr_file.name, qr, annotated)

    qr_saved = st.session_state.get("qr_result")
    if qr_saved and qr_file and qr_saved[0] == qr_file.name:
        qr, annotated = qr_saved[1], qr_saved[2]

        if qr and qr["found"]:
            st.success(qr["note"])

            if annotated:
                st.image(annotated, caption="QR codes highlighted in pink",
                         use_container_width=True)

            for code in qr["codes"]:
                st.markdown("---")
                st.write(f"**QR Type:** {code.get('qr_type', 'Unknown')} ({code['type']})")
                if code.get("details"):
                    for label, value in code["details"]:
                        st.write(f"**{label}:** {value}")
                else:
                    st.code(code["data"], language=None)
                if code.get("scam_warnings"):
                    st.markdown("### Fraud Analysis")
                    for w in code["scam_warnings"]:
                        if "upi" in w.lower() or "collect" in w.lower() or "amount" in w.lower():
                            fraud_type = "UPI Payment Fraud"
                        elif "phishing" in w.lower() or "misspelling" in w.lower() or "login" in w.lower():
                            fraud_type = "Phishing Attack"
                        elif "shortened" in w.lower() or "hidden" in w.lower():
                            fraud_type = "URL Redirect Scam"
                        elif "executable" in w.lower() or "malware" in w.lower() or "apk" in w.lower():
                            fraud_type = "Malware Distribution"
                        elif "wifi" in w.lower() or "evil twin" in w.lower() or "no password" in w.lower():
                            fraud_type = "WiFi Attack"
                        elif "lottery" in w.lower() or "prize" in w.lower() or "whatsapp" in w.lower():
                            fraud_type = "Social Engineering Scam"
                        elif "http" in w.lower() or "secure" in w.lower():
                            fraud_type = "Insecure Connection"
                        elif "ip address" in w.lower():
                            fraud_type = "Suspicious Server"
                        else:
                            fraud_type = "Suspicious Activity"
                        st.error(f"**{fraud_type}:** {w}")
                else:
                    st.success("No scam indicators detected in this QR code.")
                st.caption(code["position"])
        else:
            st.warning("No QR codes or barcodes found in this image. "
                       "Make sure the QR code is clear and not too small.")
            st.image(data, caption="Uploaded image", use_container_width=True)

# ------------------------------------------------------------ file carver
with tab_carve:
    st.caption("Upload any file to scan for hidden files embedded inside it. "
               "The tool extracts ZIP, PDF, EXE, images, and other files hidden after the main content.")

    carve_file_upload = st.file_uploader(
        "Upload a file to carve",
        type=["png", "jpg", "jpeg", "bmp", "gif", "webp", "tif", "tiff",
              "pdf", "wav", "mp3", "mp4", "doc", "docx", "zip"],
        key="carve_upload")

    if carve_file_upload is not None and st.button("Carve file", key="carve_go"):
        data = carve_file_upload.getvalue()
        with st.spinner("Scanning for hidden files..."):
            result = carve_file(data, carve_file_upload.name)
        st.session_state["carve_result"] = (carve_file_upload.name, result)

    carve_saved = st.session_state.get("carve_result")
    if carve_saved and carve_file_upload and carve_saved[0] == carve_file_upload.name:
        result = carve_saved[1]

        # File info
        col1, col2, col3 = st.columns(3)
        col1.metric("File Format", result["host_format"])
        col2.metric("Total Size", f"{result['file_size']:,} bytes")
        col3.metric("Trailing Data", f"{result['trailing_bytes']:,} bytes")

        st.info(result["note"])

        if result["carved_files"]:
            st.markdown("### Hidden Files Found")
            for i, f in enumerate(result["carved_files"]):
                size_kb = f["size"] / 1024
                if size_kb > 1024:
                    size_str = f"{size_kb/1024:.1f} MB"
                else:
                    size_str = f"{size_kb:.1f} KB"

                with st.expander(f"File {i+1}: {f['name']} ({f['extension']}) — {size_str} at position {f['position']:,}"):
                    st.write(f"**Type:** {f['name']}")
                    st.write(f"**Extension:** {f['extension']}")
                    st.write(f"**Size:** {f['size']:,} bytes ({size_str})")
                    st.write(f"**Position:** byte {f['position']:,}")

                    # Preview if it's an image
                    if f["extension"] in (".jpg", ".png", ".gif", ".bmp"):
                        try:
                            st.image(f["data"], caption=f"Hidden {f['name']}", use_container_width=True)
                        except Exception:
                            pass

                    # Download button
                    carved_name = f"carved_{i+1}_{carve_file_upload.name.rsplit('.', 1)[0]}{f['extension']}"
                    st.download_button(
                        f"Download {f['name']}",
                        f["data"],
                        file_name=carved_name,
                        key=f"carve_dl_{i}")

            # Log to audit
            try:
                log_scan(carve_file_upload.name, carve_file_upload.size, data,
                         {"verdict": f"Found {len(result['carved_files'])} hidden file(s)",
                          "stages": [
                              {"name": "Trailing data", "status": f"{result['trailing_bytes']:,} bytes"},
                              {"name": "Files found", "status": str(len(result['carved_files']))},
                          ]})
            except Exception:
                pass
        else:
            st.success("No hidden files found — this file appears clean.")

# ------------------------------------------------------------ malware scan
with tab_malware:
    st.caption("Upload any file to scan for malware indicators: suspicious strings, "
               "embedded executables, high-entropy sections, macros, and more.")

    malware_file = st.file_uploader(
        "Upload a file to scan for malware",
        type=["png", "jpg", "jpeg", "bmp", "gif", "webp", "tif", "tiff",
              "pdf", "doc", "docx", "xls", "xlsx", "pptx", "zip", "rar",
              "exe", "dll", "bat", "cmd", "ps1", "vbs", "js",
              "wav", "mp3", "mp4", "html", "htm", "xml", "csv", "txt"],
        key="malware_upload")

    if malware_file is not None and st.button("Scan for malware", key="malware_go"):
        data = malware_file.getvalue()
        with st.spinner("Scanning for malware indicators..."):
            result = analyze_malware(data, malware_file.name)
        st.session_state["malware_result"] = (malware_file.name, result)

    mal_saved = st.session_state.get("malware_result")
    if mal_saved and malware_file and mal_saved[0] == malware_file.name:
        r = mal_saved[1]

        # Risk level banner
        if r["risk_level"] == "high":
            st.error(r["summary"][0])
        elif r["risk_level"] == "medium":
            st.warning(r["summary"][0])
        elif r["risk_level"] == "low":
            st.info(r["summary"][0])
        else:
            st.success(r["summary"][0])

        # File info
        col1, col2, col3 = st.columns(3)
        col1.metric("Risk Score", f"{r['risk_score']}/100")
        col2.metric("Entropy", f"{r['overall_entropy']:.2f}/8.0")
        col3.metric("File Size", f"{r['file_size']:,} bytes")

        st.write(f"**SHA-256:** `{r['sha256']}`")
        st.write(f"**MD5:** `{r['md5']}`")
        st.caption(r["entropy_verdict"])

        # Additional summary points
        for s in r["summary"][1:]:
            st.error(s)

        # Executable findings
        if r["executable_findings"]:
            st.markdown("### Embedded Executable Content")
            for finding in r["executable_findings"]:
                if finding["severity"] == "critical":
                    st.error(f"**{finding['type']}** found at position(s): {finding['positions'][:5]}")
                else:
                    st.warning(f"**{finding['type']}** found at position(s): {finding['positions'][:5]}")
                st.write(f"**Why this matters:** {finding['reason']}")

        # String findings
        if r["string_findings"]:
            st.markdown("### Suspicious Strings")
            for finding in r["string_findings"]:
                if finding["severity"] == "critical":
                    color_fn = st.error
                elif finding["severity"] == "high":
                    color_fn = st.warning
                else:
                    color_fn = st.info
                color_fn(f"**{finding['type']}** ({finding['severity'].upper()})")
                st.write(f"**Why this matters:** {finding['reason']}")
                with st.expander(f"Show {len(finding['items'])} item(s)"):
                    for item in finding["items"]:
                        st.code(item, language=None)

        # Entropy sections
        if r["suspicious_sections"]:
            st.markdown("### High-Entropy Sections")
            st.caption("Sections with entropy above 7.5 may contain encrypted or packed data.")
            for s in r["suspicious_sections"][:10]:
                st.write(f"Offset **{s['offset']:,}** — Entropy: **{s['entropy']:.2f}** — Size: {s['size']:,} bytes")

        # No findings
        if not r["executable_findings"] and not r["string_findings"] and not r["suspicious_sections"]:
            st.success("No suspicious indicators found in this file.")

        # Log to audit
        try:
            log_scan(malware_file.name, malware_file.size, data,
                     {"verdict": f"Risk: {r['risk_level']} ({r['risk_score']}/100)",
                      "stages": [
                          {"name": "Risk Level", "status": r["risk_level"]},
                          {"name": "Risk Score", "status": f"{r['risk_score']}/100"},
                          {"name": "Entropy", "status": f"{r['overall_entropy']:.2f}"},
                          {"name": "Findings", "status": str(len(r['string_findings']) + len(r['executable_findings']))},
                      ]})
        except Exception:
            pass

# ------------------------------------------------------------ batch scan
with tab_batch:
    st.caption("Upload multiple files at once. Each file is scanned and ranked by suspicion level.")

    batch_files = st.file_uploader(
        "Upload files to batch scan",
        type=TYPES,
        accept_multiple_files=True,
        key="batch_upload")

    if batch_files and st.button("Scan all files", key="batch_go"):
        progress = st.progress(0, text="Starting batch scan...")
        file_list = []
        for i, f in enumerate(batch_files):
            progress.progress((i + 1) / len(batch_files),
                              text=f"Scanning {f.name} ({i+1}/{len(batch_files)})...")
            file_list.append((f.name, f.getvalue()))
        with st.spinner("Analyzing all files..."):
            results = scan_batch(file_list)
        progress.empty()
        st.session_state["batch_results"] = results

        # Log each to audit
        for r in results:
            if r.get("report"):
                try:
                    log_scan(r["filename"], r["size"], b"", r["report"])
                except Exception:
                    pass

    batch_results = st.session_state.get("batch_results")
    if batch_results:
        st.metric("Files scanned", len(batch_results))

        # Summary counts
        clean = sum(1 for r in batch_results if "clean" in r["verdict"].lower())
        suspicious = sum(1 for r in batch_results if "suspicious" in r["verdict"].lower())
        detected = sum(1 for r in batch_results if "detected" in r["verdict"].lower() or "found" in r["verdict"].lower())
        errors = sum(1 for r in batch_results if "error" in r["verdict"].lower())

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Clean", clean)
        c2.metric("Suspicious", suspicious)
        c3.metric("Detected", detected)
        c4.metric("Errors", errors)

        st.markdown("---")
        st.markdown("### Ranked Results (most suspicious first)")

        for r in batch_results:
            v = r["verdict"]
            if "clean" in v.lower():
                icon = "✅"
            elif "suspicious" in v.lower():
                icon = "⚠️"
            elif "error" in v.lower():
                icon = "❌"
            else:
                icon = "🚨"

            with st.expander(f"{icon}  {r['filename']}  —  Score: {r['score']}  —  {v}"):
                st.write(f"**Verdict:** {v}")
                st.write(f"**Suspicion score:** {r['score']}/100")
                st.write(f"**File size:** {r['size']:,} bytes")
                if r.get("sha256"):
                    st.write(f"**SHA-256:** `{r['sha256']}`")
                if r.get("flags"):
                    st.write("**Flags:**")
                    for flag in r["flags"]:
                        st.write(f"  - {flag}")
                else:
                    st.write("No flags raised.")

        # ---- Batch PDF export ----
        st.markdown("---")
        try:
            from core.pdf_export import PeekaBytePDF, safe
            pdf = PeekaBytePDF()
            pdf.alias_nb_pages()
            pdf.add_page()
            pdf.section("Batch Scan Report")
            pdf.row("Total Files", str(len(batch_results)))
            pdf.row("Clean", str(clean))
            pdf.row("Suspicious", str(suspicious))
            pdf.row("Detected", str(detected))
            pdf.ln(4)
            for r in batch_results:
                v = r["verdict"]
                if "clean" in v.lower():
                    color = pdf.GREEN
                elif "suspicious" in v.lower():
                    color = pdf.ORANGE
                else:
                    color = pdf.RED
                pdf.row(safe(r["filename"]), safe(f"Score: {r['score']} - {v}"), color)
                if r.get("flags"):
                    for flag in r["flags"]:
                        pdf.set_font("Helvetica", "", 9)
                        pdf.cell(10)
                        pdf.cell(0, 5, safe(f"  - {flag}"), ln=True)
                pdf.ln(2)
            batch_pdf = bytes(pdf.output())
            st.download_button("📄 Download Batch Report PDF", batch_pdf,
                               file_name="Batch_Scan_Report.pdf", mime="application/pdf")
        except Exception as e:
            st.warning(f"PDF export failed: {e}")

# ------------------------------------------------------------ #scan history
with tab_history:
    st.caption("Every file you scan is logged here automatically with its verdict and SHA-256 hash.")
    history = read_log()
    if not history:
        st.info("No scans yet. Analyze a file and it will appear here.")
    else:
        st.metric("Total scans", len(history))
        for entry in history:
            verdict = entry.get("verdict", "Unknown")
            if "clean" in verdict.lower():
                icon = "✅"
            elif "suspicious" in verdict.lower():
                icon = "⚠️"
            else:
                icon = "🚨"
            with st.expander(f"{icon}  {entry['filename']}  —  {entry['timestamp']}"):
                st.write(f"**Verdict:** {verdict}")
                st.write(f"**File size:** {int(entry.get('file_size', 0)):,} bytes")
                st.write(f"**SHA-256:** `{entry.get('sha256', 'N/A')}`")
                if entry.get("stages_summary"):
                    st.write("**Details:**")
                    for part in entry["stages_summary"].split(" | "):
                        st.write(f"- {part}")
        st.markdown("---")
        if st.button("Clear all scan history"):
            clear_log()
            st.rerun()

# ============================================================
# PDF EXPORT BUTTONS FOR ALL TABS
# ============================================================

# ---- Forensics PDF ----
with tab_forensics:
    time = st.session_state.get("forensics_time")
    if time:
        st.markdown("---")
        try:
            pdf_data = {"Format": time.get("format_note", "")}
            if time.get("device"):
                d = time["device"]
                pdf_data["__section__1"] = "Device Information"
                pdf_data["Make"] = d.get("make", "-")
                pdf_data["Model"] = d.get("model", "-")
                pdf_data["Software"] = d.get("software", "-")
            if time.get("timeline"):
                pdf_data["__section__2"] = "Timeline"
                for i, event in enumerate(time["timeline"]):
                    flag = " [FLAGGED]" if event.get("flagged") else ""
                    pdf_data[f"{event['label']}"] = f"{event['value']}{flag}"
            if time.get("tampering"):
                pdf_data["__section__3"] = "Tampering Indicators"
                for i, t_flag in enumerate(time["tampering"]):
                    pdf_data[f"__warning__{i}"] = t_flag
            if time.get("gps"):
                g = time["gps"]
                pdf_data["__section__4"] = "GPS Location"
                pdf_data["Latitude"] = str(g["lat"])
                pdf_data["Longitude"] = str(g["lon"])
                pdf_data["Google Maps"] = g.get("maps_url", "")
            fpdf = export_any_tab("Forensics", st.session_state.get("forensics_upload", {}).name if st.session_state.get("forensics_upload") else "file", pdf_data)
            st.download_button("📄 Download Forensics PDF", fpdf,
                               file_name="Forensics_Report.pdf", mime="application/pdf", key="pdf_forensics")
        except Exception as e:
            st.warning(f"PDF export failed: {e}")

# ---- Decrypt PDF ----
with tab_decrypt:
    dec_saved = st.session_state.get("decrypt_result")
    if dec_saved:
        st.markdown("---")
        try:
            r = dec_saved[1]
            pdf_data = {
                "File Type": r.get("file_type", ""),
                "Method": r.get("method", ""),
                "Result": "Cracked" if r.get("cracked") else "Not cracked",
            }
            if r.get("password"):
                pdf_data["Password Found"] = r["password"]
            if r.get("content"):
                pdf_data["__section__1"] = "Extracted Content"
                pdf_data["Content"] = str(r["content"])[:500]
            if r.get("stego_results"):
                pdf_data["__section__2"] = "Hidden Data"
                for i, (method, text) in enumerate(r["stego_results"]):
                    pdf_data[method] = str(text)[:200]
            dpdf = export_any_tab("Decryption", dec_saved[0], pdf_data)
            st.download_button("📄 Download Decrypt PDF", dpdf,
                               file_name="Decrypt_Report.pdf", mime="application/pdf", key="pdf_decrypt")
        except Exception as e:
            st.warning(f"PDF export failed: {e}")

# ---- QR Scanner PDF ----
with tab_qr:
    qr_saved2 = st.session_state.get("qr_result")
    if qr_saved2:
        qr2 = qr_saved2[1]
        if qr2 and qr2.get("found"):
            st.markdown("---")
            try:
                pdf_data = {"Codes Found": str(qr2["count"])}
                for i, code in enumerate(qr2["codes"]):
                    pdf_data[f"__section__{i}"] = f"QR Code {i+1}"
                    pdf_data[f"Type {i+1}"] = code.get("qr_type", "Unknown")
                    if code.get("details"):
                        for label, value in code["details"]:
                            pdf_data[f"{label} ({i+1})"] = value
                    else:
                        pdf_data[f"Raw Data {i+1}"] = code["data"]
                    if code.get("scam_warnings"):
                        for j, w in enumerate(code["scam_warnings"]):
                            pdf_data[f"__error__{i}_{j}"] = w
                    else:
                        pdf_data[f"__success__{i}"] = "No scam indicators detected"
                qpdf = export_any_tab("QR Scanner", qr_saved2[0], pdf_data)
                st.download_button("📄 Download QR Report PDF", qpdf,
                                   file_name="QR_Report.pdf", mime="application/pdf", key="pdf_qr")
            except Exception as e:
                st.warning(f"PDF export failed: {e}")

# ---- File Carver PDF ----
with tab_carve:
    carve_saved2 = st.session_state.get("carve_result")
    if carve_saved2:
        cr = carve_saved2[1]
        if cr.get("carved_files"):
            st.markdown("---")
            try:
                pdf_data = {
                    "Host Format": cr["host_format"],
                    "Total Size": f"{cr['file_size']:,} bytes",
                    "Host Data Ends At": f"{cr['host_size']:,} bytes",
                    "Trailing Data": f"{cr['trailing_bytes']:,} bytes",
                    "__section__0": "Hidden Files Found",
                }
                for i, f in enumerate(cr["carved_files"]):
                    pdf_data[f"File {i+1}"] = f"{f['name']} ({f['extension']}) - {f['size']:,} bytes at position {f['position']:,}"
                cvpdf = export_any_tab("File Carver", carve_saved2[0], pdf_data)
                st.download_button("📄 Download Carver PDF", cvpdf,
                                   file_name="Carver_Report.pdf", mime="application/pdf", key="pdf_carve")
            except Exception as e:
                st.warning(f"PDF export failed: {e}")

# ---- Malware Scan PDF ----
with tab_malware:
    mal_saved2 = st.session_state.get("malware_result")
    if mal_saved2:
        mr = mal_saved2[1]
        st.markdown("---")
        try:
            pdf_data = {
                "Risk Level": mr["risk_level"].upper(),
                "Risk Score": f"{mr['risk_score']}/100",
                "Entropy": f"{mr['overall_entropy']:.2f}/8.0",
                "SHA-256": mr["sha256"],
                "MD5": mr["md5"],
                "Entropy Note": mr["entropy_verdict"],
            }
            for s in mr["summary"]:
                pdf_data["__warning__summary"] = s
            if mr["executable_findings"]:
                pdf_data["__section__exe"] = "Embedded Executables"
                for i, finding in enumerate(mr["executable_findings"]):
                    pdf_data[f"{finding['type']}"] = finding["reason"]
            if mr["string_findings"]:
                pdf_data["__section__str"] = "Suspicious Strings"
                for i, finding in enumerate(mr["string_findings"]):
                    pdf_data[f"{finding['type']} ({finding['severity']})"] = finding["reason"]
                    pdf_data[f"__list__items_{i}"] = finding["items"][:5]
            if mr["suspicious_sections"]:
                pdf_data["__section__ent"] = "High-Entropy Sections"
                for i, s in enumerate(mr["suspicious_sections"][:5]):
                    pdf_data[f"Offset {s['offset']:,}"] = f"Entropy: {s['entropy']:.2f}"
            mpdf = export_any_tab("Malware Scan", mal_saved2[0], pdf_data)
            st.download_button("📄 Download Malware PDF", mpdf,
                               file_name="Malware_Report.pdf", mime="application/pdf", key="pdf_malware")
        except Exception as e:
            st.warning(f"PDF export failed: {e}")