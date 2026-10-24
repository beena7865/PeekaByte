"""Interface pieces: candy-pastel 'sticker' theme, hero, report, hide confirmation."""
from html import escape

STATUS = {
    "ok": ("Clear", "ok"), "clear": ("Clear", "ok"),
    "warn": ("Unusual", "warn"), "warning": ("Unusual", "warn"), "unusual": ("Unusual", "warn"),
    "suspicious": ("Flagged", "bad"), "flagged": ("Flagged", "bad"), "bad": ("Flagged", "bad"),
    "skipped": ("Skipped", "skip"), "skip": ("Skipped", "skip"),
}


def _t(text):
    """Escape text and keep it on one line (Streamlit markdown safe)."""
    return " ".join(escape(str(text)).split())


def _d(item):
    """One evidence line: accept a string or a (label, value) style tuple."""
    if isinstance(item, (tuple, list)):
        return ": ".join(str(x) for x in item)
    return item


THEME_NAMES = ["Candy"]


def css(theme=None):
    return "<style>" + """@import url('https://fonts.googleapis.com/css2?family=Fredoka:wght@400;500;600;700&family=Nunito:wght@400;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap');
:root{--bg:#fff3f8;--ink:#3a2146;--mu:#7a6290;--pink:#ff7eb6;--lav:#a78bfa;--sky:#63c2ff;--peach:#ffb27a;--mint:#4fd9a8;--cream:#fffaf5;
--ok:#2fc48d;--warn:#f5a524;--bad:#ff4f87;--skip:#9a8fb0;--line:#3a2146;
--head:'Fredoka',system-ui,sans-serif;--sans:'Nunito',system-ui,sans-serif;--mono:'JetBrains Mono',ui-monospace,Consolas,monospace}
.stApp{background:radial-gradient(520px 380px at 6% 4%,#ffd3e8 0,transparent 70%),radial-gradient(520px 380px at 96% 8%,#d9ccff 0,transparent 70%),radial-gradient(600px 420px at 80% 100%,#bfe6ff 0,transparent 70%),radial-gradient(480px 360px at 0% 96%,#ffe0c4 0,transparent 70%),var(--bg);color:var(--ink);font-family:var(--sans)}
header[data-testid="stHeader"]{background:transparent}
.block-container{max-width:980px;padding-top:2rem}
html,body,[class*="css"],.stMarkdown,p,label,span{font-family:var(--sans)}
h1,h2,h3,h4{color:var(--ink)!important;font-family:var(--head)!important;font-weight:600}
.stMarkdown p,.stMarkdown li,label,.stCaption,[data-testid="stCaptionContainer"]{color:var(--mu)}
/* tabs */
div[data-baseweb="tab-list"]{gap:10px;background:#fff;border:2.5px solid var(--ink);padding:7px;border-radius:999px;box-shadow:4px 4px 0 var(--lav);width:fit-content;max-width:100%}
button[data-baseweb="tab"]{background:transparent;border-radius:999px;color:var(--ink);font:600 15px var(--head);padding:8px 22px;height:auto;transition:.2s}
button[data-baseweb="tab"] p{font-family:var(--head)!important;color:inherit!important}
button[data-baseweb="tab"]:hover{background:#ffe3f0}
button[data-baseweb="tab"][aria-selected="true"]{background:var(--pink);color:#fff;box-shadow:0 3px 0 #d6508a}
button[data-baseweb="tab"][aria-selected="true"] p{color:#fff!important}
div[data-baseweb="tab-highlight"],div[data-baseweb="tab-border"]{display:none}
/* uploader */
[data-testid="stFileUploaderDropzone"]{background:#fff;border:3px dashed var(--pink);border-radius:26px;padding:30px;transition:.25s;box-shadow:5px 5px 0 #ffd0e5}
[data-testid="stFileUploaderDropzone"]:hover{border-color:var(--lav);box-shadow:5px 5px 0 var(--lav);transform:translateY(-2px) rotate(-.3deg)}
[data-testid="stFileUploaderDropzone"] *{color:var(--mu)!important}
[data-testid="stFileUploaderDropzone"] button{border:2.5px solid var(--ink);background:var(--sky);color:var(--ink)!important;border-radius:999px;font-weight:800;box-shadow:3px 3px 0 var(--ink)}
[data-testid="stFileUploaderDropzone"] button *{color:var(--ink)!important}
/* buttons */
.stButton>button,.stDownloadButton>button{background:var(--pink);color:#fff;border:2.5px solid var(--ink);border-radius:999px;padding:.65rem 1.6rem;font:600 16px var(--head);box-shadow:4px 4px 0 var(--ink);transition:.15s}
.stButton>button:hover,.stDownloadButton>button:hover{transform:translate(-2px,-2px);box-shadow:6px 6px 0 var(--ink);background:#ff6aab;color:#fff;border-color:var(--ink)}
.stButton>button:active,.stDownloadButton>button:active{transform:translate(3px,3px);box-shadow:1px 1px 0 var(--ink)}
.stButton>button p,.stDownloadButton>button p{color:#fff!important;font-family:var(--head)!important}
/* inputs */
textarea,input{background:#fff!important;color:var(--ink)!important;border-radius:16px!important}
div[data-baseweb="textarea"],div[data-baseweb="base-input"],div[data-baseweb="select"]>div{background:#fff!important;border:2.5px solid var(--ink)!important;border-radius:16px!important;box-shadow:3px 3px 0 #e7dcff}
/* alerts, expanders, code */
[data-testid="stAlert"]{background:#fff;border:2.5px solid var(--ink);border-radius:18px;color:var(--ink);box-shadow:3px 3px 0 var(--peach)}
[data-testid="stAlert"] *{color:var(--ink)!important}
[data-testid="stExpander"]{background:#fff;border:2.5px solid var(--ink);border-radius:18px;box-shadow:3px 3px 0 var(--sky)}
[data-testid="stExpander"] summary,[data-testid="stExpander"] summary *{color:var(--ink)!important;font-weight:700}
pre,code{font-family:var(--mono)!important}
[data-testid="stCode"] pre,.stCodeBlock pre{background:#3a2146!important;border-radius:16px;color:#ffd9b8!important}
[data-testid="stImage"] img{border-radius:18px;border:2.5px solid var(--ink);box-shadow:4px 4px 0 var(--pink)}
[data-testid="stSpinner"] *{color:var(--pink)!important}
/* hero */
.hero{position:relative;padding:34px 34px 28px;border:3px solid var(--ink);border-radius:32px;background:linear-gradient(135deg,#ffd6ea 0%,#e6dcff 52%,#c9ecff 100%);overflow:hidden;margin-bottom:26px;box-shadow:7px 7px 0 var(--ink)}
.hero .blob{position:absolute;border-radius:50%;filter:blur(2px);opacity:.8;animation:float 9s ease-in-out infinite}
.hero .b1{width:190px;height:190px;background:#ffb27a;right:-50px;top:-60px}
.hero .b2{width:120px;height:120px;background:#fff;left:42%;bottom:-60px;animation-duration:12s;opacity:.6}
.hero .b3{width:80px;height:80px;background:#ff7eb6;right:26%;top:20px;animation-duration:7s;opacity:.55}
@keyframes float{0%,100%{transform:translate(0,0)}50%{transform:translate(-18px,16px)}}
.spark{position:absolute;color:#fff;font-size:22px;animation:twinkle 2.6s ease-in-out infinite;text-shadow:0 0 0 var(--ink)}
.spark:nth-of-type(1){left:46%;top:18px}.spark:nth-of-type(2){left:58%;top:96px;animation-delay:.8s;font-size:16px}.spark:nth-of-type(3){right:24px;bottom:60px;animation-delay:1.5s}
@keyframes twinkle{0%,100%{transform:scale(.5) rotate(0);opacity:.4}50%{transform:scale(1.2) rotate(25deg);opacity:1}}
.hero-row{display:flex;gap:24px;align-items:center;position:relative;z-index:2}
.hero-txt{flex:1;min-width:0}
.ghost{flex:none;width:150px;animation:bob 3.4s ease-in-out infinite}
@keyframes bob{0%,100%{transform:translateY(0) rotate(-3deg)}50%{transform:translateY(-14px) rotate(3deg)}}
.eyebrow{display:inline-block;font:700 12px var(--mono);letter-spacing:.16em;color:var(--ink);background:#fff;border:2px solid var(--ink);border-radius:999px;padding:4px 12px;margin-bottom:12px;box-shadow:2px 2px 0 var(--ink)}
@import url('https://fonts.googleapis.com/css2?family=Righteous&display=swap');
.peekabyte{font-family:'Righteous',cursive;font-size:clamp(38px,6vw,62px);background:linear-gradient(135deg,#ff4f9a,#8a5cff,#2aa8ff);-webkit-background-clip:text;background-clip:text;color:transparent;letter-spacing:2px;margin:0 0 6px;text-shadow:3px 3px 0 rgba(58,33,70,0.1);display:inline-block;animation:shine 5s linear infinite;background-size:200% 100%}
.grad{background:linear-gradient(90deg,#ff4f9a,#8a5cff,#2aa8ff,#ff4f9a);-webkit-background-clip:text;background-clip:text;color:transparent;background-size:200% 100%;animation:shine 5s linear infinite}
@keyframes shine{to{background-position:-200% 0}}
.hero p{color:#5a4470;max-width:560px;margin:0 0 16px;font-size:16.5px;line-height:1.55;font-weight:600}
.fmts{display:flex;flex-wrap:wrap;gap:8px}
.fmt{font:700 12px var(--mono);padding:5px 12px;border-radius:999px;color:var(--ink);border:2px solid var(--ink);box-shadow:2px 2px 0 var(--ink);transition:.2s}
.fmt:hover{transform:translateY(-3px) rotate(-3deg)}
.fmt:nth-child(5n+1){background:#ffc2de}.fmt:nth-child(5n+2){background:#d4c6ff}.fmt:nth-child(5n+3){background:#b9e3ff}.fmt:nth-child(5n+4){background:#ffd9b8}.fmt:nth-child(5n+5){background:#b8f0da}
.bits{margin-top:18px;overflow:hidden;white-space:nowrap;font:700 12px var(--mono);color:#8a5cff;opacity:.75;mask-image:linear-gradient(90deg,transparent,#000 12%,#000 88%,transparent)}
.bits span{display:inline-block;animation:marq 26s linear infinite}
@keyframes marq{from{transform:translateX(0)}to{transform:translateX(-50%)}}
/* verdict */
.verdict{display:flex;gap:26px;align-items:center;padding:24px 26px;border-radius:30px;border:3px solid var(--ink);background:#fff;margin:22px 0 16px;position:relative;overflow:hidden;box-shadow:6px 6px 0 var(--c)}
.verdict:after{content:"";position:absolute;right:-50px;top:-50px;width:220px;height:220px;border-radius:50%;background:var(--c);opacity:.14}
.ring{--p:0;flex:none;width:120px;height:120px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*1%),#f0e6f7 0);display:grid;place-items:center;border:3px solid var(--ink);position:relative;z-index:1}
.ring>div{width:88px;height:88px;border-radius:50%;background:#fff;border:3px solid var(--ink);display:grid;place-items:center;font:700 34px var(--head);color:var(--ink)}
.vtext{position:relative;z-index:1}
.vtext h2{margin:0 0 6px;font:700 28px var(--head)!important;color:var(--ink)!important}
.vtext p{margin:0 0 12px;color:var(--mu);font-weight:600}
.meta{display:flex;flex-wrap:wrap;gap:8px}
.meta span{font:700 12px var(--mono);padding:4px 11px;border-radius:999px;background:var(--cream);border:2px solid var(--ink);color:var(--ink)}
.lv-bad{--c:var(--bad)}.lv-warn{--c:var(--warn)}.lv-ok{--c:var(--ok)}
/* message window */
.term{border-radius:24px;border:3px solid var(--ink);background:var(--ink);margin:14px 0 24px;box-shadow:6px 6px 0 var(--pink);overflow:hidden}
.term-bar{display:flex;align-items:center;gap:7px;padding:11px 16px;background:#52306a;border-bottom:3px solid var(--ink);font:700 12px var(--mono);color:#e9dcff}
.dot{width:12px;height:12px;border-radius:50%;border:2px solid var(--ink)}.d1{background:var(--pink)}.d2{background:#ffd166}.d3{background:var(--mint)}
.term-body{padding:20px 22px;font:700 18px/1.6 var(--mono);color:#ffd9b8;word-break:break-word}
.term-body:after{content:"";display:inline-block;width:10px;height:20px;background:#ffd9b8;margin-left:4px;vertical-align:-4px;border-radius:3px;animation:blink 1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
/* evidence grid */
.sec{display:flex;align-items:center;gap:12px;margin:28px 0 14px;font:700 17px var(--head);color:var(--ink)}
.sec:before{content:"";width:16px;height:16px;border-radius:50%;background:var(--pink);border:2.5px solid var(--ink);box-shadow:2px 2px 0 var(--ink)}
.sec:after{content:"";flex:1;height:0;border-top:3px dotted var(--lav)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(285px,1fr));gap:18px}
.tile{--a:#ffc2de;position:relative;padding:18px 18px 16px;border-radius:24px;background:var(--a);border:3px solid var(--ink);box-shadow:5px 5px 0 var(--ink);transition:.2s;overflow:hidden}
.tile:nth-child(4n+2){--a:#d9ccff}.tile:nth-child(4n+3){--a:#bfe5ff}.tile:nth-child(4n+4){--a:#ffdcc0}
.tile:hover{transform:translate(-3px,-5px) rotate(-.6deg);box-shadow:8px 9px 0 var(--ink)}
.st-ok{--c:var(--ok)}.st-warn{--c:var(--warn)}.st-bad{--c:var(--bad)}.st-skip{--c:var(--skip)}
.th{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:8px}
.tn{font:600 17px/1.2 var(--head);color:var(--ink)}
.pill{font:800 11px var(--mono);letter-spacing:.05em;padding:4px 11px;border-radius:999px;color:#fff;background:var(--c);border:2px solid var(--ink);white-space:nowrap;box-shadow:2px 2px 0 var(--ink)}
.ts{color:#4b3560;font-size:14px;line-height:1.5;font-weight:600}
.tile details{margin-top:10px}
.tile summary{cursor:pointer;font:700 13px var(--head);color:var(--ink);list-style:none;display:inline-block;background:#fff;border:2px solid var(--ink);border-radius:999px;padding:3px 12px}
.tile summary::-webkit-details-marker{display:none}
.tile ul{margin:10px 0 0;padding:10px 14px 10px 28px;background:rgba(255,255,255,.75);border-radius:14px;color:var(--ink);font-size:13px;line-height:1.55;font-weight:600}
/* notes + done */
.notes{display:flex;flex-direction:column;gap:10px}
.note{padding:12px 16px;border-radius:18px;background:#fff;border:2.5px solid var(--ink);color:var(--ink);font-size:14px;font-weight:600;box-shadow:3px 3px 0 var(--sky)}
.done{display:flex;gap:16px;align-items:center;padding:20px 22px;border-radius:26px;border:3px solid var(--ink);background:#d6f7e9;margin:16px 0;box-shadow:5px 5px 0 var(--mint)}
.tick{flex:none;width:48px;height:48px;border-radius:50%;display:grid;place-items:center;background:var(--mint);border:3px solid var(--ink);color:#fff;font-size:24px;font-weight:700}
.done b{color:var(--ink);font:600 19px var(--head)}.done p{margin:2px 0 0;color:#3f5a52;font-size:14px;font-weight:600}
@media(max-width:640px){.verdict{flex-direction:column;text-align:center}.meta{justify-content:center}.ghost{display:none}.hero{padding:26px 20px}}
</style>"""



def hero():
    bits = "01001000 01101001 01100100 01100100 01100101 01101110 00100000 01100100 01100001 01110100 01100001 00100000 "
    fm = "".join(f'<span class="fmt">{f}</span>' for f in
                 ("PNG", "BMP", "WEBP", "GIF", "JPG", "WAV", "TIFF", "PDF", "HEIC",
                  "MP3", "FLAC", "OGG", "M4A", "ZIP", "DOCX", "XLSX"))
    ghost = ('<svg class="ghost" viewBox="0 0 150 160" xmlns="http://www.w3.org/2000/svg"><path d="M22 150V70C22 36 46 16 75 16s53 20 53 54v80l-18-14-17 14-18-14-18 14-17-14z" fill="#fff" stroke="#3a2146" stroke-width="5" stroke-linejoin="round"/><ellipse cx="55" cy="72" rx="7" ry="9" fill="#3a2146"><animate attributeName="ry" values="9;9;1;9;9" dur="4s" repeatCount="indefinite"/></ellipse><ellipse cx="95" cy="72" rx="7" ry="9" fill="#3a2146"><animate attributeName="ry" values="9;9;1;9;9" dur="4s" repeatCount="indefinite"/></ellipse><circle cx="42" cy="90" r="8" fill="#ff9cc8" opacity=".8"/><circle cx="108" cy="90" r="8" fill="#ff9cc8" opacity=".8"/><path d="M64 92q11 11 22 0" fill="none" stroke="#3a2146" stroke-width="5" stroke-linecap="round"/><circle cx="118" cy="104" r="19" fill="#c9ecff" fill-opacity=".7" stroke="#3a2146" stroke-width="5"/><path d="M131 118l14 16" stroke="#3a2146" stroke-width="7" stroke-linecap="round"/></svg>')
    return ('<div class="hero"><span class="blob b1"></span><span class="blob b2"></span><span class="blob b3"></span>'
            '<span class="spark">&#10022;</span><span class="spark">&#10022;</span><span class="spark">&#10022;</span>'
            '<div class="hero-row"><div class="hero-txt"><div class="eyebrow">🔍 PEEKABYTE  •  v1.0</div>'
            '<h1>Peek into every <span class="grad">byte</span> of a file.</h1>'
            '<p>One scan, zero secrets left. Detect hidden data, crack passwords, '
            'analyze audio, run forensics, hide your own messages, and compare files pixel by pixel.</p>'
            f'<div class="fmts">{fm}</div></div>' + ghost + '</div>'
            f'<div class="bits"><span>{bits * 8}</span></div></div>')


def _level(verdict):
    v = str(verdict).lower()
    if v.startswith("likely"):
        return "bad"
    if v.startswith("suspicious"):
        return "warn"
    return "ok"


def verdict(report):
    score = int(report.get("score", 0) or 0)
    lv = _level(report.get("verdict", ""))
    why = {"bad": "Evidence from the checks below points to hidden data.",
           "warn": "Something is unusual. It needs a closer look.",
           "ok": "No check found strong evidence. That does not prove the file is clean."}[lv]
    if report.get("hidden_message"):
        why = "A hidden message was extracted from this file."
    size = report.get("size", 0) or 0
    meta = (f'<span>{_t(report.get("file", "file"))}</span>'
            f'<span>{_t(str(report.get("type", "?")).upper())}</span>'
            f'<span>{size:,} bytes</span>')
    return (f'<div class="verdict lv-{lv}"><div class="ring" style="--p:{max(min(score, 100), 0)}">'
            f'<div>{score}</div></div><div class="vtext"><h2>{_t(report.get("verdict", ""))}</h2>'
            f'<p>{_t(why)}</p><div class="meta">{meta}</div></div></div>')


def message_box(report):
    msg = report.get("hidden_message")
    if not msg:
        return ""
    return ('<div class="term"><div class="term-bar"><span class="dot d1"></span>'
            '<span class="dot d2"></span><span class="dot d3"></span>'
            '<span style="margin-left:8px">hidden_message.txt</span></div>'
            f'<div class="term-body">{_t(msg)}</div></div>')


def stages(report):
    tiles = []
    for stage in report.get("stages", []):
        label, cls = STATUS.get(str(stage.get("status", "")).lower(), ("Unusual", "warn"))
        details = stage.get("details") or []
        det = ""
        if details:
            items = "".join(f"<li>{_t(_d(d))}</li>" for d in details)
            op = " open" if cls in ("bad", "warn") else ""
            det = f"<details{op}><summary>Show evidence ({len(details)})</summary><ul>{items}</ul></details>"
        tiles.append(f'<div class="tile st-{cls}"><div class="th"><span class="tn">{_t(stage.get("name", ""))}</span>'
                     f'<span class="pill">{label.upper()}</span></div>'
                     f'<div class="ts">{_t(stage.get("summary", ""))}</div>{det}</div>')
    return '<div class="sec">Evidence from each check</div><div class="grid">' + "".join(tiles) + "</div>"


def report_html(report):
    parts = [verdict(report), message_box(report), stages(report)]
    notes = report.get("notes") or []
    if notes:
        items = "".join(f'<div class="note">{_t(n)}</div>' for n in notes)
        parts.append(f'<div class="sec">Notes</div><div class="notes">{items}</div>')
    return "".join(parts)


def hide_done(name):
    return ('<div class="done"><div class="tick">&#10003;</div><div><b>Message hidden</b>'
            f'<p>Your file is ready: {_t(name)}. Keep it as it is: re-saving or sending it '
            'through chat apps can destroy the message.</p></div></div>')