"""Builds the speaker script PDF from script.json and the rendered slide thumbnails.

Run from this folder:  python3 build_script_pdf.py   ->  ~/Downloads/UEBA_Presentation_Script.pdf
"""
import base64
import html
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).parent
OUT = Path.home() / "Downloads" / "UEBA_Presentation_Script.pdf"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
SCRIPT = json.loads((HERE / "script.json").read_text())
COLOR = {"Amaan": "#0FB5A6", "Tarun": "#F5A524"}

QA = [
    ("Why do you call it AI-based?", "Amaan",
     "Detection uses machine learning: an unsupervised ensemble (Isolation Forest, LOF, autoencoder) that learns each "
     "user's normal behaviour. On top, a local language model explains the findings. It is not just hand-written rules."),
    ("Why unsupervised and not a classifier?", "Tarun",
     "Real organisations have almost no labelled attacks, and the next attack is not like the last one. Learning "
     "'normal' needs no labels and can flag new techniques."),
    ("Isn't testing on your own simulated data circular?", "Tarun",
     "Partly, which is why we also used CERT r4.2 from Carnegie Mellon, which we did not design, and raw Linux, "
     "Windows and proxy logs. Results hold across five differently generated companies (mean F1 0.94)."),
    ("Why doesn't the language model decide the alerts?", "Amaan",
     "It can make things up and cannot be measured like a detector. The ML and rules decide and are evaluated; the "
     "language model only explains, from their facts, and runs locally so no data leaves."),
    ("How do you keep false alarms low?", "Amaan",
     "The threshold needs two layers to agree, so one odd statistic can never alert on its own. That raised precision "
     "from 0.31 to above 0.9. Analysts can also suppress known-harmless patterns."),
    ("What happens with real company logs?", "Amaan",
     "Upload them: it recognises Linux auth logs, Windows .evtx and Event Viewer exports, Sysmon, Squid proxy logs and "
     "CSV, and maps the columns automatically. We tested it on 278 real Windows attack log files."),
    ("Who did what in the project?", "Tarun",
     "Amaan led the system design and implementation; Tarun led the documentation, the report and the project "
     "paperwork. We prepared this presentation together."),
]


def img(n: int) -> str:
    data = base64.b64encode((HERE / "render" / f"slide-{n:02d}.jpg").read_bytes()).decode()
    return f"data:image/jpeg;base64,{data}"


def badge(who: str) -> str:
    return f'<span class="badge" style="background:{COLOR[who]}">{who}</span>'


def main():
    words = {"Amaan": 0, "Tarun": 0}
    for s in SCRIPT:
        for p in s["parts"]:
            words[p["who"]] += len(p["text"].split())
    mins = {k: v / 135 for k, v in words.items()}
    rows = "".join(
        f"<tr><td>{s['slide']}</td><td>{html.escape(s['title'])}</td>"
        f"<td>{' + '.join(badge(w) for w in dict.fromkeys(p['who'] for p in s['parts']))}</td><td>{s['time']}</td></tr>"
        for s in SCRIPT)
    blocks = []
    for s in SCRIPT:
        parts = "".join(
            f'<div class="part"><div class="who">{badge(p["who"])}</div><p>{html.escape(p["text"])}</p></div>'
            for p in s["parts"])
        nxt = next((x for x in SCRIPT if x["slide"] == s["slide"] + 1), None)
        hand = ""
        if nxt and nxt["parts"][0]["who"] != s["parts"][-1]["who"]:
            hand = (f'<div class="hand">Hand over to <b>{nxt["parts"][0]["who"]}</b>, who clicks to slide '
                    f'{nxt["slide"]}</div>')
        blocks.append(f"""
        <section class="slide">
          <div class="thumb"><img src="{img(s['slide'])}"><div class="cap">Slide {s['slide']} · {s['time']}</div></div>
          <div class="text"><h3>{s['slide']}. {html.escape(s['title'])}</h3>{parts}{hand}</div>
        </section>""")
    qa = "".join(f"<tr><td><b>{html.escape(q)}</b></td><td>{badge(w)}</td><td>{html.escape(a)}</td></tr>"
                 for q, w, a in QA)
    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>UEBA Presentation Script</title>
<style>
@page {{ size: A4; margin: 13mm 14mm; }}
body {{ font-family: -apple-system, "Helvetica Neue", Arial, sans-serif; font-size: 10.4pt; line-height: 1.45; color: #0B1220; margin: 0; }}
h1 {{ font-size: 20pt; margin: 0; color: #102A43; }}
.sub {{ color: #5B6B8C; margin: 2px 0 10px; }}
h2 {{ font-size: 13pt; color: #102A43; margin: 16px 0 6px; }}
h3 {{ font-size: 11.5pt; margin: 0 0 6px; color: #102A43; }}
table {{ width: 100%; border-collapse: collapse; margin: 4px 0 8px; }}
th, td {{ text-align: left; vertical-align: top; padding: 5px 7px; border-bottom: 1px solid #E1E6EE; }}
th {{ background: #EEF3F8; font-size: 9pt; text-transform: uppercase; letter-spacing: .3px; color: #3D4A63; }}
tr {{ page-break-inside: avoid; }}
.badge {{ display: inline-block; color: #0B1220; font-weight: 700; font-size: 8.8pt; padding: 1px 8px; border-radius: 9px; }}
.split {{ display: flex; gap: 10px; margin: 6px 0 4px; }}
.split div {{ flex: 1; border-radius: 6px; padding: 8px 10px; background: #EEF3F8; }}
.split b {{ font-size: 15pt; }}
.slide {{ display: flex; gap: 14px; padding: 10px 0; border-bottom: 1px solid #E1E6EE; page-break-inside: avoid; }}
.thumb {{ flex: 0 0 210px; }}
.thumb img {{ width: 210px; border: 1px solid #D5DEE8; border-radius: 4px; }}
.cap {{ font-size: 8.6pt; color: #5B6B8C; margin-top: 3px; }}
.text {{ flex: 1; }}
.part {{ margin-bottom: 6px; }}
.part p {{ margin: 3px 0 0; }}
.hand {{ font-size: 9pt; color: #5B6B8C; font-style: italic; margin-top: 4px; }}
.tips li {{ margin: 2px 0; }}
.pb {{ page-break-before: always; }}
</style></head><body>
<h1>Presentation Script: AI-Based UEBA System</h1>
<div class="sub">In-house project · B.Tech CSE (Cyber Security), 7th semester, batch 2023–2027 · Alliance University ·
Supervisor: Dr. Rathnakar Achary</div>

<h2>Who speaks when</h2>
<div class="split">
  <div>{badge("Amaan")} &nbsp;<b>~{mins['Amaan']:.1f} min</b><br>Opening line, architecture, detection, AI assistant, console,
  security, first half of the conclusion</div>
  <div>{badge("Tarun")} &nbsp;<b>~{mins['Tarun']:.1f} min</b><br>Introductions, problem, objectives, related work, results,
  limitations, closing and questions</div>
</div>
<p>Total about <b>{(mins['Amaan'] + mins['Tarun']):.0f} minutes</b> at a calm pace, plus questions. Whoever speaks controls the clicker.
The full lines are also in the PowerPoint speaker notes (Presenter View).</p>
<table><tr><th style="width:6%">#</th><th>Slide</th><th style="width:22%">Speaker</th><th style="width:9%">Time</th></tr>{rows}</table>

<h2>Delivery tips</h2>
<ul class="tips">
<li>Don't read the slides aloud. Use the lines below as a guide, in your own words.</li>
<li>On slide 9, point at the big numbers first, then the chart. Say "12 out of 12" slowly.</li>
<li>On slide 7, point at the screenshot: "this is real output from our system."</li>
<li>If a slide runs long, skip a sentence, not the handover. Keep each slide under a minute.</li>
<li>Stand on opposite sides of the screen, and step forward when it's your turn.</li>
</ul>

<h2 class="pb">Slide-by-slide script</h2>
{''.join(blocks)}

<h2 class="pb">Likely questions and who answers</h2>
<table><tr><th style="width:27%">Question</th><th style="width:10%">Answers</th><th>Answer in short</th></tr>{qa}</table>
<p class="cap">If one of you is unsure, the other can add: "To add to that..." It's fine to answer together.</p>
</body></html>"""
    html_path = HERE / "render" / "script.html"
    html_path.write_text(doc)
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                    f"--print-to-pdf={OUT}", html_path.as_uri()], check=True, capture_output=True)
    print("wrote", OUT, words)


if __name__ == "__main__":
    main()
