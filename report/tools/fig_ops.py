"""Figure: operational architecture, styled like report/diagrams/1_architecture.png (2400 x 1250 px)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

plt.rcParams["font.family"] = ["Arial", "Helvetica", "DejaVu Sans"]
W, H = 2400, 1130
fig = plt.figure(figsize=(12, 5.65), dpi=200)          # 1 pt = 2.78 px
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, W)
ax.set_ylim(H, 0)
ax.axis("off")

BLUE = ("#1f4e9c", "#edf2fb"); GREY = ("#222222", "#f2f2f2"); GREEN = ("#1d7a4c", "#eef7f1")
VIOLET = ("#4b3aa7", "#f0eefb"); ORANGE = ("#c25a1c", "#fdf1ea"); RED = ("#a2272c", "#fbefef")
GOLD = ("#b58a12", "#fdf8ea"); NAVY = ("#14213d", "#14213d"); DASH = ("#666666", "#ffffff")
TITLE, SUB = 10.5, 8


def box(x, y, w, h, title, sub="", c=GREY, dashed=False, dark=False):
    ec, fc = c
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=16", lw=2.2, ec=ec, fc=fc,
                                ls=(0, (4, 3)) if dashed else "-"))
    col = "white" if dark else "#111111"
    lines = sub.count("\n") + 1 if sub else 0
    ty = y + h / 2 - (lines * 13 if sub else 0)
    ax.text(x + w / 2, ty, title, ha="center", va="center", fontsize=TITLE, weight="bold", color=col)
    if sub:
        ax.text(x + w / 2, ty + 34, sub, ha="center", va="top", fontsize=SUB, color=col if dark else "#333333",
                linespacing=1.45)
    return dict(l=(x, y + h / 2), r=(x + w, y + h / 2), t=(x + w / 2, y), b=(x + w / 2, y + h),
                x=x, y=y, w=w, h=h)


def arrow(p, q, rad=0.0, dashed=False, color="#333333"):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=18, lw=1.8, color=color,
                                 connectionstyle=f"arc3,rad={rad}", ls=(0, (5, 4)) if dashed else "-",
                                 shrinkA=3, shrinkB=4))


def note(x, y, text, **kw):
    ax.text(x, y, text, fontsize=8, color="#1f4e9c", style="italic", **kw)


COLS = [(40, "SOURCES"), (500, "INGESTION"), (960, "COLLECTOR SERVICE"), (1440, "STORAGE"), (1920, "PEOPLE")]
for x, t in COLS:
    ax.text(x + 10, 60, t, fontsize=10.5, weight="bold", color="#1f4e9c", va="center")

# sources
agent = box(40, 110, 380, 140, "Endpoint agent", "CPU, memory, connections\nstore-and-forward", BLUE)
ship = box(40, 300, 380, 140, "Log shippers / SIEM", "auth, proxy, firewall exports", BLUE)
upl = box(40, 490, 380, 140, "Analyst upload", "CSV / JSON / ZIP\ncolumn mapping + preview", BLUE)
rep = box(40, 680, 380, 120, "Replay feed", "dataset streamed as if live", DASH, dashed=True)
# ingestion
api = box(500, 110, 380, 150, "Ingest API", "token auth, per workspace\n202 Accepted, batch queued", GREY)
inbox = box(500, 300, 380, 140, "Workspace inbox/", "drop folder\nfailed/ + reason file", GREY)
imp = box(500, 490, 380, 160, "Import & normalise", "stream detection, mapping,\nde-duplicated append", GREY)
# collector service
eng = box(960, 300, 400, 240, "Incremental engine", "models trained once\nonly changed days re-scored\n= identical to a full re-run\n(re-trains when settings change)",
          VIOLET)
nt = box(960, 760, 400, 150, "Notifications", "webhook / e-mail\nde-duplicated, escalations", ORANGE)
# storage
con = box(1440, 110, 400, 150, "console.db", "users (PBKDF2), roles\nAPI tokens (SHA-256), audit", RED)
ws = box(1440, 300, 400, 210, "Workspace store", "raw logs · models.joblib\nueba.db: features, scores,\nalerts, analyst verdicts", GREEN)
# people
ui = box(1920, 300, 420, 210, "SOC console", "login · roles · live refresh\ntriage · investigate\nadministration", NAVY, dark=True)
an = box(1920, 760, 420, 150, "Analysts", "alerts in Slack / Teams / e-mail", GOLD)

# sources -> ingestion
arrow(agent["r"], api["l"])
arrow((420, 340), (500, 215), rad=0.15)                 # shippers -> API
arrow(ship["r"], inbox["l"], dashed=True)               # shippers -> drop folder
arrow(upl["r"], (500, 560))                             # upload -> import
arrow((420, 720), (500, 410), rad=0.25, dashed=True)    # replay -> inbox
arrow(api["b"], inbox["t"])
arrow(inbox["b"], imp["t"])
# ingestion -> storage -> engine
arrow((880, 620), (1560, 512), rad=0.32)              # import -> store, routed under the engine
note(1270, 690, "new rows + earliest changed day", va="top")
arrow((1440, 370), (1360, 370))                        # store -> engine (logs, models)
arrow((1360, 460), (1440, 460))                        # engine -> store (scores, alerts)
arrow(eng["b"], nt["t"])
note(1150, 650, "new / escalated\nalerts", ha="right", linespacing=1.3)
arrow(nt["r"], an["l"])
# storage -> people
arrow(ws["r"], ui["l"])
arrow(con["r"], (2130, 300), rad=-0.25)
arrow((1440, 185), (880, 185), dashed=True, color="#a2272c")      # token check
note(1000, 168, "token check")
# feedback loop
arrow((2130, 510), (1640, 510), rad=-0.45, dashed=True, color="#b58a12")
note(1885, 640, "verdicts → re-score the following days", ha="center")

ax.text(W / 2, 985, "Collector service pass (every 10 s by default):  import inbox  →  incremental analysis if "
        "anything changed  →  notify", ha="center", fontsize=9, color="#222222")
ax.text(W / 2, 1035, "A broken file goes to failed/ with a reason; a broken workspace never stops the others; "
        "workspace changes run under a file lock.", ha="center", fontsize=9, color="#222222")
fig.savefig("/Users/amaan/Desktop/InHouse Project/report/diagrams/6_operational_architecture.png", dpi=200,
            facecolor="white")
print("saved")
