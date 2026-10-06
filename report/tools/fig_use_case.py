"""Use case diagram (report Figure 6.4) - actors and what each can do in the current system."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, FancyBboxPatch

plt.rcParams["font.family"] = ["Arial", "Helvetica", "DejaVu Sans"]
W, H = 2400, 1440
fig = plt.figure(figsize=(12, 7.2), dpi=200)
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, W)
ax.set_ylim(H, 0)
ax.axis("off")


def actor(x, y, name, system=False):
    if system:
        ax.add_patch(FancyBboxPatch((x - 160, y - 45), 320, 90, boxstyle="round,pad=0,rounding_size=8", lw=1.6,
                                    ec="#333", fc="white"))
        ax.text(x, y - 14, "«system»", ha="center", va="center", fontsize=8, color="#555")
        ax.text(x, y + 16, name, ha="center", va="center", fontsize=9.5, weight="bold")
        return
    ax.add_patch(plt.Circle((x, y - 95), 26, fill=False, lw=1.8, color="#222"))
    ax.plot([x, x], [y - 69, y + 10], color="#222", lw=1.8)
    ax.plot([x - 45, x + 45], [y - 40, y - 40], color="#222", lw=1.8)
    ax.plot([x, x - 38], [y + 10, y + 75], color="#222", lw=1.8)
    ax.plot([x, x + 38], [y + 10, y + 75], color="#222", lw=1.8)
    ax.text(x, y + 115, name, ha="center", va="center", fontsize=9.5, weight="bold")


def case(x, y, text, w=470, h=74):
    ax.add_patch(Ellipse((x, y), w, h, fc="#edf2fb", ec="#1f4e9c", lw=1.6))
    ax.text(x, y, text, ha="center", va="center", fontsize=8.6)
    return (x, y, w)


ax.add_patch(FancyBboxPatch((560, 70), 1280, 1290, boxstyle="round,pad=0,rounding_size=20", lw=1.8,
                            ec="#1f4e9c", fc="#fafbfe"))
ax.text(1200, 110, "UEBA System", ha="center", fontsize=11.5, weight="bold", color="#1f4e9c")

L, R = 950, 1450       # two columns of use cases
uc = {
    "overview": case(L, 200, "View security overview"),
    "cases": case(L, 300, "Triage cases and alerts"),
    "investigate": case(L, 400, "Investigate a user or device"),
    "verdict": case(L, 500, "Record verdict / close case"),
    "suppress": case(L, 600, "Suppress a known-benign pattern"),
    "logs": case(L, 700, "Explore and export logs"),
    "notify": case(L, 840, "Receive alert notifications"),
    "perf": case(L, 980, "View model performance"),
    "threshold": case(L, 1080, "Tune the alert threshold"),
    "upload": case(R, 200, "Upload logs, map columns"),
    "collect": case(R, 300, "Configure automatic collection"),
    "analyse": case(R, 400, "Analyse / re-train models"),
    "notifcfg": case(R, 500, "Configure notifications"),
    "users": case(R, 600, "Manage users and roles"),
    "tokens": case(R, 700, "Issue / revoke API tokens"),
    "audit": case(R, 800, "Review the audit log"),
    "ingest": case(R, 1180, "Send logs (API / drop folder)"),
    "score": case(R, 1300, "Import, score incrementally, notify"),
}

actor(260, 420, "SOC Analyst")
actor(260, 1120, "Security Manager")
actor(2140, 520, "Administrator")
actor(2140, 1180, "Agent / log shipper", system=True)
actor(2140, 1320, "Collector service", system=True)


def link(a, key, side="left", color="#555"):
    x, y, w = uc[key]
    ex = x - w / 2 if side == "left" else x + w / 2
    ax.plot([a[0], ex], [a[1], y], color=color, lw=0.9, alpha=0.8)


analyst, manager, admin = (305, 380), (305, 1080), (2095, 480)
for k in ("overview", "cases", "investigate", "verdict", "suppress", "logs", "notify"):
    link(analyst, k)
for k in ("notify", "perf", "threshold"):
    link(manager, k)
for k in ("upload", "collect", "analyse", "notifcfg", "users", "tokens", "audit"):
    link(admin, k, side="right")
ax.plot([1980, R + 235], [1180, 1180], color="#555", lw=0.9)
ax.plot([1980, R + 235], [1320, 1300], color="#555", lw=0.9)
ax.text(1200, 1405, "Every person signs in. Viewers can only read; analysts can also triage; administrators can also "
        "manage data, settings, users and tokens.",
        ha="center", fontsize=8.5, color="#444", style="italic")
fig.savefig("/Users/amaan/Desktop/InHouse Project/report/diagrams/5_use_case.png", dpi=200, facecolor="white")
print("saved")
