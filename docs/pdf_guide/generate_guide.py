#!/usr/bin/env python3
"""Regenerate docs/network_scanner_guide.pdf from scratch.

The PDF documents network_scanner.py and mobile_network_scanner.py: how to
pull each one, how to run it, a full options table, a pipeline diagram of
its discovery flow, and a color-coded terminal mockup explaining the
NEW/CHG/risky/missing markers both scripts share.

This script is the *source* for that PDF - the PDF itself is a generated
artifact, kept in the repo for convenience (so nobody needs Python/reportlab
just to read it), but this script is what to edit and rerun whenever either
scanner's flags or behavior change enough that the PDF would go stale.

Usage:
    pip install -r docs/pdf_guide/requirements.txt
    python3 docs/pdf_guide/generate_guide.py

Requires reportlab, matplotlib, and Pillow (see requirements.txt) - none of
which the scanner scripts themselves depend on, so these stay isolated to
this one docs-generation script rather than the project's main dependencies.
"""

import tempfile
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from PIL import Image as PILImage
from PIL import ImageDraw, ImageFont
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_PDF = REPO_ROOT / "docs" / "network_scanner_guide.pdf"

REPO_URL = "https://github.com/thomasmd321/Test-repo"
BRANCH = "claude/local-network-device-discovery-joawq5"


# =========================================================================
# Part 1: pipeline flow diagrams (matplotlib)
# =========================================================================

BOX_FILL = "#eef2f7"
BOX_EDGE = "#3a5a7a"
TEXT_COLOR = "#1c2b3a"
ARROW_COLOR = "#5a6b7a"
WARN_FILL = "#fdecec"
WARN_EDGE = "#b23b3b"


def _box(ax, xy, w, h, text, fill=BOX_FILL, edge=BOX_EDGE, fontsize=10.5, fontweight="normal"):
    x, y = xy
    patch = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.02,rounding_size=0.08",
        linewidth=1.6, edgecolor=edge, facecolor=fill,
    )
    ax.add_patch(patch)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
             fontsize=fontsize, color=TEXT_COLOR, fontweight=fontweight, wrap=True)
    return (x, y, w, h)


def _arrow(ax, start, end, label=None, color=ARROW_COLOR, style="-|>", label_t=0.5):
    a = FancyArrowPatch(start, end, arrowstyle=style, mutation_scale=16,
                         linewidth=1.6, color=color, shrinkA=2, shrinkB=2)
    ax.add_patch(a)
    if label:
        mx = start[0] + (end[0] - start[0]) * label_t
        my = start[1] + (end[1] - start[1]) * label_t
        ax.text(mx, my + 0.12, label, ha="center", va="bottom", fontsize=8.5,
                 color=color, style="italic")


def _top(b):
    x, y, w, h = b
    return (x + w / 2, y + h)


def _bottom(b):
    x, y, w, h = b
    return (x + w / 2, y)


def _right(b):
    x, y, w, h = b
    return (x + w, y + h / 2)


def make_desktop_diagram(out_path: Path) -> None:
    """The network_scanner.py discovery pipeline, start to finish."""
    fig, ax = plt.subplots(figsize=(7.2, 6.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 12)
    ax.axis("off")

    b_start = _box(ax, (2.7, 10.6), 4.6, 1.0, "network_scanner.py [subnet]", fontweight="bold")

    b_arp = _box(ax, (0.4, 9.0), 4.2, 1.0, "ARP scan (scapy)\nfast, returns MAC directly")
    b_ping = _box(ax, (5.4, 9.0), 4.2, 1.0, "Ping sweep + read\nsystem ARP table")

    _arrow(ax, _bottom(b_start), _top(b_arp))
    _arrow(ax, _bottom(b_start), _top(b_ping), label="scapy missing / unprivileged", label_t=0.7)

    b_host = _box(ax, (2.7, 7.4), 4.6, 1.1, "Hostname resolution\nreverse DNS -> mDNS -> DNS-SD (Cast)")
    _arrow(ax, _bottom(b_arp), _top(b_host))
    _arrow(ax, _bottom(b_ping), _top(b_host))

    b_vendor = _box(ax, (2.7, 5.9), 4.6, 1.0, "MAC vendor lookup\nIEEE OUI registry (cached)")
    _arrow(ax, _bottom(b_host), _top(b_vendor))

    b_ipv6 = _box(ax, (0.4, 5.9), 1.9, 1.0, "--ipv6\nNDP scan", fill="#f2f2f2", fontsize=9)
    _arrow(ax, _right(b_ipv6), (2.7, 6.4), color="#9aa5ad")

    b_ports = _box(ax, (2.7, 4.4), 4.6, 1.1, "Port scan (DEFAULT_PORTS)\n+ independent RISKY_PORTS check")
    _arrow(ax, _bottom(b_vendor), _top(b_ports))

    b_track = _box(ax, (2.7, 2.9), 4.6, 1.1, "Compare against known-devices\nregistry: NEW / CHG / missing")
    _arrow(ax, _bottom(b_ports), _top(b_track))

    b_out = _box(ax, (2.2, 1.2), 5.6, 1.1, "Colorized results table\n(green NEW, yellow CHG, red risky)",
                 fill="#e9f5ee", edge="#2f6b46", fontweight="bold")
    _arrow(ax, _bottom(b_track), _top(b_out))

    ax.text(5, 0.5, "Falls back automatically when scapy / raw sockets aren't available.",
            ha="center", fontsize=8.5, color="#5a6b7a", style="italic")

    plt.tight_layout()
    plt.savefig(out_path, dpi=220, bbox_inches="tight")
    plt.close(fig)


def make_mobile_diagram(out_path: Path) -> None:
    """The mobile_network_scanner.py discovery pipeline, start to finish."""
    fig, ax = plt.subplots(figsize=(7.2, 6.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 12)
    ax.axis("off")

    b_start = _box(ax, (2.2, 10.6), 5.6, 1.0, "mobile_network_scanner.py [subnet]", fontweight="bold")

    b_warn = _box(ax, (0.3, 9.0), 3.6, 1.2,
                  "iOS sandbox blocks:\nsubprocess, raw sockets,\nmulticast receive",
                  fill=WARN_FILL, edge=WARN_EDGE, fontsize=9)

    b_probe = _box(ax, (4.2, 9.0), 5.5, 1.0, "Plain TCP connect probe\n(DEFAULT_PORTS, per host, threaded)")
    _arrow(ax, _bottom(b_start), _top(b_probe))
    _arrow(ax, _right(b_warn), (4.2, 9.5), color=WARN_EDGE, style="-[")

    b_host = _box(ax, (2.2, 7.4), 5.6, 1.1,
                  "Hostname resolution\nCast DNS-SD -> reverse DNS -> mDNS lookup", fontsize=9.8)
    _arrow(ax, _bottom(b_probe), _top(b_host))

    b_banner = _box(ax, (2.2, 5.9), 5.6, 1.0, "Banner grab on the matched port\n(HTTP HEAD, or passive listen)")
    _arrow(ax, _bottom(b_host), _top(b_banner))

    b_risky = _box(ax, (2.2, 4.4), 5.6, 1.0, "Independent risky-port check\n(RISKY_PORTS, same as desktop)")
    _arrow(ax, _bottom(b_banner), _top(b_risky))

    b_track = _box(ax, (2.2, 2.9), 5.6, 1.1, "Compare against known-devices\nregistry: NEW / CHG / missing")
    _arrow(ax, _bottom(b_risky), _top(b_track))

    b_out = _box(ax, (2.2, 1.2), 5.6, 1.1, "Colorized results table\n(green NEW, yellow CHG, red risky)",
                 fill="#e9f5ee", edge="#2f6b46", fontweight="bold")
    _arrow(ax, _bottom(b_track), _top(b_out))

    ax.text(5, 0.5, "No ARP, no IPv6 discovery, no MAC vendor lookup - ordinary sockets only.",
            ha="center", fontsize=8.5, color="#5a6b7a", style="italic")

    plt.tight_layout()
    plt.savefig(out_path, dpi=220, bbox_inches="tight")
    plt.close(fig)


# =========================================================================
# Part 2: terminal-output mockup (Pillow)
# =========================================================================

_FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/local/lib/python3.11/dist-packages/matplotlib/mpl-data/fonts/ttf/DejaVuSansMono.ttf",
]
_FONT_BOLD_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/local/lib/python3.11/dist-packages/matplotlib/mpl-data/fonts/ttf/DejaVuSansMono-Bold.ttf",
]


def _first_existing(candidates):
    for path in candidates:
        if Path(path).exists():
            return path
    raise FileNotFoundError(f"None of the candidate fonts exist: {candidates}")


def make_terminal_mockup(out_path: Path) -> None:
    """A realistic, hand-composed rendering of colorized scan output.

    Not a real screenshot (there's no GUI here to capture) - built from the
    same colors _colorize()/_ANSI_CODES actually use, laid out to match the
    real results-table format, so it's an accurate stand-in.
    """
    w, h = 1500, 620
    bg = (30, 33, 38)
    fg = (222, 226, 230)
    green = (98, 209, 130)
    yellow = (232, 197, 92)
    red = (233, 105, 100)
    dim = (128, 136, 143)
    header = (150, 200, 240)

    img = PILImage.new("RGB", (w, h), bg)
    draw = ImageDraw.Draw(img)

    font = ImageFont.truetype(_first_existing(_FONT_CANDIDATES), 22)
    font_bold = ImageFont.truetype(_first_existing(_FONT_BOLD_CANDIDATES), 22)

    draw.rectangle([0, 0, w, 42], fill=(45, 48, 54))
    for i, color in enumerate([(233, 105, 100), (232, 197, 92), (98, 209, 130)]):
        draw.ellipse([20 + i * 28, 14, 34 + i * 28, 28], fill=color)
    draw.text((w / 2 - 90, 10), "python3 network_scanner.py", font=font, fill=(170, 176, 182))

    x0, y = 24, 64
    line_h = 30

    def line(text, color=fg, bold=False):
        nonlocal y
        draw.text((x0, y), text, font=(font_bold if bold else font), fill=color)
        y += line_h

    line("Scanning 192.168.1.0/24 ...", dim)
    y += 10
    line("     IP Address        MAC Address         Vendor      Port  Service   Hostname", header, bold=True)
    line("-" * 100, dim)
    line("NEW  192.168.1.42       3c:22:fb:1a:9c:04   Apple, Inc  62078 lockdownd iPhone.local", green)
    line("     192.168.1.1        aa:bb:cc:dd:ee:ff   Netgear     80    http      router.local")
    line("CHG  192.168.1.57       10:2c:6b:44:2a:11   Sonos       23    ?         kitchen-speaker.local", yellow)
    line("     192.168.1.72       b0:c5:54:2f:88:19   Google      8009  chromecast Living Room TV")
    line("     192.168.1.88       f4:5e:ab:12:34:56   Synology    445   smb       nas.local        (risky)", red)
    y += 14
    line("5 device(s) found. 1 new since last seen.", dim)
    y += 8
    line("2 previously-seen device(s) not found in this scan:", dim)
    line("  192.168.1.63          last seen 2026-09-14T08:03:00  (laptop.local)", dim)
    y += 8
    line("1 device(s) with a changed port since last seen:", yellow, bold=True)
    line("  192.168.1.57          (none) -> telnet (23)", yellow)
    y += 8
    line("⚠ 1 device(s) exposing commonly-risky ports:", red, bold=True)
    line("  192.168.1.88          f4:5e:ab:12:34:56   smb (445)", red)

    img.save(out_path)


# =========================================================================
# Part 3: the PDF itself (reportlab)
# =========================================================================

def build_pdf(desktop_diagram: Path, mobile_diagram: Path, terminal_mockup: Path, out_path: Path) -> None:
    styles = getSampleStyleSheet()

    navy = colors.HexColor("#1c2b3a")
    steel = colors.HexColor("#3a5a7a")
    muted = colors.HexColor("#5a6b7a")
    code_bg = colors.HexColor("#f4f6f8")
    code_border = colors.HexColor("#d6dde3")

    styles.add(ParagraphStyle(name="DocTitle", fontName="Helvetica-Bold", fontSize=26,
                               textColor=navy, spaceAfter=6, leading=30))
    styles.add(ParagraphStyle(name="DocSubtitle", fontName="Helvetica", fontSize=13,
                               textColor=muted, spaceAfter=4, leading=17))
    styles.add(ParagraphStyle(name="H1", fontName="Helvetica-Bold", fontSize=18,
                               textColor=navy, spaceBefore=18, spaceAfter=8))
    styles.add(ParagraphStyle(name="H2", fontName="Helvetica-Bold", fontSize=13.5,
                               textColor=steel, spaceBefore=12, spaceAfter=6))
    styles.add(ParagraphStyle(name="Body", fontName="Helvetica", fontSize=10.2,
                               textColor=colors.HexColor("#26313c"), leading=14.5, spaceAfter=6))
    styles.add(ParagraphStyle(name="BodySmall", fontName="Helvetica", fontSize=9,
                               textColor=muted, leading=12.5, spaceAfter=4))
    styles.add(ParagraphStyle(name="CodeText", fontName="Courier", fontSize=9.3,
                               textColor=colors.HexColor("#16324f"), leading=13))
    styles.add(ParagraphStyle(name="Caption", fontName="Helvetica-Oblique", fontSize=8.7,
                               textColor=muted, spaceAfter=10, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="FlagName", fontName="Courier-Bold", fontSize=8.6,
                               textColor=navy, leading=11.5))
    styles.add(ParagraphStyle(name="FlagDesc", fontName="Helvetica", fontSize=8.6,
                               textColor=colors.HexColor("#26313c"), leading=11.5))
    styles.add(ParagraphStyle(name="TableHead", fontName="Helvetica-Bold", fontSize=9.2,
                               textColor=colors.white, leading=12))
    styles.add(ParagraphStyle(name="CompareLabel", fontName="Helvetica-Bold", fontSize=8.8,
                               textColor=navy, leading=11.5))
    styles.add(ParagraphStyle(name="CompareCell", fontName="Helvetica", fontSize=8.8,
                               textColor=colors.HexColor("#26313c"), leading=11.5))

    def code_block(text):
        lines = text.strip("\n").split("\n")
        para = Paragraph("<br/>".join(l.replace(" ", "&nbsp;") for l in lines), styles["CodeText"])
        t = Table([[para]], colWidths=[6.5 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), code_bg),
            ("BOX", (0, 0), (-1, -1), 0.75, code_border),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        return t

    def options_table(rows):
        data = [[Paragraph("Flag", styles["TableHead"]), Paragraph("What it does", styles["TableHead"])]]
        for flag, desc in rows:
            data.append([Paragraph(flag, styles["FlagName"]), Paragraph(desc, styles["FlagDesc"])])
        t = Table(data, colWidths=[1.9 * inch, 4.6 * inch], repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), steel),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("LINEBELOW", (0, 0), (-1, 0), 0.75, steel),
            ("LINEBELOW", (0, 1), (-1, -1), 0.5, colors.HexColor("#e3e8ec")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        for i in range(1, len(data)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f8fafb")))
        t.setStyle(TableStyle(style))
        return t

    def crow(label, a, b):
        return [Paragraph(label, styles["CompareLabel"]), Paragraph(a, styles["CompareCell"]),
                Paragraph(b, styles["CompareCell"])]

    story = []

    # ------------------------------------------------------------ Title page
    story.append(Spacer(1, 1.1 * inch))
    story.append(Paragraph("Network Scanner Scripts", styles["DocTitle"]))
    story.append(Paragraph(
        "Pulling, running, and configuring network_scanner.py and mobile_network_scanner.py",
        styles["DocSubtitle"]))
    story.append(Spacer(1, 0.15 * inch))
    story.append(HRFlowable(width="100%", thickness=1, color=code_border))
    story.append(Spacer(1, 0.35 * inch))
    story.append(Paragraph(
        f"Repository: <font face='Courier'>{REPO_URL}</font><br/>"
        f"Branch: <font face='Courier'>{BRANCH}</font>",
        styles["Body"]))
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(
        "Both scripts discover devices on your local network with no external service and no "
        "account required. <b>network_scanner.py</b> targets a normal desktop/Termux environment "
        "and can read ARP/MAC data directly; <b>mobile_network_scanner.py</b> targets a sandboxed "
        "environment such as an iPhone running a-Shell, where the OS blocks raw sockets and "
        "subprocess calls, so it relies on plain TCP connections instead.", styles["Body"]))
    story.append(Spacer(1, 0.3 * inch))

    compare_data = [
        [Paragraph("", styles["TableHead"]), Paragraph("network_scanner.py", styles["TableHead"]),
         Paragraph("mobile_network_scanner.py", styles["TableHead"])],
        crow("Target platform", "Linux / macOS / Windows / Termux", "iOS sandboxes (a-Shell, Pythonista)"),
        crow("Discovery method", "ARP scan (scapy), ping-sweep fallback", "Plain TCP connect probe"),
        crow("MAC address / vendor", "Yes (IEEE OUI lookup)", "No (not exposed to the sandbox)"),
        crow("IPv6 discovery", "Yes (--ipv6)", "No"),
        crow("Banner grabbing", "--identify IP deep dive", "Built into every scan"),
        crow("Risky-port flagging", "Yes", "Yes"),
        crow("NEW / CHG / missing tracking", "Yes", "Yes"),
        crow("IP-conflict / spoofing alert", "Yes", "No (no MAC available)"),
        crow("Retry a flaky scan", "--retries N", "--retries N"),
        crow("Export results", "--output FILE (CSV/JSON)", "--output FILE (CSV/JSON)"),
        crow("Scan history log", "--log-history FILE", "--log-history FILE"),
        crow("Excluding hosts", "--exclude IP/CIDR", "--exclude IP/CIDR"),
        crow("Custom device labels", "--set-label / --remove-label", "--set-label / --remove-label"),
        crow("Environment diagnostics", "--doctor", "--doctor"),
        crow("Quiet mode (cron/systemd)", "--quiet", "--quiet"),
        crow("Webhook notifications", "--notify-webhook", "--notify-webhook"),
        crow("Multi-subnet scanning", "--all-subnets (parallel)", "Manual comma-separated list"),
        crow("Shell tab-completion", "completions.bash", "completions.bash"),
    ]
    ct = Table(compare_data, colWidths=[1.5 * inch, 2.5 * inch, 2.5 * inch])
    ct_style = [
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8.8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e3e8ec")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for i in range(1, len(compare_data)):
        if i % 2 == 0:
            ct_style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#f8fafb")))
    ct.setStyle(TableStyle(ct_style))
    story.append(ct)
    story.append(PageBreak())

    # ------------------------------------------------------------ Pulling
    story.append(Paragraph("1. Getting the scripts", styles["H1"]))
    story.append(Paragraph(
        "Both scripts are plain, dependency-light Python files living in one repository. Pick "
        "whichever pull method fits where you're running them.", styles["Body"]))

    story.append(Paragraph("Clone the whole repository (desktop / Termux)", styles["H2"]))
    story.append(code_block(f"""git clone {REPO_URL}.git
cd Test-repo
git checkout {BRANCH}"""))

    story.append(Paragraph("Grab a single file directly (no git needed)", styles["H2"]))
    story.append(Paragraph(
        "Useful on iOS, or anywhere you only want one script without the rest of the repo:", styles["Body"]))
    story.append(code_block(f"""BASE=https://raw.githubusercontent.com/thomasmd321/Test-repo/{BRANCH}
curl -O $BASE/network_scanner.py
curl -O $BASE/mobile_network_scanner.py"""))
    story.append(Paragraph(
        "<font face='Courier'>curl -O</font> saves the file under its own name in the current "
        "directory and overwrites an existing copy, so re-running the same command later pulls in "
        "any updates.", styles["BodySmall"]))

    story.append(Paragraph("On an iPhone", styles["H2"]))
    story.append(Paragraph(
        "Install <b>a-Shell</b> from the App Store (not “a-Shell mini,” which strips out "
        "<font face='Courier'>git</font>), then run either the clone or the single-file "
        "<font face='Courier'>curl</font> command above from its terminal.", styles["Body"]))

    story.append(PageBreak())

    # ------------------------------------------------------------ network_scanner.py
    story.append(Paragraph("2. network_scanner.py", styles["H1"]))
    story.append(Paragraph(
        "For a normal desktop, laptop, or Termux-on-Android environment. Prefers a fast ARP scan "
        "via scapy (returns MAC addresses directly); if scapy isn't installed or the process lacks "
        "the privileges ARP scanning needs, it falls back automatically to a multithreaded ping "
        "sweep plus the system's own ARP table — no flag needed to trigger this, it just happens.",
        styles["Body"]))

    story.append(Image(str(desktop_diagram), width=5.4 * inch, height=5.4 * inch * (1240 / 1560)))
    story.append(Paragraph("How a scan flows through network_scanner.py, start to finish.", styles["Caption"]))

    story.append(Paragraph("Running it", styles["H2"]))
    story.append(code_block("""python3 network_scanner.py                    # auto-detect subnet
python3 network_scanner.py 192.168.1.0/24      # scan a specific subnet
python3 network_scanner.py --all-subnets       # every subnet (needs psutil)
python3 network_scanner.py --identify 192.168.1.42  # deep-dive one host
python3 network_scanner.py --watch 300         # rescan every 5 minutes
python3 network_scanner.py --output scan.json  # save results to a file"""))

    story.append(Paragraph("Options", styles["H2"]))
    desktop_flags = [
        ("subnet", "Positional. CIDR range(s) to scan, comma-separated for more than one. Auto-detected if omitted."),
        ("--all-subnets", "Scan every local subnet this machine has an interface on (requires <font face=\"Courier\">pip install psutil</font>) instead of just the default route. Subnets are scanned concurrently, not one at a time, so several VLANs don't multiply the wall-clock cost."),
        ("--identify IP", "Skip the network scan; do a slow, thorough single-host investigation instead (more ports, banner grabs, full hostname/vendor resolution)."),
        ("--doctor", "Skip the network scan; check this environment for everything this script can use (scapy, ping/arp, cache writability, mDNS, etc.) and report it."),
        ("--timeout SECONDS", "Timeout per host (default: 1.0)."),
        ("--retries N", "Extra ARP/ping-sweep passes beyond the first, to recover a device that missed one reply due to transient packet loss (default: 0)."),
        ("--mdns-timeout SECONDS", "Timeout for the mDNS/DNS-SD hostname fallback (default: 0.3)."),
        ("--no-vendor-lookup", "Skip the IEEE OUI vendor lookup (avoids the first-run registry download)."),
        ("--refresh-vendor-db", "Force a fresh OUI registry download instead of using the cached copy."),
        ("--watch SECONDS", "Rescan on a timer instead of once, printing NEW markers as they appear (Ctrl+C to stop)."),
        ("--no-track-devices", "Don't use the known-devices registry at all — no NEW/CHG markers, nothing remembered."),
        ("--forget-known-devices", "Clear the registry first, so everything in this run shows as NEW."),
        ("--set-label KEY=LABEL", "Assign a friendly label to a device (KEY is its MAC, or IP if it has none), shown instead of/alongside its hostname. Repeatable."),
        ("--remove-label KEY", "Remove a device's custom label. Repeatable."),
        ("--ipv6", "Also discover IPv6 devices via multicast ping + NDP (Linux/macOS only)."),
        ("--ipv6-timeout SECONDS", "Roughly how long to spend on IPv6 discovery (default: 2.0)."),
        ("--no-scan-ports", "Skip the open-port probe (and the risky-ports check that depends on it)."),
        ("--ports LIST", "Comma-separated TCP ports to probe instead of the built-in default list."),
        ("--exclude LIST", "Comma-separated IPs and/or CIDR ranges to drop from the scan right after discovery (a bare IP is treated as a /32)."),
        ("--port-timeout SECONDS", "Per-port connection timeout, for both the port probe and risky-ports check (default: 0.3)."),
        ("--no-risky-ports", "Skip the risky-ports security check while keeping the general port probe."),
        ("--no-color", "Disable ANSI color output (also respects the <font face=\"Courier\">NO_COLOR</font> env var)."),
        ("--output FILE", "Save this scan's results to FILE as JSON, or CSV if it ends in <font face=\"Courier\">.csv</font>."),
        ("--log-history FILE", "Append this scan's results as one JSON line to FILE, instead of overwriting it like --output does."),
        ("--history-max-entries N", "Cap FILE from --log-history at N lines, dropping the oldest first (default: 200)."),
        ("--quiet", "Print nothing for a scan with no NEW/CHG/missing/risky devices - only an interesting run produces output (see --watch under cron/systemd)."),
        ("--notify-webhook URL", "POST a summary to URL as Slack-compatible JSON whenever a scan has something to report - same trigger as --quiet."),
    ]
    story.append(options_table(desktop_flags))

    story.append(PageBreak())

    # ------------------------------------------------------------ mobile_network_scanner.py
    story.append(Paragraph("3. mobile_network_scanner.py", styles["H1"]))
    story.append(Paragraph(
        "For sandboxed Python runtimes — most notably iOS apps like a-Shell — that allow "
        "neither subprocess calls nor raw sockets. Every discovery technique here is built from "
        "ordinary client TCP/UDP sockets, which is the one thing every one of these sandboxes still "
        "permits.", styles["Body"]))

    story.append(Image(str(mobile_diagram), width=5.4 * inch, height=5.4 * inch * (1240 / 1560)))
    story.append(Paragraph("How a scan flows through mobile_network_scanner.py, start to finish.", styles["Caption"]))

    story.append(Paragraph("Running it", styles["H2"]))
    story.append(code_block("""python3 mobile_network_scanner.py                    # auto-detect subnet
python3 mobile_network_scanner.py 192.168.1.0/24     # scan a specific subnet
python3 mobile_network_scanner.py --timeout 0.5 --ports 22,80,443
python3 mobile_network_scanner.py --watch 300        # rescan every 5 minutes
python3 mobile_network_scanner.py --no-banners --no-risky-ports  # faster scan
python3 mobile_network_scanner.py --output scan.csv  # save results to a file"""))

    story.append(Paragraph("Options", styles["H2"]))
    mobile_flags = [
        ("subnet", "Positional. CIDR range(s) to scan, comma-separated for more than one. Auto-detected if omitted."),
        ("--doctor", "Skip the network scan; check this environment for everything this script can use (subnet detection, TCP connectivity, cache writability, mDNS) and report it."),
        ("--timeout SECONDS", "Timeout per port probe (default: 0.5); also used for the banner-grab and risky-ports steps."),
        ("--retries N", "Extra probe passes for hosts that didn't answer, to recover a device that missed one connection attempt (default: 0)."),
        ("--ports LIST", "Comma-separated TCP ports to probe instead of the built-in default list."),
        ("--exclude LIST", "Comma-separated IPs and/or CIDR ranges to drop before probing anything (a bare IP is treated as a /32)."),
        ("--mdns-timeout SECONDS", "Timeout for the mDNS/Bonjour hostname fallback (default: 0.3)."),
        ("--watch SECONDS", "Rescan on a timer instead of once, printing NEW markers as they appear (Ctrl+C to stop)."),
        ("--no-track-devices", "Don't use the known-devices registry at all — no NEW/CHG markers, nothing remembered."),
        ("--forget-known-devices", "Clear the registry first, so everything in this run shows as NEW."),
        ("--set-label KEY=LABEL", "Assign a friendly label to a device (KEY is its IP address), shown instead of/alongside its hostname. Repeatable."),
        ("--remove-label KEY", "Remove a device's custom label. Repeatable."),
        ("--no-banners", "Skip banner grabbing on each device's open port — faster, but a weaker identification hint."),
        ("--no-risky-ports", "Skip the risky-ports security check while keeping the general port probe."),
        ("--no-color", "Disable ANSI color output (also respects the <font face=\"Courier\">NO_COLOR</font> env var)."),
        ("--output FILE", "Save this scan's results to FILE as JSON, or CSV if it ends in <font face=\"Courier\">.csv</font>."),
        ("--log-history FILE", "Append this scan's results as one JSON line to FILE, instead of overwriting it like --output does."),
        ("--history-max-entries N", "Cap FILE from --log-history at N lines, dropping the oldest first (default: 200)."),
        ("--quiet", "Print nothing for a scan with no NEW/CHG/missing/risky devices - only an interesting run produces output (see --watch under cron/systemd)."),
        ("--notify-webhook URL", "POST a summary to URL as Slack-compatible JSON whenever a scan has something to report - same trigger as --quiet."),
    ]
    story.append(options_table(mobile_flags))

    story.append(Spacer(1, 0.15 * inch))
    warn_data = [[Paragraph(
        "<b>iOS limitation:</b> mDNS/DNS-SD queries fail outright on iOS with "
        "<font face='Courier'>OSError(65, 'No route to host')</font> — Apple's Local Network "
        "Privacy model requires an app bundle to declare Bonjour service types in advance, which a "
        "script run from a generic terminal app can't do. Plain TCP port scanning, banner grabbing, "
        "and risky-port checks are unaffected, since they're ordinary unicast traffic.",
        styles["BodySmall"])]]
    wt = Table(warn_data, colWidths=[6.5 * inch])
    wt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fdecec")),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#b23b3b")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(wt)

    story.append(PageBreak())

    # ------------------------------------------------------------ Known-device tracking
    story.append(Paragraph("4. Known-device tracking, color coding, and --watch", styles["H1"]))
    story.append(Paragraph(
        "Both scripts persist a small local registry of every device they've ever seen "
        "(<font face='Courier'>~/.cache/network_scanner_known_devices.json</font> and "
        "<font face='Courier'>~/.cache/mobile_network_scanner_known_devices.json</font>). Every "
        "scan is compared against it, producing the markers and colors below. Pair either script "
        "with <font face='Courier'>--watch SECONDS</font> to turn a one-shot scan into a standing "
        "monitor.", styles["Body"]))

    story.append(Image(str(terminal_mockup), width=6.3 * inch, height=6.3 * inch * (620 / 1500)))
    story.append(Paragraph("Illustrative output — exact columns vary slightly between the two scripts.",
                            styles["Caption"]))

    legend_data = [
        [Paragraph("Marker / color", styles["TableHead"]), Paragraph("Meaning", styles["TableHead"])],
        [Paragraph("<font color='#2f8f52'><b>NEW</b></font> (green)", styles["FlagDesc"]),
         "First time this device has ever been seen."],
        [Paragraph("<font color='#b8960f'><b>CHG</b></font> (yellow)", styles["FlagDesc"]),
         "A known device is answering on a different port than last time."],
        [Paragraph("<font color='#c23b32'><b>red row</b></font>", styles["FlagDesc"]),
         "Device exposes a port on the risky-ports list (telnet, SMB, RDP, VNC, FTP)."],
        [Paragraph("<font color='#9c3fa3'><b>magenta row</b></font>", styles["FlagDesc"]),
         "This IP was last attributed to a different MAC address (network_scanner.py only)."],
        [Paragraph("dim gray line", styles["FlagDesc"]), "A previously-seen device that didn't show up in this scan."],
    ]
    lt = Table(legend_data, colWidths=[1.8 * inch, 4.7 * inch])
    lt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), steel),
        ("FONTSIZE", (0, 0), (-1, -1), 8.8),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e3e8ec")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(lt)
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph(
        "A device can be NEW or CHG, never both — a device with no prior registry entry can't "
        "have a “changed” port, only a first one. A device can be NEW <i>and</i> a magenta IP "
        "conflict at once, though (a freshly-added device can land on an IP someone else just "
        "gave up) — row-color priority, most to least urgent: risky, conflict, new, changed port.",
        styles["BodySmall"]))

    story.append(Paragraph("Resetting tracking", styles["H2"]))
    story.append(code_block("""python3 network_scanner.py --no-track-devices      # skip tracking this run
python3 network_scanner.py --forget-known-devices  # reset registry, all NEW
python3 mobile_network_scanner.py --watch 300      # standing monitor on phone"""))

    story.append(Spacer(1, 0.1 * inch))

    story.append(KeepTogether([
        Paragraph("Recovering from a flaky scan (--retries)", styles["H2"]),
        Paragraph(
            "A single dropped ARP/ping reply (or one flaky TCP connect on the mobile script) can "
            "make a live device look “missing” this run and “NEW” again next run - a false signal "
            "every registry-based feature above inherits. --retries N re-probes before finalizing "
            "results, giving a flaky device another chance to answer.", styles["Body"]),
        code_block("""python3 network_scanner.py --retries 1
python3 mobile_network_scanner.py --retries 2"""),
        Paragraph(
            "The two scripts implement this differently, matching how each discovers devices: "
            "network_scanner.py's ARP/ping sweep is one broadcast across the whole subnet, so each "
            "retry re-runs that same broadcast (scapy's raw sockets aren't necessarily safe to hit "
            "concurrently from targeted single-host requests instead). mobile_network_scanner.py "
            "already probes each host individually over plain TCP, so each retry there only "
            "re-probes the specific hosts still missing a match. Both default to 0 (a single pass), "
            "preserving the original behavior exactly.", styles["BodySmall"]),
    ]))

    story.append(KeepTogether([
        Paragraph("Custom device labels", styles["H2"]),
        Paragraph(
            "The same registry can hold a friendly label for a device — useful when its real "
            "hostname is cryptic or blank — shown in place of/alongside the hostname (e.g. "
            "<font face='Courier'>Kitchen Server (localhost)</font> when they differ). KEY is a "
            "device's MAC (or IP if it has none) for network_scanner.py, or always its IP for "
            "mobile_network_scanner.py.", styles["Body"]),
        code_block("""python3 network_scanner.py --set-label aa:bb:cc:dd:ee:ff="Kitchen Server"
python3 mobile_network_scanner.py --set-label 192.168.1.42="Kitchen Echo"
python3 network_scanner.py --remove-label aa:bb:cc:dd:ee:ff"""),
        Paragraph(
            "Both flags are repeatable and take effect immediately, including on the scan that "
            "runs in the same command. A device doesn't need to already be in the registry — "
            "labeling one creates a minimal entry for it, though that also means it won't show as "
            "NEW the next time it's actually scanned.", styles["BodySmall"]),
    ]))

    story.append(Spacer(1, 0.1 * inch))

    story.append(KeepTogether([
        Paragraph("IP-conflict / spoofing alerts (network_scanner.py only)", styles["H2"]),
        Paragraph(
            "The same registry also catches a device's IP being taken over by a different MAC "
            "address than last time — a DHCP lease getting handed to a new device is the ordinary "
            "cause, but it's exactly the same signal something spoofing another device's IP (most "
            "notably ARP-poisoning your router's own address) would produce. A conflicting device "
            "prints in magenta and shows up in its own summary section.", styles["Body"]),
        Paragraph(
            "This is a hygiene signal, not an intrusion-detection system — most hits will be "
            "completely benign lease reassignments. A conflict on your router/gateway's own IP is "
            "the one case worth treating as urgent rather than routine. Only compares devices that "
            "both have a real MAC address, so a ping-sweep-only device (no MAC at all) can't "
            "trigger or be flagged by this. Not available on mobile_network_scanner.py, which has "
            "no MAC address to compare in the first place. Skipped entirely with "
            "<font face='Courier'>--no-track-devices</font>.", styles["BodySmall"]),
    ]))

    story.append(PageBreak())

    # ------------------------------------------------------------ Exporting results
    story.append(Paragraph("5. Exporting results", styles["H1"]))
    story.append(Paragraph(
        "Both scripts can save a scan's results to a file with <font face='Courier'>--output "
        "FILE</font>, independent of the known-devices registry above — useful for feeding "
        "results into another tool, diffing two scans, or just keeping a dated record. The format "
        "is chosen by the file extension: <font face='Courier'>.csv</font> writes a CSV file, "
        "anything else (typically <font face='Courier'>.json</font>) writes JSON.", styles["Body"]))
    story.append(code_block("""python3 network_scanner.py --output scan.json
python3 network_scanner.py --output scan.csv
python3 mobile_network_scanner.py --output scan.json"""))
    story.append(Paragraph(
        "Each run overwrites FILE with that scan's results — this is a snapshot of the latest "
        "scan, not an appended history log.", styles["BodySmall"]))

    story.append(PageBreak())

    # ------------------------------------------------------------ scan_diff.py
    story.append(Paragraph("6. Diffing two scans", styles["H1"]))
    story.append(Paragraph(
        "scan_diff.py is a third, standalone script that compares two files saved with "
        "--output above and reports what changed: devices added, devices that disappeared, "
        "and per-field changes (a different port, hostname, banner, etc.) on devices present "
        "in both — the same NEW/missing/CHG comparison the scanners do against their own "
        "known-devices registry, just applied to two snapshots on disk instead.", styles["Body"]))
    story.append(code_block("""python3 scan_diff.py old.json new.json
python3 scan_diff.py before.csv after.csv
python3 scan_diff.py --no-color old.json new.json"""))
    story.append(Paragraph(
        "Either file can be JSON or CSV independently (comparing a CSV export against a JSON "
        "one works fine), and they don't need to come from the same script: fields the two "
        "scanners don't share (mac/vendor are desktop-only, banner is mobile-only) are still "
        "compared whenever both files happen to have them. A device is matched across the two "
        "files by MAC when present, falling back to IP — the same identity rule "
        "network_scanner.py's own known-devices tracking uses.", styles["Body"]))

    story.append(PageBreak())

    # ------------------------------------------------------------ Quiet mode & --doctor
    story.append(Paragraph("7. Quiet mode and environment diagnostics", styles["H1"]))
    story.append(KeepTogether([
        Paragraph("--quiet", styles["H2"]),
        Paragraph(
            "Suppresses everything — even the scan's own “Scanning...” line — for a run "
            "with nothing to report: no NEW devices, no port changes, no missing devices, and no "
            "risky ports. As soon as one of those is true, the full report prints exactly as it "
            "would without --quiet. Meant for --watch under cron/systemd, where a boring rescan "
            "producing zero output (rather than a full table every time) is what makes “did "
            "anything happen” easy to grep for or alert on.", styles["Body"]),
        code_block("""python3 network_scanner.py --watch 300 --quiet
python3 mobile_network_scanner.py --watch 300 --quiet"""),
    ]))

    story.append(Spacer(1, 0.1 * inch))

    story.append(KeepTogether([
        Paragraph("--doctor", styles["H2"]),
        Paragraph(
            "Skips the network scan and instead checks this environment for everything the "
            "script can use — scapy, ping/arp, cache-directory writability, mDNS multicast, and "
            "so on — reporting each with a clear pass/fail and, for most, the fallback that "
            "kicks in when it fails. Exits 0 if every check passed, 1 otherwise, so it's usable "
            "as a pre-flight check in a script.", styles["Body"]),
        code_block("""python3 network_scanner.py --doctor
python3 mobile_network_scanner.py --doctor"""),
        Paragraph(
            "A failed check doesn't necessarily mean a scan will fail — most have a documented "
            "fallback (no arp on PATH just means no MAC from that path, not a crash). The one "
            "exception: a failed mDNS check on mobile_network_scanner.py almost always means "
            "iOS's Local Network Privacy restriction (see mdns_diagnostic.py), which no retry or "
            "code change here can fix.", styles["BodySmall"]),
    ]))

    story.append(PageBreak())

    # ------------------------------------------------------------ Notifications
    story.append(Paragraph("8. Notifications for --watch", styles["H1"]))
    story.append(Paragraph(
        "--notify-webhook URL POSTs a plain-text summary to URL as {\"text\": \"...\"} JSON — the "
        "format Slack's incoming webhooks (and many other generic webhook receivers) expect "
        "directly — whenever a scan has a NEW device, a port change, a missing device, or a "
        "risky port to report. A boring scan sends nothing at all, the same trigger condition "
        "--quiet uses, so the two pair naturally under --watch.", styles["Body"]))
    story.append(code_block("""python3 network_scanner.py --watch 300 \\
  --notify-webhook https://hooks.slack.com/services/...
python3 mobile_network_scanner.py --watch 300 \\
  --notify-webhook https://ntfy.sh/your-topic"""))
    story.append(Paragraph(
        "A failed or unreachable webhook prints a warning to stderr and the scan continues "
        "normally — it never crashes the run. This deliberately doesn't special-case any one "
        "service's exact payload shape; a target expecting something else (Discord's content "
        "key, ntfy.sh's plain-text body) may need a small relay in between, or just point it at "
        "a service that already speaks the Slack-compatible format.", styles["Body"]))

    story.append(PageBreak())

    # ------------------------------------------------------------ Excluding devices
    story.append(Paragraph("9. Excluding devices from a scan", styles["H1"]))
    story.append(Paragraph(
        "--exclude IP/CIDR skips one or more addresses — comma-separated, each either a bare IP "
        "(treated as a /32) or a CIDR range — from the rest of a scan, without narrowing the "
        "whole subnet just to dodge one host: a printer that crashes under port probes, a NAS "
        "you don't want woken from sleep, or a noisy neighbor you just don't care about.",
        styles["Body"]))
    story.append(code_block("""python3 network_scanner.py --exclude 192.168.1.5
python3 network_scanner.py --exclude 192.168.1.5,192.168.1.10
python3 network_scanner.py --exclude 192.168.1.0/28
python3 mobile_network_scanner.py --exclude 192.168.1.5,10.0.0.0/24"""))
    story.append(Paragraph(
        "On mobile_network_scanner.py, exclusion is complete: excluded hosts are dropped from "
        "the list before any TCP connection is ever attempted, so nothing at all reaches them. "
        "On network_scanner.py's ARP path, the initial ARP broadcast still reaches every host on "
        "the subnet — scapy's srp() sends one request across the whole range in a single call, "
        "with no way to carve individual addresses out of that broadcast — but excluded devices "
        "are dropped immediately after discovery, before vendor lookup, port scanning, the "
        "risky-ports check, and the final report/export/tracking, so in practice they're never "
        "touched beyond that one broadcast packet. The ping-sweep fallback still pings every "
        "host itself and filters after, since it has no equivalent single-broadcast step to "
        "route around.", styles["Body"]))

    story.append(PageBreak())

    # ------------------------------------------------------------ Scan history log
    story.append(Paragraph("10. Scan history log", styles["H1"]))
    story.append(Paragraph(
        "--log-history FILE appends every scan's results to FILE as one JSON line per run "
        "({\"timestamp\": \"...\", \"devices\": [...]}), instead of overwriting it like --output "
        "does — useful under --watch for keeping a record of what the network looked like over "
        "time, or for feeding into your own analysis later (each line parses independently, so "
        "you don't need to load the whole file to read one entry).", styles["Body"]))
    story.append(code_block("""python3 network_scanner.py --watch 300 --log-history history.jsonl
python3 mobile_network_scanner.py --log-history history.jsonl"""))
    story.append(Paragraph(
        "The file is capped at 200 entries by default (oldest dropped first) so it doesn't grow "
        "forever under a long-running --watch; override with --history-max-entries N.",
        styles["Body"]))
    story.append(code_block(
        """python3 network_scanner.py --watch 300 --log-history history.jsonl \\\n"""
        """  --history-max-entries 1000"""))

    story.append(PageBreak())

    # ------------------------------------------------------------ Shell completion
    story.append(Paragraph("11. Shell tab-completion", styles["H1"]))
    story.append(Paragraph(
        "completions.bash adds bash tab-completion for each script's flag names (18+ per script "
        "by now, easy to half-remember). Source it from your ~/.bashrc:", styles["Body"]))
    story.append(code_block("source /path/to/Test-repo/completions.bash"))
    story.append(Paragraph(
        "It only completes flag <i>names</i>, not their arguments (a subnet, a port list, a file "
        "path), and only fires for a direct invocation matching a script's own name "
        "(<font face='Courier'>./network_scanner.py</font>, or the bare name if it's on PATH — "
        "the scripts in this repo already have their executable bit set). "
        "<font face='Courier'>python3 network_scanner.py &lt;TAB&gt;</font> does <b>not</b> "
        "trigger it: bash keys completion off the first word of the command line, which is "
        "<font face='Courier'>python3</font> in that case, not the script — putting the script "
        "on PATH so the bare-name form works is the practical fix.", styles["Body"]))

    story.append(PageBreak())

    # ------------------------------------------------------------ mdns_browser.py
    story.append(Paragraph("12. mdns_browser.py: browsing mDNS/DNS-SD", styles["H1"]))
    story.append(Paragraph(
        "The other two scripts only ever ask mDNS/DNS-SD one narrow question at a time - what's "
        "this IP's hostname, or is anything answering as a Chromecast. mdns_browser.py asks the "
        "broader one: what services exist on this network at all - printers, AirPlay speakers, "
        "SSH-capable hosts, HomeKit accessories, anything advertising itself - without needing to "
        "already know an IP or guess a service type first.", styles["Body"]))
    story.append(code_block("""python3 mdns_browser.py                    # discover + browse everything
python3 mdns_browser.py --timeout 3
python3 mdns_browser.py --services _http._tcp.local,_ipp._tcp.local
python3 mdns_browser.py --no-discover       # built-ins only, skip discovery
python3 mdns_browser.py --output services.json"""))
    story.append(Paragraph(
        "Works in two phases. First, DNS-SD's own “meta-query” "
        "(_services._dns-sd._udp.local, RFC 6763 §9) asks which service types are actually in use "
        "- not every device implements this even when it implements browsing for its own type, so "
        "the result is unioned with a small built-in list of common types (Chromecast, AirPlay, IPP "
        "printers, SMB, SSH, HomeKit, and more). Second, it browses all of those types at once on a "
        "single socket, joining each response's PTR/SRV/A records into an {ip: name} map per type - "
        "the same join mobile_network_scanner.py's own mdns_service_lookup() does for Chromecast "
        "specifically, generalized here to many types in one pass.", styles["Body"]))
    story.append(Paragraph(
        "Best-effort, like the mDNS code elsewhere in this project (one query per type, reading "
        "whatever comes back within --timeout), and shares the same iOS Local Network Privacy "
        "limitation as the other two scripts' mDNS lookups.", styles["BodySmall"]))

    story.append(PageBreak())

    # ------------------------------------------------------------ wifi_scanner.py
    story.append(Paragraph("13. Scanning nearby Wi-Fi networks (wifi_scanner.py)", styles["H1"]))
    story.append(Paragraph(
        "A different, complementary question from the rest of this project: not “what devices "
        "are on my network” but “what networks are in radio range at all,” including "
        "ones you're not connected to. A network that feels slow is often channel congestion from a "
        "neighbor on the same channel, or a weak signal - neither of which device discovery can see.",
        styles["Body"]))
    story.append(code_block("""python3 wifi_scanner.py
python3 wifi_scanner.py --timeout 15
python3 wifi_scanner.py --output networks.json"""))
    story.append(Paragraph(
        "Shells out to each OS's own Wi-Fi tooling: nmcli on Linux, the airport command-line tool "
        "on macOS (still present despite Apple's deprecation notice), and netsh wlan show networks "
        "on Windows. Signal strength stays in whatever unit each platform's own tool reports (a "
        "percentage on Linux/Windows, dBm on macOS) rather than being converted between them - there "
        "is no one true conversion, so labeling each honestly beats a false unification. An open/"
        "unencrypted network is called out in the output, the same hygiene-flagging spirit as "
        "RISKY_PORTS elsewhere in this project.", styles["Body"]))

    warn_data2 = [[Paragraph(
        "<b>Known limitation, stated plainly:</b> this project's own development environment has "
        "none of nmcli, airport, or netsh installed and no Wi-Fi hardware at all, so every "
        "platform's parser here is verified only against mocked command output matching each "
        "tool's documented format, never against a real device on real hardware, on any of the "
        "three platforms. Treat a first real run on any platform as the verification it hasn't "
        "had yet.", styles["Body"]
    )]]
    warn_table2 = Table(warn_data2, colWidths=[6.4 * inch])
    warn_table2.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff6e5")),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#e0a940")),
        ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(Spacer(1, 0.1 * inch))
    story.append(warn_table2)

    story.append(PageBreak())

    # ------------------------------------------------------------ exposure_check.py
    story.append(Paragraph("14. exposure_check.py: internet-facing exposure", styles["H1"]))
    story.append(Paragraph(
        "RISKY_PORTS elsewhere in this project flags a port from inside the LAN - but a risky port "
        "reachable only from your own network is a much smaller problem than the same port reachable "
        "from the whole internet. This asks the sharper question: is a LAN-risky port (or any port "
        "you name) also reachable from outside, by probing your own public IP from this machine.",
        styles["Body"]))
    story.append(code_block("""python3 exposure_check.py                  # RISKY_PORTS, auto-detected IP
python3 exposure_check.py --ports 22,80,443,8080
python3 exposure_check.py --ip 203.0.113.5 --ports 22
python3 exposure_check.py --output exposure.json"""))
    story.append(Paragraph(
        "Your public IP is found with a single plain HTTP(S) request to api.ipify.org - a small, "
        "purpose-built “what's my IP” echo service, no account or API key needed, "
        "returning just the address as plain text. No other data about your network is sent "
        "anywhere; --ip skips this request entirely if you'd rather not make it, or already know "
        "the address.", styles["Body"]))

    warn_data3 = [[Paragraph(
        "<b>Read this before trusting a result:</b> probing your own public IP from inside your "
        "own LAN is not a reliable substitute for a real external scan. Home routers implement NAT "
        "loopback/hairpinning inconsistently - some silently drop this traffic (a genuinely open "
        "port reports as a false “closed” here), others loop it back to a LAN device "
        "without truly routing it to the internet and back (a false “open” that doesn't "
        "prove an actual outside host could reach it). A closed result here is never proof of "
        "safety, and an open result is never definitive proof of exposure - both need confirming "
        "from a real external vantage point (a VPS, a friend's network, a phone on cellular data "
        "with Wi-Fi off, or a third-party online port-checking site you choose yourself) before "
        "acting on either one. This tool is a cheap first pass, not the final word - the CLI itself "
        "prints this same caveat after every run.", styles["Body"]
    )]]
    warn_table3 = Table(warn_data3, colWidths=[6.4 * inch])
    warn_table3.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fdeaea")),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#c23b32")),
        ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(Spacer(1, 0.1 * inch))
    story.append(warn_table3)

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.9 * inch, rightMargin=0.9 * inch,
        title="Network Scanner Scripts — Setup & Usage Guide",
    )
    doc.build(story)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        desktop_diagram = tmp_path / "diagram_desktop.png"
        mobile_diagram = tmp_path / "diagram_mobile.png"
        terminal_mockup = tmp_path / "terminal_mockup.png"

        make_desktop_diagram(desktop_diagram)
        make_mobile_diagram(mobile_diagram)
        make_terminal_mockup(terminal_mockup)

        OUTPUT_PDF.parent.mkdir(parents=True, exist_ok=True)
        build_pdf(desktop_diagram, mobile_diagram, terminal_mockup, OUTPUT_PDF)

    print(f"Wrote {OUTPUT_PDF.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
