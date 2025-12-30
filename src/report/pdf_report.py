from __future__ import annotations

from datetime import datetime
from typing import List

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend

from ..core.engine import Finding


def _make_pie(passed: int, failed: int, manual: int, unknown: int) -> Drawing:
    # Size tuned for A4 width
    d = Drawing(16.5 * cm, 6.0 * cm)
    pie = Pie()
    pie.x = 0.5 * cm
    pie.y = 0.3 * cm
    pie.width = 6.0 * cm
    pie.height = 6.0 * cm

    data = [passed, failed, manual, unknown]
    labels = ["PASS", "FAIL", "MANUAL", "UNKNOWN"]

    # Avoid zero-sum issues
    if sum(data) == 0:
        data = [1, 0, 0, 0]

    pie.data = data
    pie.labels = labels

    # Style (keep readable but simple)
    pie.slices.strokeWidth = 0.25
    pie.slices.strokeColor = colors.white

    # Legend to the right
    legend = Legend()
    legend.x = 7.2 * cm
    legend.y = 4.8 * cm
    legend.fontName = "Helvetica"
    legend.fontSize = 9
    legend.boxAnchor = "nw"
    legend.columnMaximum = 4
    legend.deltax = 0
    legend.deltay = 10
    legend.alignment = "left"

    legend.colorNamePairs = [
        (pie.slices[i].fillColor, f"{labels[i]}: {data[i]}") for i in range(len(labels))
    ]

    d.add(pie)
    d.add(legend)
    return d


def build_pdf(out_path: str, findings: List[Finding], backup_name: str, notes: str = "") -> str:
    """Build a readable PDF report (A4) with wrapped table cells and a summary chart."""
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="Small",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=10.5,
            spaceAfter=2,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SmallBold",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=10.5,
            spaceAfter=2,
            fontName="Helvetica-Bold",
        )
    )
    title = ParagraphStyle(
        name="TitleBig",
        parent=styles["Title"],
        fontSize=18,
        leading=22,
        spaceAfter=8,
    )
    normal = styles["Normal"]
    small = styles["Small"]

    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        topMargin=1.6 * cm,
        bottomMargin=1.6 * cm,
        title="Sophos Firewall Configuration Review",
        author="sophos_backup_cis_audit",
    )

    story = []

    # Header
    story.append(Paragraph("Sophos Firewall Configuration Review", title))
    story.append(Paragraph("<b>(CIS-style)</b>", normal))
    story.append(Spacer(1, 0.15 * cm))

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    story.append(Paragraph(f"Backup: <b>{backup_name}</b>", normal))
    story.append(Paragraph(f"Generated: <b>{generated}</b>", normal))
    if notes:
        story.append(Paragraph(f"Notes: {notes}", normal))
    story.append(Spacer(1, 0.35 * cm))

    # Counts
    total = len(findings)
    passed = sum(1 for f in findings if f.status == "PASS")
    failed = sum(1 for f in findings if f.status == "FAIL")
    manual = sum(1 for f in findings if f.status == "MANUAL")
    unknown = sum(1 for f in findings if f.status == "UNKNOWN")

    # Executive summary
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    exec_text = (
        "This report provides an offline configuration review of a Sophos Firewall instance based on the supplied "
        "exported backup. The assessment applies a <b>CIS-style</b> secure configuration baseline for firewall hardening "
        "(administration, logging, cryptography, network policy hygiene, and threat prevention). In addition, the ruleset "
        "includes insurance-sector-oriented best practices emphasizing auditability, strict management access control, "
        "segmentation expectations, and incident response readiness."
        "<br/><br/>"
        "Results are derived from static analysis of backup artifacts. Where a control cannot be conclusively verified "
        "from the backup contents (due to export scope, version-specific structure, or limited markers), the item is "
        "reported as <b>MANUAL</b> and should be confirmed in the Sophos Firewall UI. <b>UNKNOWN</b> is reserved for tool or "
        "parsing issues."
    )
    story.append(Paragraph(exec_text, normal))
    story.append(Spacer(1, 0.25 * cm))

    # Summary + pie chart
    story.append(Paragraph("Summary", styles["Heading2"]))
    story.append(
        Paragraph(
            f"Total checks: {total} | PASS: {passed} | FAIL: {failed} | MANUAL: {manual} | UNKNOWN: {unknown}",
            normal,
        )
    )
    story.append(Spacer(1, 0.2 * cm))
    story.append(_make_pie(passed, failed, manual, unknown))
    story.append(Spacer(1, 0.35 * cm))

    # Highlight fails (if any)
    fails = [f for f in findings if f.status == "FAIL"]
    if fails:
        story.append(Paragraph("Key Risk Items (FAIL)", styles["Heading3"]))
        for f in fails[:10]:
            story.append(Paragraph(f"<b>{f.issue_id}</b> — {f.issue_name}", small))
        if len(fails) > 10:
            story.append(Paragraph(f"...and {len(fails)-10} more FAIL findings.", small))
        story.append(Spacer(1, 0.25 * cm))

    # Findings table
    story.append(Paragraph("Findings", styles["Heading2"]))

    # Printable width = A4(21cm) - 2*margin(1.6cm) = 17.8cm
    col_widths = [2.1 * cm, 5.5 * cm, 2.1 * cm, 2.0 * cm, 6.1 * cm]  # total = 17.8cm
    header = ["Issue ID", "Issue Name", "Status", "Fix Type", "Remediation"]

    data = [header]
    for f in findings:
        data.append(
            [
                Paragraph(f.issue_id, small),
                Paragraph(f.issue_name, small),
                Paragraph(f.status, small),
                Paragraph(f.fix_type, small),
                Paragraph(f.remediation, small),
            ]
        )

    t = Table(data, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2F5597")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )

    # Zebra striping
    for r in range(1, len(data)):
        if r % 2 == 0:
            t.setStyle(TableStyle([("BACKGROUND", (0, r), (-1, r), colors.whitesmoke)]))

    story.append(t)
    story.append(PageBreak())

    # Details and evidence
    story.append(Paragraph("Details and Evidence", styles["Heading2"]))
    story.append(
        Paragraph(
            "For each check, evidence is collected from extracted backup artifacts when available. "
            "If a check is marked MANUAL, the evidence section includes a verification hint for the Sophos UI.",
            normal,
        )
    )
    story.append(Spacer(1, 0.2 * cm))

    for f in findings:
        story.append(Paragraph(f"<b>{f.issue_id}</b> — {f.issue_name}", styles["Heading3"]))
        story.append(Paragraph(f"<b>Status:</b> {f.status} &nbsp;&nbsp; <b>Fix Type:</b> {f.fix_type}", small))
        story.append(Paragraph("<b>Remediation:</b> " + f.remediation, small))
        ev = (getattr(f, "evidence", "") or "").replace("\n", "<br/>")
        if ev:
            story.append(Paragraph("<b>Evidence:</b><br/>" + ev, small))
        story.append(Spacer(1, 0.25 * cm))

    doc.build(story)
    return out_path
