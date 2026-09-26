"""
Professional PDF Report Generator
==================================

Renders executive and technical cybersecurity analysis reports into PDF files.
Supports:
  - ReportLab PDF generation (primary)
  - Styled HTML report fallback (if reportlab is not installed)
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def generate_pdf_report(
    analysis_data: dict[str, Any],
    report_type: str = "executive",  # "executive" | "technical"
    narrative: str = "",
) -> tuple[bytes, str]:
    """
    Generate a PDF report file from analysis results.

    Returns
    -------
    (pdf_bytes, filename)
    """
    filename = f"IPsec_{report_type.capitalize()}_Report_{analysis_data.get('analysis_id', 'result')}.pdf"

    # Try generating with ReportLab
    try:
        pdf_bytes = _build_reportlab_pdf(analysis_data, report_type, narrative)
        return pdf_bytes, filename
    except Exception as exc:
        logger.warning("ReportLab generation failed (%s); building HTML fallback.", exc)

    # Fallback: HTML output converted/returned
    html_content = _build_html_report(analysis_data, report_type, narrative)
    return html_content.encode("utf-8"), filename.replace(".pdf", ".html")


def _build_reportlab_pdf(
    data: dict[str, Any],
    report_type: str,
    narrative: str,
) -> bytes:
    """Build a professional PDF document using ReportLab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import (
        HRFlowable,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    from io import BytesIO

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom palette
    navy = colors.HexColor("#0f172a")
    blue = colors.HexColor("#2563eb")
    slate = colors.HexColor("#475569")
    light_bg = colors.HexColor("#f8fafc")
    red = colors.HexColor("#dc2626")
    amber = colors.HexColor("#d97706")
    green = colors.HexColor("#16a34a")

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=navy,
    )
    h2_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=blue,
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=navy,
    )
    badge_style = ParagraphStyle(
        "BadgeText",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=colors.white,
    )

    story = []

    # Header title
    title_text = "EXECUTIVE SECURITY REPORT" if report_type == "executive" else "TECHNICAL PROTOCOL & SECURITY REPORT"
    story.append(Paragraph(title_text, title_style))
    story.append(Paragraph(f"<b>System:</b> IPsec VPN Security Assessment Framework | <b>Analysis ID:</b> {data.get('analysis_id')}", body_style))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=blue, spaceBefore=4, spaceAfter=12))

    # Overview table
    cap = data.get("capture", {})
    sec = data.get("security_assessment", {})
    obs = data.get("observed", {})
    ml = data.get("ml_inference", {})

    risk_score = sec.get("risk_score", 0)
    risk_level = str(sec.get("risk_level", "medium")).upper()
    risk_color = red if risk_level in {"CRITICAL", "HIGH"} else amber if risk_level == "MEDIUM" else green

    meta_table_data = [
        [
            Paragraph("<b>Target File:</b>", body_style),
            Paragraph(str(cap.get("file_name")), body_style),
            Paragraph("<b>Risk Posture:</b>", body_style),
            Paragraph(f"<font color='{risk_color.hexval()}'><b>{risk_score}/100 ({risk_level})</b></font>", body_style),
        ],
        [
            Paragraph("<b>Packet Count:</b>", body_style),
            Paragraph(str(cap.get("packet_count")), body_style),
            Paragraph("<b>Duration:</b>", body_style),
            Paragraph(f"{cap.get('duration_seconds', 0.0):.2f} seconds", body_style),
        ],
        [
            Paragraph("<b>Protocol Observed:</b>", body_style),
            Paragraph(str(obs.get("ike_version", "IKEv2")), body_style),
            Paragraph("<b>Overall Confidence:</b>", body_style),
            Paragraph(f"{data.get('confidence', {}).get('overall', 0.9)*100:.0f}%", body_style),
        ],
    ]
    meta_table = Table(meta_table_data, colWidths=[110, 160, 110, 160])
    meta_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), light_bg),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ])
    )
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # Narrative / Summary section
    story.append(Paragraph("Executive Summary & AI Interpretation", h2_style))
    for paragraph_line in narrative.split("\n"):
        if paragraph_line.strip():
            story.append(Paragraph(paragraph_line.strip(), body_style))
            story.append(Spacer(1, 4))
    story.append(Spacer(1, 10))

    # Configuration Predictions Table
    story.append(Paragraph("VPN Cryptographic Profile & Inference", h2_style))
    config_rows = [
        [Paragraph("<b>Component</b>", body_style), Paragraph("<b>Value / Inference</b>", body_style), Paragraph("<b>Source / Provenance</b>", body_style), Paragraph("<b>Confidence</b>", body_style)],
        [Paragraph("Encryption Algorithm", body_style), Paragraph(str(ml.get("encryption", {}).get("prediction")), body_style), Paragraph("ML Model (18 features)", body_style), Paragraph(f"{ml.get('encryption', {}).get('confidence', 0.0)*100:.1f}%", body_style)],
        [Paragraph("Integrity / Hash", body_style), Paragraph(str(ml.get("hash", {}).get("prediction")), body_style), Paragraph("ML Model (18 features)", body_style), Paragraph(f"{ml.get('hash', {}).get('confidence', 0.0)*100:.1f}%", body_style)],
        [Paragraph("Diffie-Hellman Group", body_style), Paragraph(str(ml.get("dh_group", {}).get("prediction")), body_style), Paragraph("ML Model (18 features)", body_style), Paragraph(f"{ml.get('dh_group', {}).get('confidence', 0.0)*100:.1f}%", body_style)],
        [Paragraph("Perfect Forward Secrecy", body_style), Paragraph(str(ml.get("pfs_group", {}).get("prediction")), body_style), Paragraph("ML Model (18 features)", body_style), Paragraph(f"{ml.get('pfs_group', {}).get('confidence', 0.0)*100:.1f}%", body_style)],
    ]
    config_table = Table(config_rows, colWidths=[140, 150, 150, 100])
    config_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(config_table)
    story.append(Spacer(1, 14))

    # Security Findings
    findings = sec.get("findings", [])
    story.append(Paragraph(f"Security Findings ({len(findings)})", h2_style))

    if not findings:
        story.append(Paragraph("No critical or high security posture defects were identified in this capture.", body_style))
    else:
        finding_rows = [[Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Finding Title</b>", body_style), Paragraph("<b>Impact & Recommendation</b>", body_style)]]
        for f in findings:
            sev = str(f.get("severity", "info")).upper()
            title = f.get("title", f.get("id"))
            desc = f"{f.get('description', '')} <b>Recommendation:</b> {f.get('recommendation', '')}"
            finding_rows.append([
                Paragraph(f"<b>{sev}</b>", body_style),
                Paragraph(str(title), body_style),
                Paragraph(desc, body_style),
            ])
        finding_table = Table(finding_rows, colWidths=[80, 180, 280])
        finding_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("PADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(finding_table)

    # Technical Details section (only for technical reports)
    if report_type == "technical":
        story.append(Spacer(1, 14))
        story.append(Paragraph("Detailed Feature Vector & Packet Statistics", h2_style))
        features = data.get("features", {})
        feat_rows = [[Paragraph("<b>Feature Name</b>", body_style), Paragraph("<b>Extracted Value</b>", body_style)]]
        for k, v in features.items():
            feat_rows.append([Paragraph(str(k), body_style), Paragraph(str(v), body_style)])
        feat_table = Table(feat_rows, colWidths=[270, 270])
        feat_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(feat_table)

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def _build_html_report(data: dict[str, Any], report_type: str, narrative: str) -> str:
    """HTML fallback report renderer."""
    cap = data.get("capture", {})
    sec = data.get("security_assessment", {})
    ml = data.get("ml_inference", {})

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>IPsec {report_type.capitalize()} Report - {data.get('analysis_id')}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 40px; color: #0f172a; background: #ffffff; }}
  h1 {{ color: #1e293b; border-bottom: 2px solid #2563eb; padding-bottom: 8px; }}
  h2 {{ color: #2563eb; margin-top: 24px; }}
  .card {{ background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 16px; margin-bottom: 20px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; font-size: 14px; }}
  th {{ background: #e2e8f0; }}
  .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; color: white; background: #2563eb; }}
  .badge-high {{ background: #dc2626; }}
  .badge-medium {{ background: #d97706; }}
</style>
</head>
<body>
  <h1>IPsec Protocol Security Assessment — {report_type.upper()} REPORT</h1>
  <p><strong>Analysis ID:</strong> {data.get('analysis_id')} | <strong>File:</strong> {cap.get('file_name')} | <strong>Timestamp:</strong> {data.get('analysis_timestamp')}</p>
  
  <div class="card">
    <h3>Executive Posture Summary</h3>
    <p><strong>Risk Score:</strong> {sec.get('risk_score')}/100 ({sec.get('risk_level', 'medium').upper()})</p>
    <p>{narrative}</p>
  </div>

  <h2>VPN Cryptographic Profile (ML Inferred)</h2>
  <table>
    <tr><th>Target</th><th>Prediction</th><th>Confidence</th></tr>
    <tr><td>Encryption</td><td>{ml.get('encryption', {}).get('prediction')}</td><td>{ml.get('encryption', {}).get('confidence', 0.0)*100:.1f}%</td></tr>
    <tr><td>Integrity</td><td>{ml.get('hash', {}).get('prediction')}</td><td>{ml.get('hash', {}).get('confidence', 0.0)*100:.1f}%</td></tr>
    <tr><td>Diffie-Hellman Group</td><td>{ml.get('dh_group', {}).get('prediction')}</td><td>{ml.get('dh_group', {}).get('confidence', 0.0)*100:.1f}%</td></tr>
    <tr><td>PFS Group</td><td>{ml.get('pfs_group', {}).get('prediction')}</td><td>{ml.get('pfs_group', {}).get('confidence', 0.0)*100:.1f}%</td></tr>
  </table>

  <h2>Security Findings</h2>
  <table>
    <tr><th>Severity</th><th>Title</th><th>Description</th></tr>
    {"".join([f"<tr><td><span class='badge'>{f.get('severity').upper()}</span></td><td>{f.get('title')}</td><td>{f.get('description')}</td></tr>" for f in sec.get('findings', [])])}
  </table>
</body>
</html>
"""
