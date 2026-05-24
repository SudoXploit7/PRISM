"""
PRISM - PDF Report Engine
Generates professional, self-contained PDF security reports using ReportLab.
"""

from io import BytesIO
from typing import Any

from loguru import logger

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, KeepTogether,
    )
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

# - Colors -
PRISM_DARK = colors.HexColor("#0a0e1a")
PRISM_BLUE = colors.HexColor("#3b82f6")
PRISM_CYAN = colors.HexColor("#06b6d4")
PRISM_RED = colors.HexColor("#ef4444")
PRISM_ORANGE = colors.HexColor("#f59e0b")
PRISM_GREEN = colors.HexColor("#10b981")
PRISM_GRAY = colors.HexColor("#94a3b8")

SEVERITY_COLORS = {
    "CRITICAL": PRISM_RED,
    "HIGH": PRISM_ORANGE,
    "MEDIUM": PRISM_BLUE,
    "LOW": PRISM_GREEN,
}


class PDFReportEngine:
    """Generates professional security assessment PDF reports."""

    def generate(self, data: dict[str, Any]) -> bytes:
        """Generate PDF report from scan data.

        Args:
            data: Complete report data dictionary.

        Returns:
            PDF file as bytes.
        """
        if not HAS_REPORTLAB:
            logger.error("reportlab not installed - cannot generate PDF")
            return b"PDF generation requires reportlab. Install with: pip install reportlab"

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            rightMargin=50, leftMargin=50,
            topMargin=60, bottomMargin=50,
            title="PRISM - Offensive Cloud Security Threat Assessment Report",
            author="PRISM Offensive Security Platform",
            subject="Cloud Security Threat Assessment",
            creator="PRISM"
        )

        styles = self._get_styles()
        story: list = []

        # - Cover Page -
        story.append(Spacer(1, 120))
        story.append(Paragraph("PRISM", styles["CoverTitle"]))
        story.append(Spacer(1, 10))
        story.append(Paragraph("Cloud Security Threat Assessment Report", styles["CoverSubtitle"]))
        story.append(Spacer(1, 40))
        story.append(HRFlowable(width="60%", thickness=2, color=PRISM_CYAN))
        story.append(Spacer(1, 20))

        meta = data.get("meta", {})
        story.append(Paragraph(f"Region: {meta.get('region', 'N/A')}", styles["CoverMeta"]))
        story.append(Paragraph(f"Generated: {meta.get('timestamp', 'N/A')}", styles["CoverMeta"]))
        story.append(PageBreak())

        # - Executive Summary -
        story.append(Paragraph("1. Executive Summary", styles["SectionHeader"]))
        story.append(Spacer(1, 12))

        risk = data.get("risk_summary", {})
        score = risk.get("overall_score", 0)
        rating = risk.get("rating", "N/A")
        total_findings = risk.get("total_findings", 0)

        story.append(Paragraph(
            f"Overall Risk Score: <b>{score}/100 ({rating})</b> with "
            f"<b>{total_findings}</b> total security findings.",
            styles["BodyText"]
        ))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "This report details the findings of the PRISM cloud security scanner. "
            "It enumerates misconfigurations, excessive permissions, and identified attack paths "
            "within the AWS environment. Each finding is assigned a CVSS v3.1 base score and "
            "prioritized for remediation based on potential impact. The review highlights critical "
            "areas such as shadow administrators, privilege escalation vectors, and network exposure.",
            styles["BodyText"]
        ))
        story.append(Spacer(1, 8))

        # Severity table
        sev = risk.get("severity_counts", {})
        sev_data = [
            ["Severity", "Count"],
            ["CRITICAL", str(sev.get("CRITICAL", 0))],
            ["HIGH", str(sev.get("HIGH", 0))],
            ["MEDIUM", str(sev.get("MEDIUM", 0))],
            ["LOW", str(sev.get("LOW", 0))],
        ]
        story.append(self._make_table(sev_data, col_widths=[120, 80]))
        story.append(Spacer(1, 12))

        # KPIs
        kpis = data.get("kpis", {})
        story.append(Paragraph("Key Findings:", styles["SubHeader"]))
        for key, val in kpis.items():
            if val > 0:
                label = key.replace("_", " ").title()
                story.append(Paragraph(f"- {label}: <b>{val}</b>", styles["BodyText"]))
        story.append(Spacer(1, 8))

        # Narrative
        narrative = data.get("attack_narrative", {})
        if narrative.get("executive_narrative"):
            story.append(Paragraph("Assessment Overview:", styles["SubHeader"]))
            for para in narrative["executive_narrative"].split("\n\n"):
                story.append(Paragraph(para, styles["BodyText"]))
                story.append(Spacer(1, 6))

        story.append(PageBreak())

        # - Technical Findings -
        story.append(Paragraph("2. Technical Findings", styles["SectionHeader"]))
        story.append(Spacer(1, 12))

        # Shadow Admins
        shadow = data.get("shadow_admin_findings", [])
        if shadow:
            story.append(Paragraph(f"2.1 Shadow Admins ({len(shadow)})", styles["SubHeader"]))
            story.extend(self._render_findings_table(shadow, styles))
            story.append(Spacer(1, 12))

        # Privesc
        privesc = data.get("privesc_findings", [])
        if privesc:
            story.append(Paragraph(f"2.2 Privilege Escalation Paths ({len(privesc)})", styles["SubHeader"]))
            pe_data = [["Severity", "Identity", "Vector", "MITRE"]]
            for f in privesc[:20]:
                pe_data.append([
                    f.get("severity", ""),
                    self._safe_p(f.get("identity", ""), styles["Small"]),
                    self._safe_p(f.get("vector_name", ""), styles["Small"]),
                    f.get("mitre", ""),
                ])
            story.append(self._make_table(pe_data, col_widths=[60, 100, 160, 60]))
            story.append(Spacer(1, 12))

        # Ghost Identities
        ghosts = data.get("ghost_identities", [])
        if ghosts:
            story.append(Paragraph(f"2.3 Ghost Identities ({len(ghosts)})", styles["SubHeader"]))
            gh_data = [["Identity", "Dormant Days", "Score", "Severity"]]
            for g in ghosts[:15]:
                gh_data.append([
                    self._safe_p(g.get("identity", ""), styles["Small"]),
                    str(g.get("days_dormant", 0)),
                    str(g.get("ghost_score", 0)),
                    g.get("severity", ""),
                ])
            story.append(self._make_table(gh_data, col_widths=[140, 80, 50, 60]))
            story.append(Spacer(1, 12))

        # Permission Entropy
        entropy = data.get("permission_entropy", {})
        if entropy:
            story.append(Paragraph("2.4 Permission Entropy", styles["SubHeader"]))
            story.append(Paragraph(
                f"IAM Chaos Score: <b>{entropy.get('entropy_score', 0)}/100</b> "
                f"({entropy.get('chaos_level', 'N/A')}). "
                f"Biggest chaos source: <b>{entropy.get('biggest_chaos_source', 'N/A')}</b>.",
                styles["BodyText"]
            ))
            story.append(Spacer(1, 12))

        # Network
        net = data.get("network_findings", [])
        if net:
            story.append(Paragraph(f"2.5 Network Exposure ({len(net)})", styles["SubHeader"]))
            story.extend(self._render_findings_table(net[:10], styles))
            story.append(Spacer(1, 12))

        # Blast Radius
        blast = data.get("blast_radius", [])
        if blast:
            story.append(Paragraph(f"2.6 Blast Radius (Top {min(len(blast),5)})", styles["SubHeader"]))
            br_data = [["Identity", "Overall", "Data", "Compute", "Identity", "Billing"]]
            for b in blast[:5]:
                dims = b.get("dimensions", {})
                br_data.append([
                    self._safe_p(b.get("identity", ""), styles["Small"]),
                    str(b.get("overall_blast_score", 0)),
                    str(dims.get("data", {}).get("score", 0)),
                    str(dims.get("compute", {}).get("score", 0)),
                    str(dims.get("identity", {}).get("score", 0)),
                    str(dims.get("billing", {}).get("score", 0)),
                ])
            story.append(self._make_table(br_data, col_widths=[110, 50, 50, 50, 50, 50]))
            story.append(Spacer(1, 12))

        story.append(PageBreak())

        # - Offensive Operations -
        story.append(Paragraph("3. Offensive Operations", styles["SectionHeader"]))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "This section details results from PRISM's offensive simulation engines, which model "
            "real-world attacker behavior to identify the most dangerous paths to compromise.",
            styles["BodyText"]
        ))
        story.append(Spacer(1, 12))

        # 3.1 MVC Engine
        mvc = data.get("mvc_analysis", {})
        mvc_paths = mvc.get("paths", [])
        if mvc_paths or mvc.get("account_rating"):
            story.append(Paragraph("3.1 Minimum Viable Compromise (MVC)", styles["SubHeader"]))
            story.append(Paragraph(
                f"The MVC engine maps the shortest attack path from every identity to full "
                f"administrator access. Account Rating: <b>{mvc.get('account_rating', 'N/A')}</b>. "
                f"Total attack paths: <b>{mvc.get('total_paths', 0)}</b>. "
                f"Already admin: <b>{mvc.get('zero_hop_count', 0)}</b>. "
                f"One-hop to admin: <b>{mvc.get('one_hop_count', 0)}</b>. "
                f"Fastest path: <b>{mvc.get('fastest_seconds', 'N/A')}s</b>.",
                styles["BodyText"]
            ))
            if mvc_paths:
                mvc_data = [["Identity", "Hops", "Severity", "Time (s)", "Blind Spots"]]
                for p in mvc_paths[:15]:
                    mvc_data.append([
                        self._safe_p(p.get("start_identity", ""), styles["Small"]),
                        str(p.get("hops", "")),
                        p.get("severity", ""),
                        str(p.get("total_seconds", "")),
                        str(p.get("blind_steps", 0)),
                    ])
                story.append(self._make_table(mvc_data, col_widths=[140, 40, 60, 55, 55]))
            story.append(Spacer(1, 12))

        # 3.2 Ransomware Readiness
        rw = data.get("ransomware_analysis", {})
        if rw.get("risk_rating"):
            story.append(Paragraph("3.2 Ransomware Readiness Assessment", styles["SubHeader"]))
            story.append(Paragraph(
                f"Overall ransomware score: <b>{rw.get('overall_score', 0)}/100 "
                f"({rw.get('risk_rating', 'N/A')})</b>. "
                f"Recovery estimate: <b>{rw.get('recovery_time_estimate', 'N/A')}</b>. "
                f"Reference: {rw.get('real_world_reference', 'N/A')}.",
                styles["BodyText"]
            ))
            id_results = rw.get("identity_results", [])
            if id_results:
                rw_data = [["Severity", "Identity", "Phases", "Full Ransom"]]
                for r in id_results[:10]:
                    rw_data.append([
                        r.get("severity", ""),
                        self._safe_p(r.get("identity", ""), styles["Small"]),
                        f"{r.get('phases_available', 0)}/6",
                        "YES" if r.get("full_ransom_capable") else "PARTIAL",
                    ])
                story.append(self._make_table(rw_data, col_widths=[60, 140, 50, 60]))
            bucket_results = rw.get("bucket_results", [])
            if bucket_results:
                story.append(Spacer(1, 8))
                story.append(Paragraph("Bucket Protection Status:", styles["Small"]))
                bk_data = [["Bucket", "Risk", "Versioning", "Object Lock"]]
                for b in bucket_results[:8]:
                    bk_data.append([
                        self._safe_p(b.get("bucket_name", ""), styles["Small"]),
                        b.get("ransomware_risk", ""),
                        "ON" if b.get("versioning") else "OFF",
                        "ON" if b.get("object_lock") else "OFF",
                    ])
                story.append(self._make_table(bk_data, col_widths=[160, 60, 60, 60]))
            story.append(Spacer(1, 12))

        # 3.3 Supply Chain
        sc = data.get("supply_chain_analysis", {})
        sc_findings = sc.get("findings", [])
        if sc_findings:
            story.append(Paragraph(f"3.3 Supply Chain Attack Surface ({len(sc_findings)} findings)", styles["SubHeader"]))
            story.append(Paragraph(
                f"Overall risk: <b>{sc.get('overall_risk', 'N/A')}</b>. "
                f"Critical: {sc.get('critical_count', 0)}, High: {sc.get('high_count', 0)}. "
                f"Reference: {sc.get('real_world_ref', 'SolarWinds/3CX/XZ Utils')}.",
                styles["BodyText"]
            ))
            sc_data = [["Severity", "Type", "Resource", "MITRE"]]
            for f in sc_findings[:12]:
                sc_data.append([
                    f.get("severity", ""),
                    self._safe_p(f.get("type", ""), styles["Small"]),
                    self._safe_p((f.get("resource", "") or ""), styles["Small"]),
                    f.get("mitre", ""),
                ])
            story.append(self._make_table(sc_data, col_widths=[55, 130, 130, 70]))
            story.append(Spacer(1, 12))

        # 3.4 Golden SAML
        gs = data.get("golden_saml_analysis", {})
        gs_findings = gs.get("findings", [])
        if gs_findings:
            story.append(Paragraph(f"3.4 Golden SAML / Federation Risks ({len(gs_findings)} findings)", styles["SubHeader"]))
            story.append(Paragraph(
                f"Overall risk: <b>{gs.get('overall_risk', 'N/A')}</b>. "
                f"Critical: {gs.get('critical_count', 0)}, High: {gs.get('high_count', 0)}. "
                f"{gs.get('technique_summary', '')}",
                styles["BodyText"]
            ))
            gs_data = [["Severity", "Type", "Resource", "Description"]]
            for f in gs_findings[:10]:
                gs_data.append([
                    f.get("severity", ""),
                    self._safe_p(f.get("type", ""), styles["Small"]),
                    self._safe_p(f.get("resource", ""), styles["Small"]),
                    self._safe_p(f.get("description", ""), styles["Small"]),
                ])
            story.append(self._make_table(gs_data, col_widths=[55, 100, 100, 240]))
            story.append(Spacer(1, 12))

        story.append(PageBreak())

        # - Kill Chain -
        kill_chain = data.get("kill_chain", {})
        if kill_chain:
            story.append(Paragraph("4. Temporal Kill Chain", styles["SectionHeader"]))
            story.append(Spacer(1, 8))
            story.append(Paragraph(
                f"Total estimated attack duration: <b>{kill_chain.get('total_attack_duration_minutes', 'N/A')} minutes</b>",
                styles["BodyText"]
            ))
            for phase in kill_chain.get("phases", []):
                logged = "- Logged" if phase.get("logged_by_cloudtrail") else "[BLIND SPOT]"
                story.append(Paragraph(
                    f"<b>{phase['phase']}</b> (+{phase['duration_minutes']}m) - "
                    f"Detection: {int(phase.get('detection_probability', 0)*100)}% - {logged}",
                    styles["BodyText"]
                ))
                story.append(Paragraph(phase.get("description", ""), styles["Small"]))
                story.append(Spacer(1, 6))
            story.append(Spacer(1, 12))

        # - Technical Narrative -
        if narrative.get("technical_narrative"):
            story.append(Paragraph("5. Attack Narrative", styles["SectionHeader"]))
            story.append(Spacer(1, 8))
            story.append(Paragraph(narrative["technical_narrative"], styles["BodyText"]))
            story.append(Spacer(1, 12))

        story.append(PageBreak())

        # - Remediation Plan -
        remediation = data.get("remediation_plan", [])
        if remediation:
            story.append(Paragraph(f"6. Remediation Plan ({len(remediation)} items)", styles["SectionHeader"]))
            story.append(Spacer(1, 8))
            rem_data = [["Priority", "Severity", "Summary"]]
            for r in remediation[:25]:
                rem_data.append([
                    r.get("priority", ""),
                    r.get("severity", ""),
                    self._safe_p(r.get("summary", ""), styles["Small"]),
                ])
            story.append(self._make_table(rem_data, col_widths=[50, 60, 385]))

        # Build PDF
        try:
            doc.build(story)
        except Exception as e:
            logger.error(f"PDF build failed: {e}")
            return f"PDF generation failed: {str(e)}".encode()

        pdf_bytes = buffer.getvalue()
        buffer.close()
        logger.info(f"PDF report generated: {len(pdf_bytes)} bytes")
        return pdf_bytes

    def _get_styles(self):
        """Create custom paragraph styles."""
        styles = getSampleStyleSheet()

        styles.add(ParagraphStyle(
            name="CoverTitle", fontSize=36, textColor=PRISM_CYAN,
            alignment=TA_CENTER, spaceAfter=24, fontName="Helvetica-Bold", leading=42,
        ))
        styles.add(ParagraphStyle(
            name="CoverSubtitle", fontSize=14, textColor=PRISM_GRAY,
            alignment=TA_CENTER, spaceAfter=10, leading=18,
        ))
        styles.add(ParagraphStyle(
            name="CoverMeta", fontSize=11, textColor=PRISM_GRAY,
            alignment=TA_CENTER, spaceAfter=4,
        ))
        styles.add(ParagraphStyle(
            name="SectionHeader", fontSize=18, textColor=PRISM_BLUE,
            spaceAfter=8, fontName="Helvetica-Bold",
            borderWidth=0, borderPadding=0,
        ))
        styles.add(ParagraphStyle(
            name="SubHeader", fontSize=13, textColor=PRISM_CYAN,
            spaceAfter=6, fontName="Helvetica-Bold",
        ))
        styles.add(ParagraphStyle(
            name="Small", fontSize=9, textColor=PRISM_GRAY,
            spaceAfter=2,
        ))

        styles["BodyText"].fontSize = 10
        styles["BodyText"].leading = 14
        styles["BodyText"].textColor = colors.HexColor("#333333")

        return styles

    def _safe_p(self, text, style):
        from xml.sax.saxutils import escape
        try:
            from reportlab.platypus import Paragraph
        except ImportError:
            return str(text)
        return Paragraph(escape(str(text)), style)

    def _make_table(self, data: list, col_widths: list | None = None) -> Table:
        """Create a styled table."""
        t = Table(data, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRISM_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
            ("TOPPADDING", (0, 1), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        return t

    def _render_findings_table(self, findings: list, styles) -> list:
        """Render a list of findings as a table."""
        data = [["Severity", "Type", "Identity/Resource", "Description"]]
        for f in findings[:15]:
            data.append([
                f.get("severity", ""),
                self._safe_p(f.get("type", ""), styles["Small"]),
                self._safe_p((f.get("identity", "") or f.get("resource", "")), styles["Small"]),
                self._safe_p(f.get("description", ""), styles["Small"]),
            ])
        return [self._make_table(data, col_widths=[55, 90, 110, 240])]
