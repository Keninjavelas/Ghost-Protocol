"""
ai_core/pdf_report.py
Generate a professional PDF intelligence report from the report JSON dict.

Uses fpdf2 (pure-Python, no external dependencies).
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

from fpdf import FPDF


class _GhostPDF(FPDF):
    """Custom PDF with Ghost Protocol header/footer branding."""

    _title_text: str = "AI Intelligence Report"
    _session_id: str = ""

    def header(self) -> None:
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 100, 100)
        w = self.w - self.l_margin - self.r_margin
        self.cell(w / 2, 6, "GHOST PROTOCOL | AI CYBER DEFENSE", align="L")
        self.cell(w / 2, 6, "CLASSIFIED - INTERNAL USE ONLY", align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(80, 80, 80)
        self.line(10, self.get_y(), self.w - 10, self.get_y())
        self.ln(4)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(140, 140, 140)
        self.cell(0, 10, f"Ghost Protocol | Session: {self._session_id} | Page {self.page_no()}/{{nb}}", align="C")


def _safe(val: Any, default: str = "N/A") -> str:
    """Safely convert any value to a latin-1 printable string (Helvetica compatible)."""
    if val is None:
        return default
    if isinstance(val, bool):
        return "Yes" if val else "No"
    if isinstance(val, (list, dict)):
        if isinstance(val, list):
            val = ", ".join(str(v) for v in val)
        else:
            val = ", ".join(f"{k}: {v}" for k, v in val.items())
    text = str(val).strip() or default
    # Common Unicode substitutions
    _replacements = {
        "\u2014": "--", "\u2013": "-", "\u2012": "-",
        "\u2018": "'", "\u2019": "'", "\u02bc": "'",
        "\u201c": '"', "\u201d": '"',
        "\u2026": "...", "\u2022": "*", "\u2023": ">",
        "\u2192": "->", "\u2190": "<-",
        "\u2713": "[x]", "\u2717": "[ ]", "\u2716": "[x]",
        "\u00b7": "*", "\u25cf": "*", "\u25cb": "o",
        "\u2502": "|", "\u2500": "-", "\u250c": "+", "\u2514": "+",
        "\u2510": "+", "\u2518": "+",
        "\u200b": "", "\u200c": "", "\u200d": "", "\ufeff": "",
    }
    for old, new in _replacements.items():
        text = text.replace(old, new)
    # Drop any remaining characters outside latin-1 range
    text = text.encode("latin-1", errors="replace").decode("latin-1")
    return text


def generate_pdf(report: dict[str, Any]) -> bytes:
    """
    Accept the report JSON dict (same schema as ReportGenerator output)
    and return the PDF file content as bytes.
    """
    pdf = _GhostPDF(orientation="P", unit="mm", format="A4")
    pdf._session_id = _safe(report.get("session_id"), "N/A")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # ── Title ──────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 14, "AI Intelligence Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 100, 100)
    gen_at = report.get("generated_at", datetime.now(timezone.utc).isoformat())
    pdf.cell(0, 6, f"Generated: {gen_at}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Session: {_safe(report.get('session_id'))}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # ── Executive Summary ──────────────────────────────────────────────────
    _section_heading(pdf, "Executive Summary")
    _body_text(pdf, _safe(report.get("executive_summary"), "No summary available."))
    pdf.ln(4)

    # ── Attacker Profile ───────────────────────────────────────────────────
    prof = report.get("attacker_profile") or {}
    _section_heading(pdf, "Attacker Profile")
    _kv_row(pdf, "Type", _safe(prof.get("type") or report.get("attacker_type")))
    _kv_row(pdf, "Primary Objective", _safe(prof.get("objective") or report.get("primary_objective")))
    _kv_row(pdf, "Sophistication", _safe(prof.get("sophistication") or report.get("sophistication_level")))
    _kv_row(pdf, "Likely Nation-State", _safe(prof.get("likely_nation_state")))
    pdf.ln(4)

    # ── Threat Assessment ──────────────────────────────────────────────────
    ta = report.get("threat_assessment") or {}
    _section_heading(pdf, "Threat Assessment")
    risk = ta.get("risk_score", report.get("risk_score", 0))
    level = _safe(ta.get("threat_level", report.get("threat_level")))
    _kv_row(pdf, "Risk Score", f"{risk}/100")
    _kv_row(pdf, "Threat Level", level)
    _kv_row(pdf, "Immediate Danger", _safe(ta.get("immediate_danger")))
    dar = ta.get("data_at_risk") or []
    if dar:
        _kv_row(pdf, "Data at Risk", ", ".join(str(d) for d in dar))
    pdf.ln(4)

    # ── MITRE ATT&CK Techniques ───────────────────────────────────────────
    techs = report.get("techniques_used") or []
    if techs:
        _section_heading(pdf, f"MITRE ATT&CK Techniques ({len(techs)})")
        # Table header
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(40, 40, 50)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(25, 7, "ID", border=1, fill=True)
        pdf.cell(55, 7, "Technique", border=1, fill=True)
        pdf.cell(0, 7, "Description", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "", 9)
        for i, t in enumerate(techs):
            fill = i % 2 == 0
            if fill:
                pdf.set_fill_color(245, 245, 250)
            pdf.cell(25, 7, _safe(t.get("mitre_id") or t.get("id")), border=1, fill=fill)
            pdf.cell(55, 7, _safe(t.get("name"))[:35], border=1, fill=fill)
            pdf.cell(0, 7, _safe(t.get("description"))[:70], border=1, fill=fill, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    # ── Intent Analysis ────────────────────────────────────────────────────
    ia = report.get("intent_analysis") or {}
    if ia:
        _section_heading(pdf, "Intent Analysis")
        _kv_row(pdf, "Primary Goal", _safe(ia.get("primary_goal")))
        sg = ia.get("secondary_goals") or []
        if sg:
            _kv_row(pdf, "Secondary Goals", ", ".join(str(g) for g in sg))
        _kv_row(pdf, "Behavioral Patterns", _safe(ia.get("behavioral_patterns")))
        pdf.ln(4)

    # ── Mitigation Suggestions ─────────────────────────────────────────────
    mits = report.get("mitigation_suggestions") or []
    if mits:
        _section_heading(pdf, "Mitigation Suggestions")
        pdf.set_font("Helvetica", "", 10)
        for i, m in enumerate(mits, 1):
            _body_text(pdf, f"{i}. {_safe(m)}")
        pdf.ln(4)

    # ── Indicators of Compromise ───────────────────────────────────────────
    iocs = report.get("iocs") or {}
    if iocs:
        _section_heading(pdf, "Indicators of Compromise (IOCs)")
        ips = iocs.get("ip_addresses") or []
        if ips:
            _kv_row(pdf, "IP Addresses", ", ".join(str(ip) for ip in ips))
        users = iocs.get("usernames") or []
        if users:
            _kv_row(pdf, "Usernames", ", ".join(str(u) for u in users))
        tools = iocs.get("tools_or_commands") or []
        if tools:
            _kv_row(pdf, "Tools / Commands", ", ".join(str(c) for c in tools))
        pdf.ln(4)

    # ── Classification Footer ──────────────────────────────────────────────
    pdf.ln(6)
    pdf.set_draw_color(80, 80, 80)
    pdf.line(10, pdf.get_y(), pdf.w - 10, pdf.get_y())
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(180, 50, 50)
    pdf.cell(0, 6, "CLASSIFICATION: INTERNAL - Generated by Ghost Protocol AI Cyber Defense System", align="C")

    # ── Output ─────────────────────────────────────────────────────────────
    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _section_heading(pdf: FPDF, title: str) -> None:
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(50, 90, 180)
    pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(50, 90, 180)
    pdf.line(10, pdf.get_y(), 80, pdf.get_y())
    pdf.ln(3)


def _kv_row(pdf: FPDF, key: str, value: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(48, 6, key + ":", new_x="END")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(30, 30, 30)
    val_w = pdf.w - pdf.r_margin - pdf.get_x()
    if val_w < 20:
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 6, value[:300])
    else:
        pdf.multi_cell(val_w, 6, value[:300])
    pdf.set_x(pdf.l_margin)


def _body_text(pdf: FPDF, text: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(40, 40, 40)
    pdf.multi_cell(0, 5.5, text)
    pdf.set_x(pdf.l_margin)
