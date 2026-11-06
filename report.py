"""Automated PDF compliance report (fpdf2, core fonts -> latin-1 text only)."""
from datetime import datetime
from fpdf import FPDF

SEV_RGB = {"CRITICAL": (176, 0, 32), "HIGH": (214, 90, 0), "MEDIUM": (160, 120, 0),
           "LOW": (30, 90, 170), "INFO": (90, 90, 90)}


def _t(s):
    return str(s).encode("latin-1", "replace").decode("latin-1")


class _PDF(FPDF):
    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 8, f"SysAdmin Guard-AI  |  Page {self.page_no()}", align="C")


def _line(pdf, text, size=10, style="", rgb=(0, 0, 0), h=5.5):
    pdf.set_font("Helvetica", style, size)
    pdf.set_text_color(*rgb)
    pdf.multi_cell(0, h, _t(text), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)


def build_pdf(host, result):
    pdf = _PDF()
    pdf.set_auto_page_break(True, 15)
    pdf.add_page()
    _line(pdf, "SysAdmin Guard-AI - Compliance Report", 18, "B", h=10)
    _line(pdf, f"Host: {host}    Generated: {datetime.now():%Y-%m-%d %H:%M}", 10)
    _line(pdf, f"Risk score: {result.risk}/100    Rating: {result.rating}", 13, "B", h=8)
    _line(pdf, f"Findings: {len(result.findings)}    Rules fired: {len(result.fired)}    "
               f"Derived facts: {len(result.derived)}")
    pdf.ln(3)

    _line(pdf, "1. Framework compliance", 13, "B", h=8)
    for fw, d in result.compliance().items():
        _line(pdf, f"{fw}: {d['pct']}% pass  ({d['failed']} of {d['checks']} checks failed)  "
                   f"-> {d['status']}")
    pdf.ln(3)

    _line(pdf, "2. Findings and remediation (highest severity first)", 13, "B", h=8)
    if not result.findings:
        _line(pdf, "No findings. All evaluated controls passed.")
    for f in result.findings:
        r = f.rule
        _line(pdf, f"[{r.severity}] {r.id} - {r.name}", 10, "B", SEV_RGB[r.severity])
        _line(pdf, f"Category: {r.category} | Refs: {r.refs or 'n/a'} | Points: {r.pts}", 9)
        if r.fix:
            _line(pdf, f"Remediation: {r.fix}", 9)
        pdf.ln(1.5)
    pdf.ln(2)

    _line(pdf, "3. Forward-chaining audit trail", 13, "B", h=8)
    _line(pdf, "Cycle | Depth | Rule | Facts asserted. Depth > 1 means the rule used "
               "conclusions of earlier rules.", 9, "I")
    for f in result.fired:
        asserted = ", ".join(f.new_facts) or "-"
        _line(pdf, f"#{f.cycle}  d{f.depth}  {f.rule.id}  asserts: {asserted}", 9, "B", h=5)
        _line(pdf, "   because " + "; ".join(f.evidence), 8, h=4.2)
    return bytes(pdf.output())
