"""PDF investigation report. Observed evidence and interpretations are kept in separate sections."""
import time
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

NAVY = colors.HexColor("#0a1628")
BLUE = colors.HexColor("#2f7bff")
GREY = colors.HexColor("#8aa4cc")

_ss = getSampleStyleSheet()
BODY = ParagraphStyle("body", parent=_ss["BodyText"], fontSize=9.5, leading=13)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=7.8, leading=10)
WHITE = ParagraphStyle("white", parent=SMALL, textColor=colors.white, fontName="Helvetica-Bold")
HEAD = ParagraphStyle("head", parent=_ss["Heading2"], textColor=BLUE, spaceBefore=10, spaceAfter=4)


def _utc(ts):
    return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _table(rows, widths, header=True):
    cells = []
    for i, row in enumerate(rows):
        st = WHITE if (header and i == 0) else SMALL
        cells.append([Paragraph(escape(str(c)), st) for c in row])
    t = Table(cells, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.25, GREY), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    t.setStyle(TableStyle(style))
    return t


def _p(text, style=BODY):
    return Paragraph(escape(str(text)), style)


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.grey)
    canvas.drawString(15 * mm, 8 * mm, f"CyberTrace AI Agent  |  Confidential  |  {doc.investigation_id}")
    canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(path, inv, evidence, findings, executions, timeline, notes, risk):
    doc = SimpleDocTemplate(path, pagesize=A4, title=f"CyberTrace report {inv['investigation_id']}",
                            leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm)
    doc.investigation_id = inv["investigation_id"]
    width = A4[0] - 30 * mm
    s = []

    s.append(_p("CyberTrace AI Agent: Investigation Report", _ss["Title"]))
    s.append(_p("Think Like an Analyst. Investigate Like an Expert. Defend Like an AI.", BODY))
    s.append(Spacer(1, 8))
    s.append(_table([
        ["Investigation ID", inv["investigation_id"]],
        ["Title", inv["title"]],
        ["Status", inv["status"]],
        ["Severity", inv["severity"]],
        ["Created", _utc(inv["created_at"])],
        ["Report generated", _utc(time.time())],
    ], [45 * mm, width - 45 * mm], header=False))

    s.append(_p("1. Incident description", HEAD))
    s.append(_p(inv.get("description") or "Not provided by the analyst.", BODY))

    s.append(_p("2. Evidence analysed", HEAD))
    if evidence:
        rows = [["File", "Type", "Size (bytes)", "Status", "Uploaded"]]
        rows += [[e["filename"], e["file_type"], e["size"], e["analysis_status"], _utc(e["created_at"])] for e in evidence]
        s.append(_table(rows, [60 * mm, 20 * mm, 25 * mm, 35 * mm, width - 140 * mm]))
    else:
        s.append(_p("No files uploaded. Analysis used pasted content only.", BODY))

    s.append(_p("3. Tools executed", HEAD))
    if executions:
        rows = [["Tool", "Status", "Timestamp (UTC)"]]
        rows += [[x["tool_name"], x["execution_status"], _utc(x["timestamp"])] for x in executions[-60:]]
        s.append(_table(rows, [70 * mm, 30 * mm, width - 100 * mm]))
    else:
        s.append(_p("No tools have been executed for this investigation.", BODY))

    s.append(_p("4. Threat classification, risk score and confidence", HEAD))
    s.append(_table([
        ["Risk score", f"{risk.get('score', 0)} / 100"],
        ["Threat category", risk.get("category", "LOW")],
        ["Confidence", f"{round(risk.get('confidence', 0.4) * 100)}%"],
        ["Rationale", risk.get("rationale", "n/a")],
    ], [45 * mm, width - 45 * mm], header=False))
    s.append(Spacer(1, 4))
    s.append(_p(risk.get("disclaimer", "Score reflects rule matches, not proof of compromise."), SMALL))

    observed = [f for f in findings if f["kind"] in ("observed", "intel")]
    interpreted = [f for f in findings if f["kind"] not in ("observed", "intel")]
    s.append(_p("5. Detected indicators: confirmed observations", HEAD))
    if observed:
        rows = [["Category", "Severity", "Source", "Description", "Evidence ref"]]
        rows += [[f["category"], f["severity"], f["kind"], f["description"], f["evidence_reference"]] for f in observed]
        s.append(_table(rows, [38 * mm, 18 * mm, 18 * mm, width - 110 * mm, 36 * mm]))
    else:
        s.append(_p("No directly observed or intel-backed indicators.", BODY))

    s.append(_p("6. Detailed findings: AI and rule-based interpretations", HEAD))
    s.append(_p("These are interpretations produced by detection rules. They are hypotheses for analyst validation, "
                "not confirmed facts.", SMALL))
    if interpreted:
        rows = [["Category", "Severity", "Confidence", "Description"]]
        rows += [[f["category"], f["severity"], f"{round(f['confidence'] * 100)}%", f["description"]] for f in interpreted]
        s.append(_table(rows, [42 * mm, 18 * mm, 22 * mm, width - 82 * mm]))
    else:
        s.append(_p("No interpretive findings.", BODY))

    s.append(_p("7. Investigation timeline", HEAD))
    if timeline:
        rows = [["#", "Timestamp", "Event", "Ref"]]
        rows += [[t["step"], t["timestamp"], t["event"], t["ref"]] for t in timeline[:100]]
        s.append(_table(rows, [10 * mm, 50 * mm, width - 80 * mm, 20 * mm]))
        if len(timeline) > 100:
            s.append(_p(f"Showing first 100 of {len(timeline)} events.", SMALL))
    else:
        s.append(_p("No timeline events available.", BODY))

    s.append(_p("8. Evidence limitations", HEAD))
    for line in [
        "Rule-based detections depend on log format and may miss events in unfamiliar formats.",
        "Submitted URLs were parsed, not visited. Attachments were not opened or executed.",
        "Threat reputation is live only when an API key is configured; otherwise it is labelled as a local heuristic.",
        "AI narratives are interpretation, not verified fact.",
        "This is a point-in-time snapshot. No host, endpoint or network telemetry was reviewed.",
    ]:
        s.append(_p("- " + line, BODY))

    s.append(_p("9. Recommended defensive actions", HEAD))
    for i, a in enumerate(risk.get("recommended_actions", []), 1):
        s.append(_p(f"{i}. {a}", BODY))

    s.append(_p("10. Analyst notes", HEAD))
    if notes:
        for n in notes:
            s.append(_p(f"[{_utc(n['created_at'])}] {n['body']}", BODY))
    else:
        s.append(_p("No analyst notes recorded.", BODY))

    s.append(_p("11. Conclusion", HEAD))
    s.append(_p(
        f"Overall classification: {risk.get('category', 'LOW')} with {round(risk.get('confidence', 0.4) * 100)}% confidence. "
        "The findings identify potential risk that requires analyst validation. On their own, they do not confirm "
        "that a compromise occurred.", BODY))

    doc.build(s, onFirstPage=_footer, onLaterPages=_footer)
    return path
