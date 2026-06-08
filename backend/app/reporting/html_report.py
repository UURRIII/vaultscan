"""Print-ready HTML security report. Open in a browser and 'Save as PDF'."""
from html import escape

SEV_COLOR = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
    "LOW": "#2563eb", "INFO": "#64748b",
}
GRADE_COLOR = {"A": "#16a34a", "B": "#65a30d", "C": "#ca8a04", "D": "#ea580c", "F": "#dc2626"}


def render_report(scan, findings, counts, risk) -> str:
    grade = risk["grade"]
    grade_color = GRADE_COLOR.get(grade, "#64748b")
    date = scan.created_at.strftime("%Y-%m-%d %H:%M UTC")

    summary_boxes = "".join(
        f'<div class="sbox"><div class="n" style="color:{SEV_COLOR[s]}">{counts.get(s, 0)}</div>'
        f'<div class="l">{s}</div></div>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )

    findings_html = ""
    for i, f in enumerate(findings, 1):
        color = SEV_COLOR.get(f.severity, "#64748b")
        findings_html += f"""
        <div class="finding">
          <div class="fhead">
            <span class="fnum">#{i}</span>
            <span class="badge" style="background:{color}">{f.severity}</span>
            <span class="cvss">CVSS {f.cvss}</span>
            {f'<span class="conf">{escape(f.confidence)}</span>' if f.confidence else ""}
            <span class="ftitle">{escape(f.title)}</span>
            {f'<span class="owasp">{escape(f.owasp)}</span>' if f.owasp else ""}
            {f'<span class="cwe">{escape(f.cwe)}</span>' if f.cwe else ""}
            <span class="fcat">{escape(f.category)}</span>
          </div>
          <div class="fbody">
            <div class="sec"><div class="lbl">Description</div><div class="val">{escape(f.description)}</div></div>
            {_section("Evidence", f.evidence) if f.evidence else ""}
            <div class="sec"><div class="lbl">Recommendation</div><div class="val">{escape(f.recommendation)}</div></div>
            {f'<div class="furl">{escape(f.url)}</div>' if f.url else ""}
          </div>
        </div>"""

    notes_html = ""
    if scan.notes:
        notes_html = f"""<div class="notes"><h2>Assessment Notes</h2><p>{escape(scan.notes)}</p></div>"""

    tags_html = ""
    if scan.tags:
        chips = "".join(f'<span class="tag">{escape(t.strip())}</span>'
                        for t in scan.tags.split(",") if t.strip())
        tags_html = f'<div class="tags">{chips}</div>'

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>VaultScan Report — {escape(scan.target)}</title>
<style>
  @page {{ margin: 1.5cm; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; color: #1e293b;
         max-width: 880px; margin: 0 auto; padding: 2.5rem 1.5rem; line-height: 1.55; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-start;
            border-bottom: 3px solid #6366f1; padding-bottom: 1.2rem; margin-bottom: 1.5rem; }}
  .logo {{ font-size: 1.4rem; font-weight: 800; }}
  .logo span {{ color: #6366f1; }}
  .logo-sub {{ font-size: 0.7rem; letter-spacing: 2px; color: #94a3b8; font-family: monospace; }}
  .meta {{ text-align: right; font-size: 0.82rem; color: #64748b; }}
  .meta strong {{ color: #1e293b; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 0.3rem; }}
  h2 {{ font-size: 1.05rem; color: #475569; margin: 2rem 0 1rem; border-bottom: 1px solid #e2e8f0; padding-bottom: 0.4rem; }}
  .riskrow {{ display: flex; gap: 1.5rem; align-items: center; background: #f8fafc;
             border: 1px solid #e2e8f0; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .grade {{ font-size: 3.5rem; font-weight: 800; line-height: 1; width: 90px; height: 90px;
           display: flex; align-items: center; justify-content: center; border-radius: 12px;
           color: #fff; flex-shrink: 0; }}
  .riskinfo {{ flex: 1; }}
  .riskinfo .score {{ font-size: 1.1rem; font-weight: 600; }}
  .riskbar {{ height: 8px; background: #e2e8f0; border-radius: 4px; margin-top: 0.6rem; overflow: hidden; }}
  .riskbar > div {{ height: 100%; border-radius: 4px; }}
  .summary {{ display: flex; gap: 0.75rem; margin-bottom: 0.5rem; }}
  .sbox {{ flex: 1; text-align: center; padding: 0.9rem; border: 1px solid #e2e8f0; border-radius: 8px; }}
  .sbox .n {{ font-size: 1.8rem; font-weight: 700; }}
  .sbox .l {{ font-size: 0.65rem; color: #64748b; font-weight: 600; letter-spacing: 0.5px; }}
  .tags {{ margin: 1rem 0; }}
  .tag {{ display: inline-block; background: #eef2ff; color: #6366f1; padding: 0.2rem 0.7rem;
         border-radius: 20px; font-size: 0.75rem; margin-right: 0.4rem; font-weight: 500; }}
  .finding {{ border: 1px solid #e2e8f0; border-radius: 10px; margin-bottom: 1rem; overflow: hidden;
             page-break-inside: avoid; }}
  .fhead {{ display: flex; align-items: center; gap: 0.6rem; padding: 0.85rem 1.1rem; background: #f8fafc; flex-wrap: wrap; }}
  .fnum {{ font-family: monospace; color: #94a3b8; font-size: 0.8rem; font-weight: 600; }}
  .badge {{ color: #fff; padding: 0.18rem 0.6rem; border-radius: 5px; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.5px; }}
  .cvss {{ font-family: monospace; font-size: 0.72rem; color: #475569; background: #e2e8f0; padding: 0.15rem 0.5rem; border-radius: 4px; }}
  .conf {{ font-size: 0.62rem; font-weight: 700; text-transform: uppercase; padding: 0.15rem 0.45rem; border-radius: 4px; background: #ecfdf5; color: #059669; }}
  .owasp {{ font-family: monospace; font-size: 0.68rem; font-weight: 600; color: #6d28d9; background: #f3e8ff; padding: 0.15rem 0.45rem; border-radius: 4px; }}
  .cwe {{ font-family: monospace; font-size: 0.68rem; color: #475569; background: #f1f5f9; padding: 0.15rem 0.45rem; border-radius: 4px; }}
  .ftitle {{ font-weight: 600; font-size: 0.92rem; flex: 1; }}
  .fcat {{ font-size: 0.72rem; color: #94a3b8; font-family: monospace; }}
  .fbody {{ padding: 1rem 1.1rem; }}
  .sec {{ margin-bottom: 0.85rem; }}
  .lbl {{ font-size: 0.66rem; font-weight: 700; color: #94a3b8; letter-spacing: 0.8px; text-transform: uppercase; margin-bottom: 0.3rem; }}
  .val {{ font-size: 0.84rem; white-space: pre-wrap; word-break: break-word; }}
  .sec.mono .val {{ font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; background: #f8fafc;
                   border: 1px solid #e2e8f0; border-radius: 5px; padding: 0.6rem 0.8rem; }}
  .furl {{ font-size: 0.76rem; color: #6366f1; font-family: monospace; margin-top: 0.5rem; }}
  .notes p {{ background: #fffbeb; border: 1px solid #fde68a; border-radius: 8px; padding: 1rem; font-size: 0.85rem; }}
  .footer {{ margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid #e2e8f0;
            font-size: 0.72rem; color: #94a3b8; text-align: center; }}
  @media print {{ body {{ padding: 0; }} .noprint {{ display: none; }} }}
  .printbtn {{ position: fixed; top: 1rem; right: 1rem; background: #6366f1; color: #fff;
              border: none; padding: 0.6rem 1.2rem; border-radius: 6px; font-size: 0.85rem;
              cursor: pointer; font-weight: 600; }}
</style></head><body>
<button class="printbtn noprint" onclick="window.print()">↓ Save as PDF</button>

<div class="header">
  <div>
    <div class="logo">Vault<span>Scan</span></div>
    <div class="logo-sub">SECURITY ASSESSMENT REPORT</div>
  </div>
  <div class="meta">
    Target: <strong>{escape(scan.target)}</strong><br>
    Date: {date}<br>
    Findings: <strong>{len(findings)}</strong>
  </div>
</div>

<div class="riskrow">
  <div class="grade" style="background:{grade_color}">{grade}</div>
  <div class="riskinfo">
    <div class="score">Risk Score: {risk['score']}/100</div>
    <div class="riskbar"><div style="width:{risk['score']}%;background:{grade_color}"></div></div>
    <div style="font-size:0.8rem;color:#64748b;margin-top:0.5rem">
      Overall security posture grade based on the severity and number of findings.
    </div>
  </div>
</div>

{tags_html}

<h2>Findings Summary</h2>
<div class="summary">{summary_boxes}</div>

{notes_html}

<h2>Detailed Findings</h2>
{findings_html if findings_html else '<p style="color:#64748b">No findings recorded.</p>'}

<div class="footer">
  Generated by VaultScan · This report is intended for authorized security assessment only.
</div>
</body></html>"""


def _section(label: str, value: str) -> str:
    return f'<div class="sec mono"><div class="lbl">{escape(label)}</div><div class="val">{escape(value)}</div></div>'
