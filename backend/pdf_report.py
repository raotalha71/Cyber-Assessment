# pdf_report.py
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def generate_scan_pdf(sme_name, target_url, summary, findings):
    path = _get_downloads_path()
    filename = f"scan_report_{sme_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    full_path = os.path.join(path, filename)

    c = canvas.Canvas(full_path, pagesize=A4)
    width, height = A4
    y = height - 40

    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "SME Cyber Risk Scan Report")
    y -= 30

    c.setFont("Helvetica", 11)
    c.drawString(40, y, f"SME: {sme_name}")
    y -= 15
    c.drawString(40, y, f"Target: {target_url}")
    y -= 20

    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Summary")
    y -= 15
    c.setFont("Helvetica", 11)
    for k, v in summary["by_severity"].items():
        c.drawString(50, y, f"{k}: {v}")
        y -= 12

    y -= 20
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Findings")
    y -= 15
    c.setFont("Helvetica", 9)

    for f in findings[:20]:
        line = f"- [{f['severity']}] {f['title'][:90]}"
        c.drawString(50, y, line)
        y -= 10
        if y < 60:
            c.showPage()
            y = height - 40
            c.setFont("Helvetica", 9)

    c.save()
    return full_path

def _get_downloads_path():
    # Cross-platform: prefer HOME/Downloads or USERPROFILE\Downloads on Windows
    home = os.path.expanduser("~")
    dl = os.path.join(home, "Downloads")
    os.makedirs(dl, exist_ok=True)
    return dl

def generate_pdf(summary: dict, output_dir=None):
    if not output_dir:
        output_dir = _get_downloads_path()
    os.makedirs(output_dir, exist_ok=True)
    filename = f"cyber_risk_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = os.path.join(output_dir, filename)

    c = canvas.Canvas(path, pagesize=A4)
    width, height = A4
    y = height - 40

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "Cyber Risk Assessment Report")
    y -= 28

    # Metadata
    c.setFont("Helvetica", 12)
    c.drawString(40, y, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    y -= 20

    # High-level scores
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, f"Overall Score: {summary.get('normalized')} / 100  ({summary.get('label')})")
    y -= 22
    c.setFont("Helvetica", 11)
    c.drawString(40, y, f"Business Type: {summary.get('business_type', '-')}")
    y -= 20

    # Components breakdown
    comps = summary.get("components", {})
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Breakdown")
    y -= 16
    c.setFont("Helvetica", 11)
    c.drawString(48, y, f"Manual Sum: {comps.get('manual_sum', 0)} (count {comps.get('manual_count', 0)})")
    y -= 14
    # We keep the existing keys from your backend (zap_sum/zap_count) but label them generically for Nikto
    c.drawString(48, y, f"Scanner Sum (Nikto): {comps.get('zap_sum', 0)} (count {comps.get('zap_count', 0)})")
    y -= 20

    # Alerts
    alerts = summary.get("alerts", [])
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, f"Alerts (showing up to 25) — total found: {len(alerts)}")
    y -= 18
    c.setFont("Helvetica", 10)
    if alerts:
        for a in alerts[:25]:
            line = f"- {a.get('name')} | risk={a.get('risk', 'Unknown')} | conf={a.get('confidence', 'Unknown')} | uri={a.get('uri','')[:60]}"
            c.drawString(48, y, line[:120])
            y -= 12
            if y < 60:
                c.showPage()
                y = height - 40
                c.setFont("Helvetica", 10)
    else:
        c.drawString(48, y, "No alerts were reported by the URL scanner.")
        y -= 12

    c.save()
    return path


def generate_scan_pdf_report(scan_run_id: int):
    """Generate comprehensive PDF report for a scan"""
    from db_helpers import get_scan_report
    
    report_data = get_scan_report(scan_run_id)
    if not report_data:
        raise ValueError(f"Scan {scan_run_id} not found")
    
    run = report_data.get("run", {})
    findings = report_data.get("findings", [])
    
    path = _get_downloads_path()
    filename = f"scan_report_{scan_run_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    full_path = os.path.join(path, filename)
    
    c = canvas.Canvas(full_path, pagesize=A4)
    width, height = A4
    y = height - 40
    
    # Title
    c.setFont("Helvetica-Bold", 18)
    c.drawString(40, y, "Cyber Risk Assessment - Scan Report")
    y -= 30
    
    # Metadata
    c.setFont("Helvetica", 11)
    c.drawString(40, y, f"Target URL: {run.get('target_url', 'N/A')}")
    y -= 15
    c.drawString(40, y, f"Scan Date: {run.get('created_at', 'N/A')}")
    y -= 15
    c.drawString(40, y, f"Scan ID: {scan_run_id}")
    y -= 25
    
    # Risk Score Section
    c.setFont("Helvetica-Bold", 14)
    risk_level = run.get("risk_level", "Unknown")
    final_score = run.get("final_score", 0)
    c.drawString(40, y, f"Risk Level: {risk_level}")
    y -= 20
    
    c.setFont("Helvetica", 12)
    c.drawString(40, y, f"Final Risk Score: {final_score:.1f}/100")
    y -= 15
    c.drawString(40, y, f"Base Score: {run.get('base_score', 0):.1f}")
    y -= 25
    
    # SME Multipliers
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Business Context Multipliers:")
    y -= 15
    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"• Business Type: {run.get('business_type_multiplier', 1.0)}x")
    y -= 12
    c.drawString(50, y, f"• Data Sensitivity: {run.get('data_sensitivity_multiplier', 1.0)}x")
    y -= 12
    c.drawString(50, y, f"• IT Dependency: {run.get('it_dependency_multiplier', 1.0)}x")
    y -= 25
    
    # Summary statistics
    summary = run.get("summary_json", "{}")
    if isinstance(summary, str):
        import json
        summary = json.loads(summary)
    
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Vulnerability Summary:")
    y -= 15
    c.setFont("Helvetica", 10)
    
    by_severity = summary.get("by_severity", {})
    c.drawString(50, y, f"• High Severity: {by_severity.get('High', 0)}")
    y -= 12
    c.drawString(50, y, f"• Medium Severity: {by_severity.get('Medium', 0)}")
    y -= 12
    c.drawString(50, y, f"• Low Severity: {by_severity.get('Low', 0)}")
    y -= 12
    c.drawString(50, y, f"• Total Findings: {summary.get('total_findings', 0)}")
    y -= 25
    
    # Findings details
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, f"Detailed Findings (Top 30):")
    y -= 18
    c.setFont("Helvetica", 9)
    
    for idx, f in enumerate(findings[:30], 1):
        if y < 100:
            c.showPage()
            y = height - 40
            c.setFont("Helvetica", 9)
        
        title = f.get("title", "Unknown")[:100]
        severity = f.get("severity", "Unknown")
        confidence = f.get("confidence", "Unknown")
        owasp = f.get("owasp_category", "N/A")
        
        c.drawString(45, y, f"{idx}. [{severity}] {title}")
        y -= 10
        c.drawString(55, y, f"Confidence: {confidence} | OWASP: {owasp}")
        y -= 12
    
    # Recommendations
    if y < 150:
        c.showPage()
        y = height - 40
    
    y -= 10
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Recommendations:")
    y -= 15
    c.setFont("Helvetica", 10)
    
    if final_score >= 75:
        recs = [
            "CRITICAL: Immediate action required to address high-risk vulnerabilities",
            "Conduct comprehensive security audit",
            "Implement web application firewall (WAF)",
            "Review and patch all outdated components"
        ]
    elif final_score >= 50:
        recs = [
            "HIGH PRIORITY: Address security misconfigurations",
            "Update security headers (X-Frame-Options, CSP, etc.)",
            "Review access controls and authentication",
            "Schedule regular security assessments"
        ]
    elif final_score >= 25:
        recs = [
            "MEDIUM PRIORITY: Continue improving security posture",
            "Address identified vulnerabilities systematically",
            "Implement security best practices",
            "Consider penetration testing"
        ]
    else:
        recs = [
            "LOW RISK: Maintain current security practices",
            "Continue monitoring for new vulnerabilities",
            "Stay updated with security patches",
            "Regular security awareness training"
        ]
    
    for rec in recs:
        c.drawString(50, y, f"• {rec}")
        y -= 12
        if y < 60:
            c.showPage()
            y = height - 40
            c.setFont("Helvetica", 10)
    
    # Footer
    if y < 80:
        c.showPage()
        y = height - 40
    
    y = 50
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(40, y, "This report was generated automatically by the Cyber Risk Assessment System")
    y -= 10
    c.drawString(40, y, f"Report generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    
    c.save()
    return full_path
