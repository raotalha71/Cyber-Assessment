# app.py — FINAL STABLE BACKEND (Auth + SME + Manual + Scan + Admin)

import os
import shutil
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

# ------------------------------------------------------------
# Database
# ------------------------------------------------------------
from db_helpers import (
    init_db,
    create_sme,
    list_smes,
    get_sme,
    update_sme,
    save_manual_assessment,
    save_scan_run,
    save_scan_finding,
    get_user_scan_history,
    get_all_scan_history,
    get_scan_report,
)

# ------------------------------------------------------------
# Authentication
# ------------------------------------------------------------
from auth_db import (
    init_auth_db,
    create_user,
    get_user_by_email,
    get_user_by_id,
    verify_password,
    store_totp_secret,
    activate_user,
    list_users,
    set_user_active,
    delete_user,
    admin_reset_password,
)

# ------------------------------------------------------------
# Manual assessment
# ------------------------------------------------------------
from manual.manual_questions import MANUAL_QUESTIONS
from manual.manual_scoring import calculate_manual_risk

# ------------------------------------------------------------
# Scanning
# ------------------------------------------------------------
from nikto_runner import run_nikto_scan
from scan.owasp_map import map_owasp
from scan.scan_scoring import calculate_severity, calculate_confidence, calculate_scan_score
from scan.vuln_explain import explain_alert, explain_finding

# ------------------------------------------------------------
# TOTP
# ------------------------------------------------------------
from totp_utils import generate_totp_secret, generate_qr_code, verify_totp

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)
CORS(app)

# ============================================================
# HELPERS
# ============================================================
def get_request_user():
    uid = request.args.get("user_id")
    if uid is None:
        body = request.get_json(silent=True) or {}
        uid = body.get("user_id")
    if not uid:
        return None
    return get_user_by_id(int(uid))


def admin_only(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_request_user()
        if not user or user.get("role") != "admin":
            return jsonify({"ok": False, "error": "Admin only"}), 403
        return fn(*args, **kwargs)
    return wrapper


# ============================================================
# ADMIN
# ============================================================
@app.post("/admin/login")
def admin_login():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if (
        email != os.getenv("DEFAULT_ADMIN_EMAIL", "").strip().lower()
        or password != os.getenv("DEFAULT_ADMIN_PASSWORD", "")
    ):
        return jsonify({"ok": False, "error": "Invalid admin credentials"}), 200

    admin_user = get_user_by_email(email)
    if not admin_user or admin_user.get("role") != "admin":
        return jsonify({"ok": False, "error": "Admin user missing"}), 200

    return jsonify({
        "ok": True,
        "user_id": admin_user["id"],
        "email": admin_user["email"],
        "role": "admin",
        "full_name": admin_user.get("full_name", "Admin"),
    }), 200


@app.get("/admin/users")
@admin_only
def admin_list_users():
    return jsonify({"ok": True, "items": list_users()}), 200


@app.post("/admin/users/disable")
@admin_only
def admin_disable_user():
    set_user_active(int(request.json.get("target_user_id", 0)), False)
    return jsonify({"ok": True}), 200


@app.post("/admin/users/enable")
@admin_only
def admin_enable_user():
    set_user_active(int(request.json.get("target_user_id", 0)), True)
    return jsonify({"ok": True}), 200


@app.post("/admin/users/reset-password")
@admin_only
def admin_reset_user_password():
    admin_reset_password(
        int(request.json.get("target_user_id", 0)),
        request.json.get("new_password", ""),
    )
    return jsonify({"ok": True}), 200


@app.delete("/admin/users/<int:target_user_id>")
@admin_only
def admin_delete_user(target_user_id):
    delete_user(target_user_id)
    return jsonify({"ok": True}), 200


@app.get("/admin/health")
@admin_only
def admin_health():
    return jsonify({"ok": True}), 200


@app.get("/admin/nikto")
@admin_only
def admin_nikto():
    nikto_path = shutil.which("nikto")
    return jsonify({
        "ok": True,
        "nikto_found": bool(nikto_path),
        "nikto_path": nikto_path,
    }), 200


# ============================================================
# AUTH
# ============================================================
@app.post("/auth/register")
def register():
    data = request.json or {}
    res = create_user(
        data.get("email", "").strip().lower(),
        data.get("password", ""),
        data.get("full_name", ""),
    )

    if not res["ok"]:
        return jsonify(res), 200

    secret = generate_totp_secret()
    store_totp_secret(res["user_id"], secret)

    return jsonify({
        "ok": True,
        "user_id": res["user_id"],
        "qr_code": generate_qr_code(data["email"], secret),
    }), 200


@app.post("/auth/verify-totp")
def verify_totp_api():
    user = get_user_by_id(int(request.json.get("user_id", 0)))
    if not user or not verify_totp(user["totp_secret"], request.json.get("code", "")):
        return jsonify({"ok": False, "error": "Invalid code"}), 200

    activate_user(user["id"])
    return jsonify({"ok": True}), 200


@app.post("/auth/login")
def login():
    user = get_user_by_email(request.json.get("email", "").strip().lower())
    if not user or not verify_password(user, request.json.get("password", "")):
        return jsonify({"ok": False, "error": "Invalid credentials"}), 200

    if not user["is_active"]:
        return jsonify({"ok": False, "error": "Complete TOTP setup"}), 200

    return jsonify({
        "ok": True,
        "user_id": user["id"],
        "email": user["email"],
        "full_name": user["full_name"],
    }), 200


# ============================================================
# SME
# ============================================================
@app.post("/smes")
def create_sme_api():
    return jsonify({"ok": True, "sme_id": create_sme(request.json)}), 200


@app.get("/smes")
def list_smes_api():
    return jsonify({"items": list_smes()}), 200


@app.get("/smes/<int:sme_id>")
def get_sme_api(sme_id):
    return jsonify({"ok": True, "sme": get_sme(sme_id)}), 200


@app.put("/smes/<int:sme_id>")
def update_sme_api(sme_id):
    update_sme(sme_id, request.json)
    return jsonify({"ok": True}), 200


# ============================================================
# MANUAL
# ============================================================
@app.get("/manual/questions")
def manual_questions():
    return jsonify({"ok": True, "questions": MANUAL_QUESTIONS}), 200


@app.post("/manual/assess")
def manual_assess():
    data = request.get_json(force=True) or {}
    answers = data.get("answers", [])
    
    # Convert answers to dict format for calculate_manual_risk
    answers_dict = {ans["question_id"]: ans["answer"] for ans in answers}
    
    result = calculate_manual_risk(answers_dict)
    
    # Save assessment (use user_id as sme_id if not provided)
    sme_id = data.get("sme_id") or data.get("user_id")
    save_manual_assessment(
        sme_id,
        answers_dict,
        result,
    )
    
    return jsonify({
        "ok": True,
        "risk_level": result.get("risk_level", "Unknown"),
        "score": result.get("score", 0),
        "category": result.get("category", "N/A"),
        "recommendations": result.get("recommendations", [])
    }), 200


# ============================================================
# SCAN (REAL NIKTO + SME ENRICHMENT)
# ============================================================
@app.post("/scan/start")
def start_scan():
    """
    Start a Nikto vulnerability scan
    Returns findings with ML-enhanced confidence scores
    """
    try:
        data = request.get_json(force=True) or {}
        target = data.get("target")
        
        if not target:
            return jsonify({"ok": False, "error": "Target URL is required"}), 400
        
        print(f"[INFO] Starting scan for: {target}")
        scan = run_nikto_scan(target)

        if not scan.get("ok"):
            return jsonify(scan), 200
    except Exception as e:
        print(f"[ERROR] Scan failed: {e}")
        return jsonify({
            "ok": False,
            "error": f"Scan failed: {str(e)}"
        }), 500

    findings = []
    ml_enabled = True  # Flag to indicate ML is being used

    for alert in scan.get("alerts", []):
        nikto_finding = alert.get("name", "")

        finding = {
            "title": nikto_finding,  # Keep original Nikto finding
            "raw_finding": nikto_finding,  # Store original
            "owasp": map_owasp(nikto_finding),
            "severity": calculate_severity(nikto_finding),
            "confidence": calculate_confidence(nikto_finding, use_ml=True),
            "ml_enhanced": True,  # Indicates ML-enhanced confidence
            "uri": alert.get("uri"),
        }

        # Get friendly explanation if available (but don't overwrite title)
        nikto_hint = explain_alert(nikto_finding)
        if nikto_hint:
            finding["friendly_title"] = nikto_hint.get("title", "")
            finding["meaning"] = nikto_hint.get("meaning", "")
            finding["technical_details"] = nikto_hint.get("business_impact", "")
            finding["fix_recommendation"] = nikto_hint.get("recommendation", "")

        # Add OWASP explanations
        owasp_info = explain_finding(finding)
        finding.update(owasp_info)
        
        findings.append(finding)

    summary = {
        "total_findings": len(findings),
        "by_severity": {
            "High": sum(f["severity"] == "High" for f in findings),
            "Medium": sum(f["severity"] == "Medium" for f in findings),
            "Low": sum(f["severity"] == "Low" for f in findings),
        },
    }

    # Use sme_id if provided, otherwise use user_id as sme_id for backwards compatibility
    sme_id = data.get("sme_id") or data.get("user_id")
    
    # Get SME profile for business multipliers
    sme_profile = None
    if sme_id:
        sme_profile = get_sme(sme_id)
    
    # Calculate scan score with SME multipliers
    score_data = calculate_scan_score(findings, sme_profile)
    
    # Add score to summary
    summary.update({
        "base_score": score_data["base_score"],
        "final_score": score_data["final_score"],
        "risk_level": score_data["risk_level"],
    })
    
    scan_id = save_scan_run(
        sme_id,
        data.get("user_id"),
        data.get("target"),
        summary,
        score_data,
    )

    for f in findings:
        save_scan_finding(scan_id, f)

    return jsonify({
        "ok": True,
        "scan_run_id": scan_id,
        "summary": summary,
        "score": score_data,
        "findings": findings,
        "raw_output_path": scan.get("out_path"),
    }), 200


# ============================================================
# USER HISTORY
# ============================================================
@app.get("/user/history")
def user_history():
    """Get scan and manual assessment history for a user"""
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "user_id required"}), 400
    
    scans = get_user_scan_history(int(user_id), limit=50)
    
    return jsonify({
        "ok": True,
        "scans": scans,
    }), 200


@app.get("/report/scan/<int:scan_id>")
def download_scan_report(scan_id):
    """Generate and return PDF report for a scan"""
    from pdf_report import generate_scan_pdf_report
    
    try:
        pdf_path = generate_scan_pdf_report(scan_id)
        from flask import send_file
        return send_file(pdf_path, as_attachment=True, download_name=f"scan_report_{scan_id}.pdf")
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ============================================================
# ADMIN ENHANCED
# ============================================================
@app.get("/admin/scans")
def admin_all_scans():
    """Get all scans for admin dashboard"""
    user = get_request_user()
    if not user or not user.get("is_admin"):
        return jsonify({"ok": False, "error": "Admin access required"}), 403
    
    scans = get_all_scan_history(limit=100)
    return jsonify({"ok": True, "scans": scans}), 200


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    init_db()
    init_auth_db()
    # Use debug=False in production or use_reloader=False to prevent scan interruption
    app.run(port=5050, debug=True, use_reloader=False)
