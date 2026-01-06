# frontend_app.py — FINAL, STABLE, SME + ADMIN FRIENDLY FRONTEND
# Auth (TOTP) + SME + Manual + Scan + Admin + Raw Nikto Output

import re
import requests
import streamlit as st
import pandas as pd

DEFAULT_BACKEND = "http://127.0.0.1:5050"

st.set_page_config(
    page_title="Cyber Risk Assessment System",
    layout="wide",
)

# ============================================================
# SESSION STATE
# ============================================================
if "backend_url" not in st.session_state:
    st.session_state.backend_url = DEFAULT_BACKEND

if "page" not in st.session_state:
    st.session_state.page = "login"  # login | dashboard | manual | scan | admin

if "auth" not in st.session_state:
    st.session_state.auth = {
        "logged_in": False,
        "role": None,   # user | admin
        "user_id": None,
        "email": None,
        "full_name": None,
    }

backend_url = st.session_state.backend_url


# ============================================================
# HELPERS
# ============================================================
def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return re.sub(r"(?<!:)//+", "/", url)


def safe_json(resp):
    try:
        return resp.json()
    except Exception:
        st.error("Backend returned invalid response")
        st.code(resp.text)
        return None


def is_admin():
    return st.session_state.auth.get("role") == "admin"


# ============================================================
# AUTH UI
# ============================================================
def show_auth_ui():
    st.title("🔐 Cyber Risk Assessment System")

    tab_login, tab_register, tab_admin = st.tabs(
        ["User Login", "Register", "Admin Login"]
    )

    # ---------------- USER LOGIN ----------------
    with tab_login:
        email = st.text_input("Email", key="user_login_email")
        password = st.text_input("Password", type="password", key="user_login_pwd")

        if st.button("Login", key="user_login_btn"):
            r = requests.post(
                f"{backend_url}/auth/login",
                json={"email": email, "password": password},
            )
            data = safe_json(r)

            if not data or not data.get("ok"):
                st.error(data.get("error", "Login failed"))
                return

            st.session_state.auth.update({
                "logged_in": True,
                "role": "user",
                "user_id": data["user_id"],
                "email": data["email"],
                "full_name": data.get("full_name"),
            })
            st.session_state.page = "dashboard"
            st.rerun()

    # ---------------- USER REGISTER ----------------
    with tab_register:
        name = st.text_input("Full Name", key="reg_name")
        email = st.text_input("Email", key="reg_email")
        pwd1 = st.text_input("Password", type="password", key="reg_pwd1")
        pwd2 = st.text_input("Confirm Password", type="password", key="reg_pwd2")

        if st.button("Register", key="reg_btn"):
            if pwd1 != pwd2:
                st.error("Passwords do not match")
                return

            r = requests.post(
                f"{backend_url}/auth/register",
                json={
                    "email": email,
                    "password": pwd1,
                    "full_name": name,
                },
            )
            data = safe_json(r)

            if not data or not data.get("ok"):
                st.error(data.get("error", "Registration failed"))
                return

            st.success("Registration successful")
            st.info("Scan the QR code from backend logs to complete TOTP setup.")

    # ---------------- ADMIN LOGIN ----------------
    with tab_admin:
        admin_email = st.text_input("Admin Email", key="admin_login_email")
        admin_pwd = st.text_input("Admin Password", type="password", key="admin_login_pwd")

        if st.button("Login as Admin", key="admin_login_btn"):
            r = requests.post(
                f"{backend_url}/admin/login",
                json={"email": admin_email, "password": admin_pwd},
            )
            data = safe_json(r)

            if not data or not data.get("ok"):
                st.error(data.get("error", "Admin login failed"))
                return

            st.session_state.auth.update({
                "logged_in": True,
                "role": "admin",
                "user_id": data["user_id"],
                "email": data["email"],
                "full_name": data.get("full_name", "Admin"),
            })
            st.session_state.page = "admin"
            st.rerun()


# ============================================================
# SIDEBAR
# ============================================================
def show_sidebar():
    st.sidebar.title("Navigation")
    st.sidebar.write(f"👤 {st.session_state.auth['email']}")

    if st.sidebar.button("🏠 Dashboard"):
        st.session_state.page = "dashboard"
        st.rerun()

    if is_admin():
        if st.sidebar.button("🛠 Admin Panel"):
            st.session_state.page = "admin"
            st.rerun()
    else:
        if st.sidebar.button("📝 Manual Assessment"):
            st.session_state.page = "manual"
            st.rerun()

        if st.sidebar.button("🌐 Website Scan"):
            st.session_state.page = "scan"
            st.rerun()
        
        if st.sidebar.button("📊 My History"):
            st.session_state.page = "history"
            st.rerun()

    st.sidebar.divider()

    if st.sidebar.button("🚪 Logout"):
        st.session_state.clear()
        st.rerun()


# ============================================================
# DASHBOARD (USER)
# ============================================================
def show_dashboard():
    st.title("📊 Cyber Risk Assessment Dashboard")

    st.markdown("""
This system helps **SMEs understand cyber risks** using:
- Automated vulnerability scanning (Nikto)
- OWASP Top 10 mapping
- Business-friendly explanations
""")

    if st.button("📝 Start Manual Assessment"):
        st.session_state.page = "manual"
        st.rerun()

    if st.button("🌐 Run Website Scan"):
        st.session_state.page = "scan"
        st.rerun()


# ============================================================
# ADMIN DASHBOARD
# ============================================================
def show_admin_dashboard():
    st.title("🛠 Admin Control Panel")

    # Tab navigation for admin functions
    tab_users, tab_scans, tab_logs = st.tabs(["👥 Users", "🔍 All Scans", "📋 Access Logs"])
    
    with tab_users:
        st.subheader("User Management")
        
        users_resp = requests.get(
            f"{backend_url}/admin/users",
            params={"user_id": st.session_state.auth["user_id"]},
        )
        users = safe_json(users_resp).get("items", [])

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Users", len(users))
        col2.metric("Active Users", sum(u["is_active"] for u in users))
        col3.metric("Inactive Users", sum(not u["is_active"] for u in users))

        st.divider()

        for u in users:
            with st.expander(f"{u['email']} ({'✅ Active' if u['is_active'] else '❌ Disabled'})"):
                ucol1, ucol2, ucol3, ucol4 = st.columns(4)
                ucol1.write(f"**Name:** {u.get('full_name', 'N/A')}")
                ucol2.write(f"**ID:** {u['id']}")
                ucol3.write(f"**Admin:** {'Yes' if u.get('is_admin') else 'No'}")
                
                st.divider()
                
                c1, c2, c3 = st.columns(3)

                if c1.button("🚫 Disable", key=f"dis_{u['id']}"):
                    requests.post(
                        f"{backend_url}/admin/users/disable",
                        json={
                            "user_id": st.session_state.auth["user_id"],
                            "target_user_id": u["id"],
                        },
                    )
                    st.rerun()

                if c2.button("✅ Enable", key=f"ena_{u['id']}"):
                    requests.post(
                        f"{backend_url}/admin/users/enable",
                        json={
                            "user_id": st.session_state.auth["user_id"],
                            "target_user_id": u["id"],
                        },
                    )
                    st.rerun()

                if c3.button("🗑️ Delete", key=f"del_{u['id']}"):
                    requests.delete(
                        f"{backend_url}/admin/users/{u['id']}",
                        params={"user_id": st.session_state.auth["user_id"]},
                    )
                    st.rerun()
    
    with tab_scans:
        st.subheader("All System Scans")
        
        # Fetch all scans
        scans_resp = requests.get(f"{backend_url}/admin/scans")
        scans_data = safe_json(scans_resp)
        
        if not scans_data or not scans_data.get("ok"):
            st.error("Failed to load scans")
        else:
            scans = scans_data.get("scans", [])
            
            if not scans:
                st.info("No scans found in the system")
            else:
                st.success(f"Total scans: {len(scans)}")
                
                # Summary metrics
                total_critical = sum(1 for s in scans if s.get("risk_level") == "Critical")
                total_high = sum(1 for s in scans if s.get("risk_level") == "High")
                total_medium = sum(1 for s in scans if s.get("risk_level") == "Medium")
                total_low = sum(1 for s in scans if s.get("risk_level") == "Low")
                
                mcol1, mcol2, mcol3, mcol4 = st.columns(4)
                mcol1.metric("⚫ Critical", total_critical)
                mcol2.metric("🔴 High", total_high)
                mcol3.metric("🟡 Medium", total_medium)
                mcol4.metric("🟢 Low", total_low)
                
                st.divider()
                
                # Display scans
                for scan in scans[:50]:  # Limit to 50 most recent
                    risk_color = {
                        "Low": "🟢",
                        "Medium": "🟡",
                        "High": "🔴",
                        "Critical": "⚫"
                    }.get(scan.get("risk_level", "Unknown"), "⚪")
                    
                    with st.expander(f"{risk_color} {scan.get('target_url', 'N/A')} - {scan.get('risk_level', 'Unknown')} - {scan.get('created_at', 'N/A')}"):
                        acol1, acol2, acol3, acol4 = st.columns(4)
                        acol1.metric("Scan ID", scan.get("id"))
                        acol2.metric("User ID", scan.get("user_id", "N/A"))
                        acol3.metric("Risk Score", f"{scan.get('final_score', 0):.1f}/100")
                        acol4.metric("Base Score", f"{scan.get('base_score', 0):.1f}")
    
    with tab_logs:
        st.subheader("Access Logs & Monitoring")
        st.info("🚧 Access logging feature coming soon")
        st.write("Future features:")
        st.write("• User login/logout tracking")
        st.write("• Scan execution logs")
        st.write("• Failed authentication attempts")
        st.write("• System health monitoring")


# ============================================================
# MANUAL
# ============================================================
def show_manual():
    st.subheader("📝 Manual Cyber Risk Assessment")
    st.info("Answer the following questions to assess your organization's cybersecurity posture.")

    if st.button("⬅ Back"):
        st.session_state.page = "dashboard"
        st.rerun()

    # Get questions from backend
    resp = requests.get(f"{backend_url}/manual/questions")
    data = safe_json(resp)
    
    if not data or not data.get("ok"):
        st.error("Failed to load questions")
        return
    
    questions = data.get("questions", [])
    
    # Initialize answers in session state
    if "manual_answers" not in st.session_state:
        st.session_state.manual_answers = {}
    
    st.write(f"**Total Questions:** {len(questions)}")
    st.divider()
    
    # Display questions
    for q in questions:
        st.markdown(f"**{q['id']}. {q['text']}**")
        
        answer = st.radio(
            "Select your answer:",
            options=["Yes", "No", "Partially", "N/A"],
            key=f"q_{q['id']}",
            index=0 if q['id'] not in st.session_state.manual_answers else 
                  ["Yes", "No", "Partially", "N/A"].index(st.session_state.manual_answers.get(q['id'], "Yes"))
        )
        
        st.session_state.manual_answers[q['id']] = answer
        st.divider()
    
    # Submit button
    if st.button("📊 Calculate Risk Score", type="primary"):
        # Prepare answers for backend
        answers_payload = [
            {"question_id": qid, "answer": ans}
            for qid, ans in st.session_state.manual_answers.items()
        ]
        
        with st.spinner("Calculating risk score..."):
            score_resp = requests.post(
                f"{backend_url}/manual/assess",
                json={
                    "user_id": st.session_state.auth["user_id"],
                    "answers": answers_payload,
                }
            )
            score_data = safe_json(score_resp)
        
        if not score_data or not score_data.get("ok"):
            st.error(score_data.get("error", "Assessment failed"))
            return
        
        # Display results in clean layout
        st.success("Assessment completed successfully")
        st.write("")  # spacing
        
        # Calculate percentage and raw score
        risk_percentage = score_data.get('score', 0)
        risk_level = score_data.get('risk_level', 'Unknown')
        
        # Assuming 27 is max score (9 questions * 3 points each)
        raw_score = int((risk_percentage / 100) * 27)
        
        # Two column layout for Risk Score and Risk Level
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Risk Score**")
            st.markdown(f"<h1 style='font-size: 72px; margin: 0;'>{risk_percentage}%</h1>", unsafe_allow_html=True)
            st.markdown(f"**Raw Score:** {raw_score} / 27")
        
        with col2:
            st.markdown("**Risk Level**")
            # Color based on risk level
            risk_color = {
                "Low": "#00C853",
                "Medium": "#FFB300", 
                "High": "#E53935",
                "Critical": "#B71C1C"
            }.get(risk_level, "#757575")
            st.markdown(f"<h1 style='font-size: 72px; margin: 0; color: {risk_color};'>{risk_level}</h1>", unsafe_allow_html=True)
        
        # Progress bar
        st.progress(risk_percentage / 100)
        
        st.write("")  # spacing
        
        # Back button
        if st.button("⬅ Back to Dashboard", type="secondary"):
            st.session_state.page = "dashboard"
            st.rerun()
        
        # Expandable recommendations section
        with st.expander("📋 View Detailed Recommendations"):
            st.markdown(f"**Category:** {score_data.get('category', 'N/A')}")
            st.divider()
            for rec in score_data.get("recommendations", []):
                st.write(f"• {rec}")


# ============================================================
# SCAN
# ============================================================
def show_scan():
    st.subheader("🌐 Automated Website Scan")

    if st.button("⬅ Back"):
        st.session_state.page = "dashboard"
        st.rerun()

    target = st.text_input("Website URL", key="scan_target")

    if st.button("Run Scan"):
        with st.spinner("Running Nikto scan... This may take 1-2 minutes"):
            try:
                r = requests.post(
                    f"{backend_url}/scan/start",
                    json={
                        "target": normalize_url(target),
                        "user_id": st.session_state.auth["user_id"],
                    },
                    timeout=180,  # 3 minutes to allow scan completion
                )
                data = safe_json(r)
            except requests.exceptions.Timeout:
                st.error("⏱️ Scan timed out after 3 minutes. The target may be slow or unreachable.")
                st.warning("**Tip:** Try a simpler target or check if Nikto is responding")
                return
            except requests.exceptions.ConnectionError:
                st.error("🔌 Connection lost to backend. The server may have restarted during the scan.")
                st.info("**Solutions:**")
                st.write("• Run backend without auto-reload: `python app.py` (instead of Flask debug mode)")
                st.write("• Try a different target URL")
                st.write("• Check backend terminal for errors")
                return
            except Exception as e:
                st.error(f"❌ Scan failed: {str(e)}")
                return

        if not data:
            st.error("Backend error: invalid or empty response")
            return

        if not data.get("ok"):
            st.error(data.get("error", "Scan failed"))
            return


        findings = data.get("findings", [])
        raw_path = data.get("raw_output_path")

        st.success("✅ Scan completed with AI-Enhanced Analysis")
        
        # AI Summary Section
        ml_enhanced_count = sum(1 for f in findings if f.get("ml_enhanced"))
        if ml_enhanced_count > 0:
            st.info(f"🤖 **AI Analysis Active:** {ml_enhanced_count} findings analyzed with Machine Learning")

        tab_overview, tab_alerts, tab_ai_insights, tab_graphs, tab_raw = st.tabs(
            ["📊 Overview", "🚨 Vulnerabilities", "🤖 AI Insights", "📈 Risk Analysis", "🧾 Raw Output"]
        )

        with tab_overview:
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Findings", len(findings))
            col2.metric("High Risk", sum(f["severity"] == "High" for f in findings))
            col3.metric("Medium Risk", sum(f["severity"] == "Medium" for f in findings))
            col4.metric("🤖 AI Analyzed", ml_enhanced_count)
            
            st.divider()
            st.subheader("🎯 Priority Actions")
            high_severity = [f for f in findings if f["severity"] == "High"]
            if high_severity:
                for f in high_severity[:3]:  # Show top 3
                    st.warning(f"⚠️ **{f.get('friendly_title') or f['title'][:80]}**")
            else:
                st.success("✅ No high-severity issues detected!")

        with tab_alerts:
            if not findings:
                st.info("No vulnerabilities found!")
            
            for f in findings:
                # Add ML badge if enhanced
                ml_icon = "🤖 " if f.get("ml_enhanced") else ""
                severity_color = {
                    "High": "🔴",
                    "Medium": "🟡",
                    "Low": "🟢"
                }.get(f["severity"], "⚪")
                
                with st.expander(f"{severity_color} {ml_icon}{f.get('friendly_title') or f['title'][:100]} ({f['severity']} - {f['confidence']} Confidence)"):
                    
                    # Key metrics
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Severity", f['severity'])
                    col2.metric("Confidence", f['confidence'])
                    col3.metric("OWASP", f['owasp'])
                    
                    st.divider()
                    
                    # AI-Enhanced indicator
                    if f.get("ml_enhanced"):
                        st.success("🤖 **AI-Enhanced Confidence Score** - Analyzed using Machine Learning model")
                    
                    # What is this vulnerability?
                    if f.get("meaning"):
                        st.markdown("### 🔍 What is this?")
                        st.info(f.get("meaning"))
                    
                    # Technical details
                    st.markdown("### ⚙️ Technical Finding")
                    st.code(f.get("raw_finding") or f['title'], language="text")
                    
                    # Business Impact
                    st.markdown("### 💼 Business Impact")
                    st.warning(f.get("business_impact", "Potential security risk to your organization"))
                    
                    # Recommendation
                    st.markdown("### ✅ How to Fix")
                    if f.get("fix_recommendation"):
                        st.success(f.get("fix_recommendation"))
                    else:
                        st.write(f.get("recommendation", "Review and apply security best practices"))
                    
                    # Additional OWASP info
                    st.markdown("### 📚 Vulnerability Type Details")
                    st.write(f.get("owasp_description", "Security vulnerability detected"))
        
        with tab_ai_insights:
            st.subheader("🤖 AI-Powered Security Analysis")
            
            # ML Model Info
            st.markdown("""
            **Machine Learning Model Active** ✅
            - **Model Type:** Logistic Regression (scikit-learn 1.8.0)
            - **Features Analyzed:** 12 security indicators per finding
            - **Confidence Scoring:** AI-enhanced prediction based on:
              - Keyword patterns (SQL, XSS, admin, etc.)
              - CVE/OSVDB references
              - Severity indicators
              - Code structure analysis
            """)
            
            st.divider()
            
            # AI Analysis Results
            st.markdown("### 📊 Confidence Distribution")
            if findings:
                confidence_counts = {}
                for f in findings:
                    conf = f.get("confidence", "Unknown")
                    confidence_counts[conf] = confidence_counts.get(conf, 0) + 1
                
                for conf, count in confidence_counts.items():
                    st.metric(f"{conf} Confidence", count)
            
            st.divider()
            
            # Smart Recommendations
            st.markdown("### 💡 AI-Generated Recommendations")
            high_conf_high_sev = [f for f in findings if f.get("severity") == "High" and f.get("confidence") == "High"]
            
            if high_conf_high_sev:
                st.error(f"⚠️ **Critical:** {len(high_conf_high_sev)} high-severity, high-confidence vulnerabilities require immediate attention")
                for idx, f in enumerate(high_conf_high_sev[:3], 1):
                    st.write(f"{idx}. {f.get('friendly_title') or f['title'][:80]}")
            else:
                st.success("✅ No critical high-confidence threats detected")
            
            # ML Insights
            st.markdown("### 🧠 Machine Learning Insights")
            ml_findings = [f for f in findings if f.get("ml_enhanced")]
            if ml_findings:
                st.write(f"- Analyzed **{len(ml_findings)}** findings using trained ML model")
                st.write(f"- Feature extraction: Text analysis, keyword detection, pattern recognition")
                st.write(f"- Model confidence: Based on {len(ml_findings)} security indicators")
            else:
                st.write("ML analysis not available for current findings")

        with tab_graphs:
            if findings:
                df = pd.DataFrame(findings)
                st.bar_chart(df["severity"].value_counts())

        with tab_raw:
            if raw_path:
                st.code(raw_path)
            else:
                st.info("No raw output available.")


# ============================================================
# HISTORY
# ============================================================
def show_history():
    st.title("📊 My Scan History")
    
    if st.button("⬅ Back to Dashboard"):
        st.session_state.page = "dashboard"
        st.rerun()
    
    st.divider()
    
    # Fetch user's scan history
    resp = requests.get(
        f"{backend_url}/user/history",
        params={"user_id": st.session_state.auth["user_id"]}
    )
    
    data = safe_json(resp)
    if not data or not data.get("ok"):
        st.error("Failed to load scan history")
        return
    
    scans = data.get("scans", [])
    
    if not scans:
        st.info("📭 No scan history found. Run your first scan!")
        return
    
    st.success(f"Found {len(scans)} scan(s)")
    
    # Display scans in a table
    for scan in scans:
        scan_id = scan.get("id")
        target = scan.get("target_url", "N/A")
        created = scan.get("created_at", "N/A")
        risk_level = scan.get("risk_level", "Unknown")
        final_score = scan.get("final_score", 0)
        
        # Parse summary JSON
        summary_json = scan.get("summary_json", "{}")
        if isinstance(summary_json, str):
            import json
            summary = json.loads(summary_json)
        else:
            summary = summary_json
        
        total_findings = summary.get("total_findings", 0)
        
        # Color code risk level
        risk_color = {
            "Low": "🟢",
            "Medium": "🟡",
            "High": "🔴",
            "Critical": "⚫"
        }.get(risk_level, "⚪")
        
        with st.expander(f"{risk_color} {target} - {risk_level} ({final_score:.1f}/100) - {created}"):
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Risk Score", f"{final_score:.1f}/100")
            col2.metric("Risk Level", risk_level)
            col3.metric("Total Findings", total_findings)
            col4.metric("Scan ID", scan_id)
            
            st.divider()
            
            # Severity breakdown
            st.markdown("**Vulnerability Breakdown:**")
            by_severity = summary.get("by_severity", {})
            scol1, scol2, scol3 = st.columns(3)
            scol1.metric("🔴 High", by_severity.get("High", 0))
            scol2.metric("🟡 Medium", by_severity.get("Medium", 0))
            scol3.metric("🟢 Low", by_severity.get("Low", 0))
            
            st.divider()
            
            # Multipliers info
            st.markdown("**Business Context Multipliers:**")
            mcol1, mcol2, mcol3 = st.columns(3)
            mcol1.metric("Business Type", f"{scan.get('business_type_multiplier', 1.0)}x")
            mcol2.metric("Data Sensitivity", f"{scan.get('data_sensitivity_multiplier', 1.0)}x")
            mcol3.metric("IT Dependency", f"{scan.get('it_dependency_multiplier', 1.0)}x")
            
            st.divider()
            
            # Download PDF button
            if st.button(f"📄 Download PDF Report", key=f"pdf_{scan_id}"):
                with st.spinner("Generating PDF report..."):
                    try:
                        pdf_resp = requests.get(f"{backend_url}/report/scan/{scan_id}")
                        if pdf_resp.status_code == 200:
                            st.download_button(
                                label="💾 Save PDF",
                                data=pdf_resp.content,
                                file_name=f"scan_report_{scan_id}.pdf",
                                mime="application/pdf",
                                key=f"download_{scan_id}"
                            )
                        else:
                            st.error("Failed to generate PDF report")
                    except Exception as e:
                        st.error(f"Error: {e}")


# ============================================================
# MAIN ROUTER
# ============================================================
if not st.session_state.auth["logged_in"]:
    show_auth_ui()
else:
    show_sidebar()

    if st.session_state.page == "dashboard":
        show_dashboard()
    elif st.session_state.page == "manual":
        show_manual()
    elif st.session_state.page == "scan":
        show_scan()
    elif st.session_state.page == "history":
        show_history()
    elif st.session_state.page == "admin":
        show_admin_dashboard()
