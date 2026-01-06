# vuln_explain.py
# Maps Nikto alert keywords → SME-friendly explanations.

VULN_MAP = {
    "directory indexing": {
        "title": "Directory Indexing Exposed",
        "meaning": "Your server is allowing the public to view all files inside a folder.",
        "business_impact": "Attackers can browse sensitive files and find weaknesses.",
        "recommendation": "Disable directory listing in Apache/Nginx (e.g., 'Options -Indexes')."
    },

    "x-frame-options": {
        "title": "Missing Clickjacking Protection",
        "meaning": "Your website can be embedded inside another malicious website.",
        "business_impact": "Users can be tricked into clicking harmful buttons.",
        "recommendation": "Add security header: 'X-Frame-Options: DENY'."
    },

    "x-xss-protection": {
        "title": "Missing XSS Protection Header",
        "meaning": "Your site does not block reflected cross-site scripting attempts.",
        "business_impact": "Hackers can inject malicious JavaScript into your pages.",
        "recommendation": "Enable security header: 'X-XSS-Protection: 1; mode=block'."
    },

    "outdated": {
        "title": "Outdated Server Software",
        "meaning": "Your website server is running an old version.",
        "business_impact": "Old versions have known vulnerabilities attackers can exploit.",
        "recommendation": "Update your server software to the latest stable version."
    },

    "apache": {
        "title": "Apache Configuration Issue",
        "meaning": "There may be misconfigurations in the Apache web server.",
        "business_impact": "Hackers can exploit weak configurations to attack your site.",
        "recommendation": "Review Apache settings and apply recommended security hardening."
    },

    "http methods": {
        "title": "Insecure HTTP Methods Enabled",
        "meaning": "Your website allows dangerous HTTP methods such as PUT or DELETE.",
        "business_impact": "Hackers may upload malicious files or delete data.",
        "recommendation": "Restrict allowed HTTP methods to: GET, POST, HEAD."
    },

    "server leaks": {
        "title": "Server Information Disclosure",
        "meaning": "Your server reveals software details that should be hidden.",
        "business_impact": "Attackers may use this information to target known weaknesses.",
        "recommendation": "Disable server signature and modify server tokens."
    },
}


def explain_alert(alert_name: str):
    """
    Takes Nikto alert text and returns SME-friendly explanation if keyword matches.
    """
    name = alert_name.lower()

    for keyword, info in VULN_MAP.items():
        if keyword in name:
            return info

    return None  # If no match found


OWASP_TOP_10_EXPLANATIONS = {
    "A01: Broken Access Control": {
        "description": (
            "Access control mechanisms are not properly enforced, allowing users "
            "to perform actions or access data beyond their intended permissions."
        ),
        "business_impact": (
            "Attackers may gain unauthorized access to sensitive data, "
            "modify records, or take administrative control of the system."
        ),
        "example": (
            "A normal user accessing admin-only pages or downloading other users’ data."
        ),
        "recommendation": (
            "Implement proper role-based access control (RBAC), enforce authorization "
            "checks on the server side, and ensure users can only access resources "
            "they are permitted to use."
        ),
    },

    "A02: Cryptographic Failures": {
        "description": (
            "Sensitive data is not adequately protected using encryption, or "
            "weak cryptographic algorithms are used."
        ),
        "business_impact": (
            "Confidential information such as passwords, personal data, or payment "
            "details may be exposed to attackers."
        ),
        "example": (
            "Passwords stored in plain text or transmitted over HTTP instead of HTTPS."
        ),
        "recommendation": (
            "Use strong encryption algorithms, enforce HTTPS, securely store passwords "
            "using hashing (e.g., bcrypt), and protect sensitive data at rest and in transit."
        ),
    },

    "A03: Injection": {
        "description": (
            "Untrusted user input is sent to an interpreter as part of a command or query, "
            "allowing attackers to inject malicious code."
        ),
        "business_impact": (
            "Attackers may read, modify, or delete database records, execute system commands, "
            "or fully compromise the application."
        ),
        "example": (
            "SQL Injection, Command Injection, Cross-Site Scripting (XSS)."
        ),
        "recommendation": (
            "Validate and sanitize all user inputs, use parameterized queries, "
            "and apply input validation frameworks to prevent injection attacks."
        ),
    },

    "A04: Insecure Design": {
        "description": (
            "Security controls are missing or insufficient due to poor application design."
        ),
        "business_impact": (
            "Even correctly implemented code may still be vulnerable if security "
            "was not considered during the design phase."
        ),
        "example": (
            "No rate-limiting on login attempts, allowing brute-force attacks."
        ),
        "recommendation": (
            "Adopt secure design principles, perform threat modeling early, "
            "and ensure security requirements are included during system design."
        ),
    },

    "A05: Security Misconfiguration": {
        "description": (
            "Security settings are missing, improperly configured, or left at default values."
        ),
        "business_impact": (
            "Attackers may exploit misconfigured services, default accounts, or missing "
            "security headers."
        ),
        "example": (
            "Missing X-Frame-Options or Content-Security-Policy headers."
        ),
        "recommendation": (
            "Harden system configurations, remove unused services, apply secure defaults, "
            "and regularly review configuration settings."
        ),
    },

    "A06: Vulnerable and Outdated Components": {
        "description": (
            "The application uses components with known security vulnerabilities."
        ),
        "business_impact": (
            "Publicly known vulnerabilities can be easily exploited by attackers."
        ),
        "example": (
            "Outdated web servers, frameworks, or third-party libraries."
        ),
        "recommendation": (
            "Maintain an inventory of components, apply security patches promptly, "
            "and remove unsupported or outdated dependencies."
        ),
    },

    "A07: Identification and Authentication Failures": {
        "description": (
            "Authentication mechanisms are improperly implemented or missing."
        ),
        "business_impact": (
            "Attackers may compromise user accounts or impersonate legitimate users."
        ),
        "example": (
            "Weak passwords, missing MFA, or predictable session tokens."
        ),
        "recommendation": (
            "Enforce strong passwords, implement multi-factor authentication (MFA), "
            "and securely manage session handling."
        ),
    },

    "A08: Software and Data Integrity Failures": {
        "description": (
            "The integrity of software updates or critical data is not verified."
        ),
        "business_impact": (
            "Attackers may introduce malicious updates or tamper with application data."
        ),
        "example": (
            "Unverified software updates or unsigned third-party plugins."
        ),
        "recommendation": (
            "Use digital signatures, verify integrity of updates, and restrict "
            "trusted sources for software components."
        ),
    },

    "A09: Security Logging and Monitoring Failures": {
        "description": (
            "Insufficient logging, monitoring, or alerting of security-related events."
        ),
        "business_impact": (
            "Security incidents may remain undetected, increasing damage and recovery time."
        ),
        "example": (
            "No alerts for repeated failed login attempts."
        ),
        "recommendation": (
            "Implement comprehensive logging, real-time monitoring, and alerting "
            "for suspicious activities."
        ),
    },

    "A10: Server-Side Request Forgery (SSRF)": {
        "description": (
            "The server fetches remote resources without validating user-supplied URLs."
        ),
        "business_impact": (
            "Attackers may access internal systems or sensitive services."
        ),
        "example": (
            "User-controlled URLs accessing internal network resources."
        ),
        "recommendation": (
            "Validate and restrict outbound requests, block internal IP ranges, "
            "and enforce allowlists for external connections."
        ),
    },
}


def explain_finding(finding):
    owasp = finding.get("owasp", "Unknown")

    info = OWASP_TOP_10_EXPLANATIONS.get(
        owasp,
        {
            "description": "This vulnerability may expose the system to security risks.",
            "business_impact": "Potential impact depends on how the issue is exploited.",
            "example": "General web application vulnerability.",
            "recommendation": "Review security best practices and apply appropriate fixes.",
        }
    )

    return {
        "owasp_description": info["description"],
        "business_impact": info["business_impact"],
        "example": info["example"],
        "recommendation": info["recommendation"],

        "confidence_explanation": (
            "Confidence represents how certain the system is about this finding. "
            "Nikto findings usually have high confidence because they are derived "
            "from direct responses from the target application."
        ),

        "ml_reasoning": (
            "Machine learning assists by analyzing vulnerability patterns, keywords, "
            "and historical exploit trends to refine confidence estimation and prioritization."
        ),
    }
