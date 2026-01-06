# owasp_map.py
# Maps Nikto findings to OWASP Top 10 categories

OWASP_MAP = [
    ("sql", "A03: Injection"),
    ("xss", "A03: Injection"),
    ("directory indexing", "A05: Security Misconfiguration"),
    ("x-frame-options", "A05: Security Misconfiguration"),
    ("x-content-type-options", "A05: Security Misconfiguration"),
    ("http methods", "A05: Security Misconfiguration"),
    ("outdated", "A06: Vulnerable and Outdated Components"),
    ("admin", "A01: Broken Access Control"),
]

def map_owasp(alert_text: str) -> str:
    text = (alert_text or "").lower()
    for keyword, category in OWASP_MAP:
        if keyword in text:
            return category
    return "A05: Security Misconfiguration"
