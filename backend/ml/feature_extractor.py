# feature_extractor.py
# Extract numerical features from Nikto alert text
# Updated to provide 12 features to match trained model

import re

KEYWORDS = [
    "sql", "xss", "admin", "outdated",
    "directory", "method", "execute",
    "shell", "vulnerable"
]

SEVERITY_KEYWORDS = ["critical", "high", "severe", "dangerous"]
INFO_KEYWORDS = ["info", "informational", "notice"]

def extract_features(alert_text: str):
    """
    Extract 12 features from alert text to match the trained model
    """
    text = (alert_text or "").lower()

    # Original 4 features
    length = len(text)
    keyword_hits = sum(1 for k in KEYWORDS if k in text)
    has_cve = 1 if re.search(r"cve-\d{4}-\d+", text) else 0
    has_osvdb = 1 if "osvdb" in text else 0
    
    # Additional 8 features to reach 12 total
    has_severity_keyword = 1 if any(k in text for k in SEVERITY_KEYWORDS) else 0
    has_info_keyword = 1 if any(k in text for k in INFO_KEYWORDS) else 0
    has_http_code = 1 if re.search(r"\b[45]\d{2}\b", text) else 0  # 4xx or 5xx
    has_version = 1 if re.search(r"\d+\.\d+", text) else 0
    word_count = len(text.split())
    has_path = 1 if "/" in text else 0
    has_header = 1 if "header" in text or "x-" in text else 0
    has_exploit = 1 if "exploit" in text or "attack" in text else 0

    return [
        length, keyword_hits, has_cve, has_osvdb,
        has_severity_keyword, has_info_keyword, has_http_code, has_version,
        word_count, has_path, has_header, has_exploit
    ]
