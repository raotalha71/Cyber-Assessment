# manual_questions.py
# SME-friendly manual cybersecurity questionnaire (Phase 2)

MANUAL_QUESTIONS = [
    {
        "id": "asset_inventory",
        "text": "Does your organization keep a list of all IT assets (e.g. laptops, servers, systems)?",
        "help": "Knowing what systems you own helps prevent unmanaged security risks.",
        "choices": {
            "Yes": {"likelihood": 1, "impact": 1},
            "Partially": {"likelihood": 2, "impact": 2},
            "No": {"likelihood": 3, "impact": 3},
            "N/A": {"likelihood": 2, "impact": 2},
        },
        "weight": 1.0,
    },
    {
        "id": "access_control",
        "text": "Are strong passwords or multi-factor authentication (MFA) used?",
        "help": "Weak access control is a common cause of cyber incidents.",
        "choices": {
            "Yes": {"likelihood": 1, "impact": 2},
            "Partially": {"likelihood": 2, "impact": 3},
            "No": {"likelihood": 3, "impact": 3},
            "N/A": {"likelihood": 2, "impact": 2},
        },
        "weight": 1.2,
    },
    {
        "id": "data_backup",
        "text": "Are important business data backed up regularly?",
        "help": "Backups help recover data after ransomware or accidental loss.",
        "choices": {
            "Yes": {"likelihood": 1, "impact": 2},
            "Partially": {"likelihood": 2, "impact": 3},
            "No": {"likelihood": 3, "impact": 3},
            "N/A": {"likelihood": 2, "impact": 2},
        },
        "weight": 1.3,
    },
    {
        "id": "software_updates",
        "text": "Are operating systems and software updated regularly?",
        "help": "Outdated software often contains known vulnerabilities.",
        "choices": {
            "Yes": {"likelihood": 1, "impact": 2},
            "Partially": {"likelihood": 2, "impact": 3},
            "No": {"likelihood": 3, "impact": 3},
            "N/A": {"likelihood": 2, "impact": 2},
        },
        "weight": 1.1,
    },
    {
        "id": "incident_awareness",
        "text": "Do employees know how to report suspicious emails or incidents?",
        "help": "Many cyber attacks start with phishing emails.",
        "choices": {
            "Yes": {"likelihood": 1, "impact": 1},
            "Partially": {"likelihood": 2, "impact": 2},
            "No": {"likelihood": 3, "impact": 3},
            "N/A": {"likelihood": 2, "impact": 2},
        },
        "weight": 1.0,
    },
]
