from manual.manual_questions import MANUAL_QUESTIONS

def calculate_manual_risk(answers: dict):
    total_score = 0.0
    max_score = 0.0

    for q in MANUAL_QUESTIONS:
        weight = q["weight"]
        max_score += (3 * 3) * weight

        answer = answers.get(q["id"])
        if not answer:
            continue

        choice = q["choices"].get(answer)
        if not choice:
            continue

        risk = choice["likelihood"] * choice["impact"] * weight
        total_score += risk

    normalized = round((total_score / max_score) * 100, 2) if max_score else 0

    if normalized >= 80:
        risk_level = "Critical"
        category = "High Risk"
        recommendations = [
            "Immediate action required: Your organization has critical security gaps.",
            "Implement strong password policies and multi-factor authentication.",
            "Establish regular backup procedures for all critical data.",
            "Update all software and systems to the latest versions.",
            "Consider hiring a cybersecurity consultant for a comprehensive review."
        ]
    elif normalized >= 60:
        risk_level = "High"
        category = "At Risk"
        recommendations = [
            "Several security improvements needed to reduce risk.",
            "Enable multi-factor authentication for all critical systems.",
            "Implement automated backup solutions.",
            "Create an incident response plan.",
            "Conduct security awareness training for all staff."
        ]
    elif normalized >= 40:
        risk_level = "Medium"
        category = "Needs Attention"
        recommendations = [
            "Your security posture is acceptable but has room for improvement.",
            "Review and strengthen access controls.",
            "Test backup and recovery procedures regularly.",
            "Maintain a regular patching schedule.",
            "Document security policies and procedures."
        ]
    else:
        risk_level = "Low"
        category = "Good Security Posture"
        recommendations = [
            "Continue maintaining your current security practices.",
            "Regularly review and update security policies.",
            "Stay informed about emerging threats.",
            "Conduct periodic security assessments.",
            "Keep all staff trained on security best practices."
        ]

    return {
        "score": normalized,
        "risk_level": risk_level,
        "category": category,
        "recommendations": recommendations,
        "normalized": normalized,
        "label": risk_level,
        "raw_score": round(total_score, 2),
    }
