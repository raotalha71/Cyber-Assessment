# scan_scoring.py
# Enhanced with ML-based predictions and SME business multipliers

# SME Business Multipliers
BUSINESS_TYPE_MULTIPLIERS = {
    "Retail": 1.0,
    "Finance": 1.3,
    "Healthcare": 1.4,
    "Education": 1.1,
    "Other": 1.0,
}

DATA_SENSITIVITY_MULTIPLIERS = {
    "Low": 1.0,
    "Medium": 1.2,
    "High": 1.5,
}

IT_DEPENDENCY_MULTIPLIERS = {
    "Low": 1.0,
    "Medium": 1.1,
    "High": 1.3,
}

def calculate_severity(alert_text: str) -> str:
    """Rule-based severity calculation"""
    t = (alert_text or "").lower()
    if any(x in t for x in ["sql", "xss", "rce", "execute", "shell", "injection", "remote"]):
        return "High"
    if any(x in t for x in ["outdated", "admin", "directory indexing", "methods", "disclosure"]):
        return "Medium"
    return "Low"


def calculate_confidence(alert_text: str, use_ml: bool = True) -> str:
    """
    Hybrid confidence calculation: ML + Rule-based
    
    Args:
        alert_text: The vulnerability finding text
        use_ml: Whether to use ML model (falls back to rules if model fails)
    
    Returns:
        Confidence level: Low, Medium, or High
    """
    # Try ML prediction first
    if use_ml:
        try:
            from ml.predictor import predict_confidence
            ml_confidence = predict_confidence(alert_text)
            return ml_confidence
        except Exception as e:
            print(f"[WARN] ML prediction failed, using rule-based: {e}")
    
    # Fallback to rule-based
    t = (alert_text or "").lower()
    if any(x in t for x in ["cve", "osvdb", "confirmed", "found", "exploit"]):
        return "High"
    if any(x in t for x in ["may", "might", "possible", "appears", "likely"]):
        return "Medium"
    return "High"  # Default to High for Nikto findings


def calculate_scan_score(findings: list, sme_profile: dict = None) -> dict:
    """
    Calculate comprehensive scan score with SME business multipliers
    
    Args:
        findings: List of vulnerability findings with severity and confidence
        sme_profile: SME business profile with business_type, data_sensitivity, it_dependency
    
    Returns:
        dict with base_score, final_score (0-100), risk_level, multipliers
    """
    if not findings:
        return {
            "base_score": 0,
            "final_score": 0,
            "risk_level": "Low",
            "business_type_multiplier": 1.0,
            "data_sensitivity_multiplier": 1.0,
            "it_dependency_multiplier": 1.0,
        }
    
    # Calculate base score from findings
    severity_weights = {"High": 10, "Medium": 5, "Low": 2}
    confidence_weights = {"High": 1.0, "Medium": 0.7, "Low": 0.4}
    
    total_weighted_score = 0
    for f in findings:
        severity_score = severity_weights.get(f.get("severity", "Low"), 2)
        confidence_factor = confidence_weights.get(f.get("confidence", "Medium"), 0.7)
        total_weighted_score += severity_score * confidence_factor
    
    # Normalize base score to 0-100 range
    # Assume max realistic score is 50 findings * 10 (High) * 1.0 (High confidence) = 500
    max_possible_score = 500
    base_score = min(100, (total_weighted_score / max_possible_score) * 100)
    
    # Apply SME business multipliers if profile provided
    business_type_mult = 1.0
    data_sensitivity_mult = 1.0
    it_dependency_mult = 1.0
    
    if sme_profile:
        business_type_mult = BUSINESS_TYPE_MULTIPLIERS.get(
            sme_profile.get("business_type", "Other"), 1.0
        )
        data_sensitivity_mult = DATA_SENSITIVITY_MULTIPLIERS.get(
            sme_profile.get("data_sensitivity", "Low"), 1.0
        )
        it_dependency_mult = IT_DEPENDENCY_MULTIPLIERS.get(
            sme_profile.get("it_dependency", "Low"), 1.0
        )
    
    # Calculate final score with multipliers
    final_score = base_score * business_type_mult * data_sensitivity_mult * it_dependency_mult
    
    # Cap at 100
    final_score = min(100, final_score)
    
    # Determine risk level based on final score
    if final_score >= 75:
        risk_level = "Critical"
    elif final_score >= 50:
        risk_level = "High"
    elif final_score >= 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    return {
        "base_score": round(base_score, 2),
        "final_score": round(final_score, 2),
        "risk_level": risk_level,
        "business_type_multiplier": business_type_mult,
        "data_sensitivity_multiplier": data_sensitivity_mult,
        "it_dependency_multiplier": it_dependency_mult,
    }
