def combine_risk(rule_result, ml_result):
    final_score = rule_result["risk_score"]

    # If the ML model thinks the behavior is anomalous,
    # add extra risk.
    if ml_result["is_anomaly"]:
        final_score += 25

    if final_score >= 80:
        final_severity = "CRITICAL"
    elif final_score >= 50:
        final_severity = "HIGH"
    elif final_score >= 20:
        final_severity = "MEDIUM"
    else:
        final_severity = "LOW"

    return {
        "final_risk_score": final_score,
        "final_severity": final_severity
    }