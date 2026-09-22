def analyze_aws_event(event):
    risk_score = 0
    reasons = []

    # Root account usage
    if event["is_root"]:
        risk_score += 40
        reasons.append("Root account used")

    # Important IAM privilege-changing actions
    privilege_actions = [
        "AttachRolePolicy",
        "PutRolePolicy",
        "CreateAccessKey",
        "UpdateAssumeRolePolicy"
    ]

    if event["action"] in privilege_actions:
        risk_score += 60
        reasons.append("IAM privilege change detected")

    # CloudTrail tampering
    if event["action"] in ["StopLogging", "DeleteTrail"]:
        risk_score += 90
        reasons.append("CloudTrail logging modified or disabled")

    # S3 policy change
    if event["action"] == "PutBucketPolicy":
        risk_score += 50
        reasons.append("S3 bucket policy changed")

    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 50:
        severity = "HIGH"
    elif risk_score >= 20:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "reasons": reasons
    }