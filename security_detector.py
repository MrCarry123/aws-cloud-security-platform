import json


def analyze_event(event):
    risk_score = 0
    reasons = []

    if event["failed_logins"] > 10:
        risk_score += 50
        reasons.append("Too many failed login attempts")

    if event["hour"] < 6:
        risk_score += 30
        reasons.append("Activity occurred at an unusual hour")

    if event["is_root"]:
        risk_score += 40
        reasons.append("Root account used")

    if event["s3_public"]:
        risk_score += 70
        reasons.append("S3 bucket made public")

    if event["cloudtrail_disabled"]:
        risk_score += 90
        reasons.append("CloudTrail logging disabled")

    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 50:
        severity = "HIGH"
    elif risk_score >= 20:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "user": event["user"],
        "action": event["action"],
        "risk_score": risk_score,
        "severity": severity,
        "reasons": reasons
    }


if __name__ == "__main__": #Only runs if I run it locally
    with open("events.json", "r") as file:
        events = json.load(file)

    results = []

    for event in events:
        result = analyze_event(event)
        results.append(result)

    with open("results.json", "w") as file:
        json.dump(results, file, indent=4)