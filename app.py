from fastapi import FastAPI
from pydantic import BaseModel
from security_detector import analyze_event
from anomaly_detector import detect_anomaly
from database import SessionLocal
from sqlalchemy import text
from risk_combiner import combine_risk


app = FastAPI()


class SecurityEvent(BaseModel):
    user: str
    action: str
    failed_logins: int
    hour: int
    is_root: bool
    s3_public: bool
    cloudtrail_disabled: bool

    api_calls: int
    data_download_mb: float
    new_ip: bool
    privilege_change: bool


@app.get("/")
def home():
    return {"message": "Cloud Security API is running"}


@app.post("/analyze")
def analyze(event: SecurityEvent):

    # Convert incoming Pydantic object into a dictionary
    event_data = event.model_dump()

    # Run rule-based detection
    rule_result = analyze_event(event_data)

    # Run ML anomaly detection
    ml_result = detect_anomaly(event_data)
    final_result = combine_risk(rule_result, ml_result)

    # Open database connection
    db = SessionLocal()

    try:
        db.execute(
    text("""
        INSERT INTO security_events
        (
            username,
            action,
            risk_score,
            severity,
            reasons,
            is_anomaly,
            anomaly_score,
            final_risk_score,
            final_severity
        )
        VALUES (
            :username,
            :action,
            :risk_score,
            :severity,
            :reasons,
            :is_anomaly,
            :anomaly_score,
            :final_risk_score,
            :final_severity
        )
    """),
    {
        "username": rule_result["user"],
        "action": rule_result["action"],
        "risk_score": rule_result["risk_score"],
        "severity": rule_result["severity"],
        "reasons": ", ".join(rule_result["reasons"]),
        "is_anomaly": ml_result["is_anomaly"],
        "anomaly_score": ml_result["anomaly_score"],
        "final_risk_score": final_result["final_risk_score"],
        "final_severity": final_result["final_severity"]
    }
)

        db.commit()

    finally:
        db.close()

    # Return both detection results
    return {
        "rule_analysis": rule_result,
        "ml_analysis": ml_result,
        "final_analysis": final_result
}


@app.get("/alerts")
def get_alerts():

    db = SessionLocal()

    try:
        result = db.execute(
            text("""
                SELECT
                    username,
                    action,
                    risk_score,
                    severity,
                    reasons,
                    is_anomaly,
                    anomaly_score,
                    final_risk_score,
                    final_severity,
                    created_at
                FROM security_events
                ORDER BY created_at DESC
            """)
        )

        alerts = result.mappings().all()

        return [dict(alert) for alert in alerts]

    finally:
        db.close()


@app.get("/stats")
def get_stats():

    db = SessionLocal()

    try:
        result = db.execute(
            text("""
                SELECT
                    COUNT(*) AS total_events,
                    COUNT(*) FILTER (
                        WHERE severity = 'CRITICAL'
                    ) AS critical_alerts,
                    COUNT(*) FILTER (
                        WHERE severity = 'HIGH'
                    ) AS high_alerts,
                    COUNT(*) FILTER (
                        WHERE severity = 'MEDIUM'
                    ) AS medium_alerts,
                    COUNT(*) FILTER (
                        WHERE severity = 'LOW'
                    ) AS low_alerts,
                    AVG(risk_score) AS average_risk_score
                FROM security_events
            """)
        )

        stats = result.mappings().one()

        return dict(stats)

    finally:
        db.close()