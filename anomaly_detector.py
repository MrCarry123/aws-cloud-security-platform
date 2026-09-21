import joblib
import pandas as pd


FEATURES = [
    "failed_logins",
    "hour",
    "is_root",
    "s3_public",
    "cloudtrail_disabled",
    "api_calls",
    "data_download_mb",
    "new_ip",
    "privilege_change"
]


model = joblib.load("isolation_forest_model.pkl")


def detect_anomaly(event):

    data = {
        "failed_logins": event["failed_logins"],
        "hour": event["hour"],
        "is_root": int(event["is_root"]),
        "s3_public": int(event["s3_public"]),
        "cloudtrail_disabled": int(event["cloudtrail_disabled"]),
        "api_calls": event["api_calls"],
        "data_download_mb": event["data_download_mb"],
        "new_ip": int(event["new_ip"]),
        "privilege_change": int(event["privilege_change"])
    }

    X = pd.DataFrame([data], columns=FEATURES)

    prediction = model.predict(X)[0]
    anomaly_score = model.decision_function(X)[0]

    return {
        "is_anomaly": bool(prediction == -1),
        "anomaly_score": float(anomaly_score)
    }