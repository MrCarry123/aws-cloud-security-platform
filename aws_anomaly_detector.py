import joblib
import pandas as pd


FEATURES = [
    "hour",
    "is_root",
    "api_calls",
    "new_ip",
    "privilege_change"
]


# Load the model we trained earlier
model = joblib.load("aws_isolation_forest_model.pkl")


def detect_aws_anomaly(features):

    data = {
        "hour": features["hour"],
        "is_root": int(features["is_root"]),
        "api_calls": features["api_calls"],
        "new_ip": int(features["new_ip"]),
        "privilege_change": int(features["privilege_change"])
    }

    # Isolation Forest expects a table
    X = pd.DataFrame([data], columns=FEATURES)

    # 1 = normal
    # -1 = anomaly
    prediction = model.predict(X)[0]

    # Usually:
    # positive = more normal
    # negative = more anomalous
    anomaly_score = model.decision_function(X)[0]

    return {
        "is_anomaly": bool(prediction == -1),
        "anomaly_score": float(anomaly_score)
    }