import json
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib


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


# Load generated events
with open("generated_events.json", "r") as file:
    events = json.load(file)


# Convert JSON data into a DataFrame
df = pd.DataFrame(events)


# Convert True/False into 1/0
boolean_columns = [
    "is_root",
    "s3_public",
    "cloudtrail_disabled",
    "new_ip",
    "privilege_change"
]

for column in boolean_columns:
    df[column] = df[column].astype(int)


# Only give the ML model the features we want it to learn from
X = df[FEATURES]


# Create anomaly detection model
model = IsolationForest(
    n_estimators=100,
    contamination=0.10,
    random_state=42
)


# Train model
model.fit(X)


# Save trained model
joblib.dump(model, "isolation_forest_model.pkl")

print("ML anomaly detector trained successfully")
print("Events used for training:", len(X))