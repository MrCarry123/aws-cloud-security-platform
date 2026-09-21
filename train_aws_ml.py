import json
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib


FEATURES = [
    "hour",
    "is_root",
    "api_calls",
    "new_ip",
    "privilege_change"
]


# Load the synthetic training events we already generated
with open("generated_events.json", "r") as file:
    events = json.load(file)


# Convert JSON into a table
df = pd.DataFrame(events)


# Convert True/False into 1/0 for the ML model
boolean_columns = [
    "is_root",
    "new_ip",
    "privilege_change"
]

for column in boolean_columns:
    df[column] = df[column].astype(int)


# Only train using features we can reproduce from real AWS activity
X = df[FEATURES]


model = IsolationForest(
    n_estimators=100,
    contamination=0.10,
    random_state=42
)


model.fit(X)


joblib.dump(
    model,
    "aws_isolation_forest_model.pkl"
)


print("AWS-compatible Isolation Forest trained successfully")
print("Events used:", len(X))
print("Features used:", FEATURES)