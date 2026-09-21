import json
from collections import Counter
from security_detector import analyze_event


with open("generated_events.json", "r") as file:
    events = json.load(file)


results = []

for event in events:
    result = analyze_event(event)
    results.append(result)


with open("analyzed_events.json", "w") as file:
    json.dump(results, file, indent=4)


severity_counts = Counter(
    result["severity"] for result in results
)


print("Total events:", len(results))
print("LOW:", severity_counts["LOW"])
print("MEDIUM:", severity_counts["MEDIUM"])
print("HIGH:", severity_counts["HIGH"])
print("CRITICAL:", severity_counts["CRITICAL"])
