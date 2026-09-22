import boto3
import json
from backend.aws_event_parser import parse_aws_event
from backend.aws_security_detector import analyze_aws_event

sqs = boto3.client(
    "sqs",
    region_name="us-east-2"
)

QUEUE_URL = "https://sqs.us-east-2.amazonaws.com/787565913179/cloud-security-events"

response = sqs.receive_message(
    QueueUrl=QUEUE_URL,
    MaxNumberOfMessages=1,
    WaitTimeSeconds=10,
    VisibilityTimeout=30
)

messages = response.get("Messages", [])

if len(messages) == 0:
    print("No messages found.")
else:
    message = messages[0]

    event = json.loads(message["Body"])

    clean_event = parse_aws_event(event)
    result = analyze_aws_event(clean_event)

    print("Clean event:")
    print(json.dumps(clean_event, indent=4))

    print("\nSecurity analysis:")
    print(json.dumps(result, indent=4))

    print("Clean security event:")
    print(json.dumps(clean_event, indent=4))