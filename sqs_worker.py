import boto3
import json

from sqlalchemy import text

from database import SessionLocal
from aws_event_parser import parse_aws_event
from aws_security_detector import analyze_aws_event
from aws_feature_extractor import extract_ml_features
from aws_anomaly_detector import detect_aws_anomaly
from risk_combiner import combine_risk


# Connect to SQS
sqs = boto3.client(
    "sqs",
    region_name="us-east-2"
)

QUEUE_URL = "https://sqs.us-east-2.amazonaws.com/787565913179/cloud-security-events"


# Ask SQS for one message
response = sqs.receive_message(
    QueueUrl=QUEUE_URL,
    MaxNumberOfMessages=1,
    WaitTimeSeconds=10,
    VisibilityTimeout=30
)

messages = response.get("Messages", [])


# Nothing currently waiting in SQS
if len(messages) == 0:
    print("No messages found.")

else:
    message = messages[0]

    # -----------------------------------
    # 1. Get the raw AWS CloudTrail event
    # -----------------------------------

    raw_event = json.loads(message["Body"])


    # -----------------------------------
    # 2. Convert giant AWS event
    #    into our clean event format
    # -----------------------------------

    clean_event = parse_aws_event(raw_event)


    # Open PostgreSQL connection
    db = SessionLocal()

    try:

        # -----------------------------------
        # 3. Create ML features
        #
        # Uses:
        # - current AWS event
        # - previous PostgreSQL history
        # -----------------------------------

        ml_features = extract_ml_features(
            clean_event,
            db
        )


        # -----------------------------------
        # 4. Run Isolation Forest
        # -----------------------------------

        ml_result = detect_aws_anomaly(
            ml_features
        )


        # -----------------------------------
        # 5. Run rule-based security detector
        # -----------------------------------

        rule_result = analyze_aws_event(
            clean_event
        )
        final_result = combine_risk(
        rule_result,
        ml_result
)
        


        # -----------------------------------
        # 6. Print everything so we can see
        #    what the system detected
        # -----------------------------------

        print("\nEvent:")
        print(
            json.dumps(
                clean_event,
                indent=4
            )
        )


        print("\nML Features:")
        print(
            json.dumps(
                ml_features,
                indent=4
            )
        )


        print("\nML Analysis:")
        print(
            json.dumps(
                ml_result,
                indent=4
            )
        )


        print("\nRule Analysis:")
        print(
            json.dumps(
                rule_result,
                indent=4
            )
        )
        print("\nFinal Analysis:")
        print(
            json.dumps(
                final_result,
                indent=4
            )
        )


        # -----------------------------------
        # 7. Save result into PostgreSQL
        # -----------------------------------

        query = text("""
        INSERT INTO security_events
        (
            username,
            action,
            risk_score,
            severity,
            reasons,
            source_ip,
            is_anomaly,
            anomaly_score,
            final_risk_score,
            final_severity
        )
        VALUES
        (
            :username,
            :action,
            :risk_score,
            :severity,
            :reasons,
            :source_ip,
            :is_anomaly,
            :anomaly_score,
            :final_risk_score,
            :final_severity
    )
""")


        db.execute(
        query,
        {
            "username": clean_event["user"],
            "action": clean_event["action"],
            "risk_score": rule_result["risk_score"],
            "severity": rule_result["severity"],
            "reasons": ", ".join(rule_result["reasons"]),
            "source_ip": clean_event["source_ip"],
            "is_anomaly": ml_result["is_anomaly"],
            "anomaly_score": ml_result["anomaly_score"],
            "final_risk_score": final_result["final_risk_score"],
            "final_severity": final_result["final_severity"]
    }
)


        # Permanently save database changes
        db.commit()


        # -----------------------------------
        # 8. Delete event from SQS
        #
        # ONLY after PostgreSQL successfully
        # saved the event
        # -----------------------------------

        sqs.delete_message(
            QueueUrl=QUEUE_URL,
            ReceiptHandle=message["ReceiptHandle"]
        )


        print(
            "\nSaved to PostgreSQL "
            "and removed from SQS."
        )


    finally:

        # Close database connection
        db.close()