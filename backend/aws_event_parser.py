from datetime import datetime


def parse_aws_event(event):
    detail = event["detail"]

    event_time = datetime.fromisoformat(
        detail["eventTime"].replace("Z", "+00:00")
    )

    identity = detail.get("userIdentity", {})

    return {
        "user": identity.get("arn", "unknown"),
        "action": detail.get("eventName", "unknown"),
        "service": detail.get("eventSource", "unknown"),
        "hour": event_time.hour,
        "is_root": identity.get("type") == "Root",
        "source_ip": detail.get("sourceIPAddress", "unknown"),
        "region": detail.get("awsRegion", "unknown"),
        "read_only": detail.get("readOnly", False),
        "request_parameters": detail.get("requestParameters", {})
    }