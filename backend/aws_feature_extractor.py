from sqlalchemy import text


PRIVILEGE_ACTIONS = [
    "AttachRolePolicy",
    "PutRolePolicy",
    "CreateAccessKey",
    "UpdateAssumeRolePolicy"
]


def extract_ml_features(event, db):

    # --------------------------------
    # 1. Count recent API calls
    # --------------------------------

    query = text("""
        SELECT COUNT(*)
        FROM security_events
        WHERE username = :username
        AND created_at >= NOW() - INTERVAL '5 minutes'
    """)

    api_calls = db.execute(
        query,
        {
            "username": event["user"]
        }
    ).scalar()

    # Include the event we are currently processing
    api_calls += 1


    # --------------------------------
    # 2. Check whether IP is new
    # --------------------------------

    query = text("""
        SELECT COUNT(*)
        FROM security_events
        WHERE username = :username
        AND source_ip = :source_ip
    """)

    previous_ip_count = db.execute(
        query,
        {
            "username": event["user"],
            "source_ip": event["source_ip"]
        }
    ).scalar()

    new_ip = previous_ip_count == 0


    # --------------------------------
    # 3. Check for privilege change
    # --------------------------------

    privilege_change = event["action"] in PRIVILEGE_ACTIONS


    # --------------------------------
    # 4. Build ML feature dictionary
    # --------------------------------

    return {
        "hour": event["hour"],
        "is_root": event["is_root"],
        "api_calls": api_calls,
        "new_ip": new_ip,
        "privilege_change": privilege_change
    }