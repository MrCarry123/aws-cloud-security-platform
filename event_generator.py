import random
import json


USERS = [
    "alice",
    "bob",
    "charlie",
    "david",
    "emma",
    "admin"
]

NORMAL_ACTIONS = [
    "login",
    "upload_file",
    "download_file",
    "view_bucket",
    "list_files"
]


def create_normal_event():
    return {
        "user": random.choice(USERS),
        "action": random.choice(NORMAL_ACTIONS),
        "failed_logins": random.randint(0, 3),
        "hour": random.randint(6, 23),
        "is_root": False,
        "s3_public": False,
        "cloudtrail_disabled": False,

        "region": random.choice([
            "us-west-2",
            "us-east-1"
        ]),

        "api_calls": random.randint(1, 20),
        "data_download_mb": random.randint(0, 100),
        "new_ip": False,
        "privilege_change": False
    }


def create_attack_event():
    event = create_normal_event()

    attack_type = random.choice([
    "brute_force",
    "unusual_hour",
    "root_access",
    "public_s3",
    "disable_cloudtrail",
    "api_spike",
    "large_download",
    "new_ip",
    "privilege_escalation",
    "multiple_threats"
])

    if attack_type == "brute_force":
        event["action"] = "login"
        event["failed_logins"] = random.randint(11, 30)

    elif attack_type == "unusual_hour":
        event["hour"] = random.randint(0, 5)

    elif attack_type == "root_access":
        event["user"] = "admin"
        event["is_root"] = True

    elif attack_type == "public_s3":
        event["action"] = "make_bucket_public"
        event["s3_public"] = True

    elif attack_type == "disable_cloudtrail":
        event["action"] = "disable_logging"
        event["cloudtrail_disabled"] = True

    elif attack_type == "multiple_threats":
        event["user"] = "admin"
        event["action"] = "login"
        event["failed_logins"] = random.randint(11, 30)
        event["hour"] = random.randint(0, 5)
        event["is_root"] = True

    elif attack_type == "api_spike":
        event["api_calls"] = random.randint(100, 500)

    elif attack_type == "large_download":
        event["data_download_mb"] = random.randint(1000, 10000)

    elif attack_type == "new_ip":
        event["new_ip"] = True
        event["region"] = random.choice([
            "eu-central-1",
            "ap-southeast-1"
    ])

    elif attack_type == "privilege_escalation":
        event["privilege_change"] = True
        event["action"] = "modify_permissions"  

    return event


def generate_events(number_of_events):
    events = []

    for _ in range(number_of_events):

        # 90% normal, 10% suspicious
        if random.random() < 0.90:
            event = create_normal_event()
        else:
            event = create_attack_event()

        events.append(event)

    return events


events = generate_events(50000)

with open("generated_events.json", "w") as file:
    json.dump(events, file, indent=4)

print(f"Generated {len(events)} events")