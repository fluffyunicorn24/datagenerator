from collections import OrderedDict
import json
import random
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()

# ------------------------
# Global Shared Constants
# ------------------------

TENANT_ID = "d63f3f4b-6e5b-4e10-a8b8-2d7e2a8b5f72"
SOURCE_SYSTEM = "Azure AD"

# Generate a single GUID for ResourceId that will remain constant across records
RESOURCE_ID_GUID = fake.uuid4()

# OperationName, OperationVersion, Category remain as previously defined
OPERATION_NAME = "UserSignIn"
OPERATION_VERSION = "1.0"
CATEGORY = "SigninLogs"

# Instead of separate random lists, define 4 specific combos for (ResultType, ResultSignature, ResultDescription)
RESULT_COMBINATIONS = [
    {
        "ResultType": "1",
        "ResultSignature": "70043",
        "ResultDescription": "Other"
    },
    {
        "ResultType": "4",
        "ResultSignature": "50158",
        "ResultDescription": "External security challenge was not satisfied."
    },
    {
        "ResultType": "19",
        "ResultSignature": "50074",
        "ResultDescription": "Strong Authentication is required."
    },
    {
        "ResultType": "60",
        "ResultSignature": "70044",
        "ResultDescription": "The session has expired or is invalid due to sign-in frequency checks by conditional access."
    }
]

DURATION_MS_OPTIONS = [58, 220, 1660]
RESOURCES = ["WindowsDefenderATP", "Microsoft Graph"]
RESOURCE_GROUP_OPTIONS = ["ResourceGroup1", "SecurityOps"]
RESOURCE_PROVIDER = "Microsoft.Identity"

def get_identity():
    # Either return an empty JSON object or a random GUID
    return "{}" if random.choice([True, False]) else fake.uuid4()

LEVEL = "Information"
LOCATION_OPTIONS = ["United States", "Brazil", "United Kingdom"]
APP_DISPLAY_NAME_OPTIONS = ["Azure AD SSO", "Office 365 Exchange Online"]
AUTHENTICATION_METHODS_USED_OPTIONS = ["MFA", "Password", "Certificate"]
CLIENT_APP_USED_OPTIONS = ["Edge", "Chrome", "PowerShell"]
CONDITIONAL_ACCESS_STATUS_OPTIONS = ["Success", "Failure", "Not Applied"]
IS_INTERACTIVE_OPTIONS = [True, False]

def random_created_datetime():
    return fake.date_time_between(start_date='-30d', end_date='now').isoformat()

# Some placeholder or reused definitions for other fields
DEVICE_DETAIL = '{"DeviceId": "' + fake.uuid4() + '", "DeviceType": "Laptop"}'
IS_RISKY = ""
# ... etc. The rest of the script remains unchanged.

def prompt_for_days():
    valid_options = ['1', '3', '5']
    while True:
        inp = input("Enter the number of days for data replication (1, 3, or 5): ").strip()
        if inp in valid_options:
            return int(inp)
        else:
            print("Invalid input. Please enter 1, 3, or 5.")

def generate_signin_log_event(event_index, start_time, delta):
    event_time = start_time + (event_index * delta)
    
    record = OrderedDict()
    
    # 1. TenantId
    record["TenantId"] = TENANT_ID
    # 2. SourceSystem
    record["SourceSystem"] = SOURCE_SYSTEM
    # 3. TimeGenerated_UTC (current run time)
    record["TimeGenerated_UTC"] = datetime.utcnow().isoformat()
    # 4. ResourceId - using the single global GUID
    record["ResourceId"] = f"/tenants/{RESOURCE_ID_GUID}/providers/Microsoft.aadiam."
    # 5. OperationName
    record["OperationName"] = OPERATION_NAME
    # 6. OperationVersion
    record["OperationVersion"] = OPERATION_VERSION
    # 7. Category
    record["Category"] = CATEGORY

    # 8-10. (ResultType, ResultSignature, ResultDescription) chosen from one of the 4 combos
    chosen_result = random.choice(RESULT_COMBINATIONS)
    record["ResultType"] = chosen_result["ResultType"]
    record["ResultSignature"] = chosen_result["ResultSignature"]
    record["ResultDescription"] = chosen_result["ResultDescription"]

    # 11. DurationMs
    record["DurationMs"] = random.choice(DURATION_MS_OPTIONS)
    
    # The rest of the fields remain as previously defined or updated
    # ...
    # For example:
    record["CorrelationId"] = fake.uuid4()
    record["Resource"] = random.choice(RESOURCES)
    record["ResourceGroup"] = random.choice(RESOURCE_GROUP_OPTIONS)
    record["ResourceProvider"] = RESOURCE_PROVIDER
    record["Identity"] = get_identity()
    record["Level"] = LEVEL
    record["Location"] = random.choice(LOCATION_OPTIONS)
    record["AlternateSignInName"] = fake.email()
    record["AppDisplayName"] = random.choice(APP_DISPLAY_NAME_OPTIONS)
    record["AppId"] = fake.uuid4()
    # ...
    # Continue for all 88 fields as previously set.

    # 88. Type
    record["Type"] = "SigninLog"
    
    return record

def generate_signin_log_events(num_events, start_time, end_time, output_file):
    total_seconds = (end_time - start_time).total_seconds()
    delta = timedelta(seconds=(total_seconds / num_events))
    with open(output_file, 'w', encoding='utf-8') as f:
        for i in range(num_events):
            event = generate_signin_log_event(i, start_time, delta)
            f.write(json.dumps(event) + "\n")

if __name__ == "__main__":
    days = prompt_for_days()
    events_per_day = 1000
    total_events = days * events_per_day

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    output_filename = "signin_logs.json"
    
    generate_signin_log_events(total_events, start_time, end_time, output_filename)
    print(f"Generated {total_events} signin log events for the past {days} day(s) in '{output_filename}'.")
