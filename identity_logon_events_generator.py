from collections import OrderedDict
import json
import random
from datetime import datetime, timedelta
from faker import Faker
import uuid

# Initialize Faker for realistic fake data
fake = Faker()

# ------------------------
# Constants & Shared Lists
# ------------------------

TENANT_ID = "d63f3f4b-6e5b-4e10-a8b8-2d7e2a8b5f72"

# Global list of account names
ACCOUNT_NAMES = [
    "jdoe",
    "msmith",
    "ajones",
    "bwilliams",
    "cjohnson",
    "Admin"
]

# Fixed AccountDomain
FIXED_ACCOUNT_DOMAIN = "govtesttenant.net"

# DeviceName options (shared with other scripts)
DEVICE_NAME_OPTIONS = [
    "govms01.govtesttenant.net",
    "govms02.govtesttenant.net",
    "govms03.govtesttenant.net",
    "govms04.govtesttenant.net",
    "govms05.govtesttenant.net",
    "govms06.govtesttenant.net",
    "eidcloudsync01.govtesttenant.net",
    "govavd-0",
    "govavd-1",
    "adcs.govtesttenant.net",
    "entraassessment"
]

# ------------------------
# IdentityLogonEvents-Specific Constants
# ------------------------

ACTION_TYPE_OPTIONS = ["LogonFailed", "LogonSuccess"]
APPLICATION_VALUE = "Microsoft 365"
LOGON_TYPE_OPTIONS = ["OAuth2:Token", "OAuth2:Authorize"]
PROTOCOL_OPTIONS = ["", "OAuth2"]
FAILURE_REASON_VALUE = "General failure"

OS_PLATFORMS = ["Windows", "macOS", "Linux", "Android", "iOS"]
DEVICE_TYPES = ["Desktop", "Laptop", "Mobile", "Tablet", "Server"]

# ------------------------
# Helper Functions
# ------------------------

def random_sid():
    return "S-1-5-21-" + "-".join(str(random.randint(1000000000, 9999999999)) for _ in range(3))

def random_md5():
    return ''.join(random.choices('0123456789abcdef', k=32))

def random_sha1():
    return ''.join(random.choices('0123456789abcdef', k=40))

def random_sha256():
    return ''.join(random.choices('0123456789abcdef', k=64))

def prompt_for_days():
    valid_options = ['1', '3', '5']
    while True:
        inp = input("Enter the number of days for data replication (1, 3, or 5): ").strip()
        if inp in valid_options:
            return int(inp)
        else:
            print("Invalid input. Please enter 1, 3, or 5.")

def get_identity_additional_fields(account_name, account_domain):
    # Build a JSON object with the required structure.
    additional = {
        "TARGET_OBJECT.ENTITY_USER": account_name,
        "TARGET_OBJECT.ALIAS": account_name,
        "TARGET_OBJECT.USER": f"{account_name}@{account_domain}",
        "Pass-through authentication": "false",
        "Request ID": str(uuid.uuid4()),
        "TO.CLOUD_SERVICE": "Graph Files Manager"
    }
    return json.dumps(additional)

# ------------------------
# IdentityLogonEvents Generation
# ------------------------

def generate_identity_logon_event(event_index, start_time, delta):
    # Compute sequential event timestamp for Timestamp_UTC
    event_time = start_time + (event_index * delta)
    
    record = OrderedDict()
    
    # 1. TenantId
    record["TenantId"] = TENANT_ID
    
    # 2. TimeGenerated_UTC (current run time)
    record["TimeGenerated_UTC"] = datetime.utcnow().isoformat()
    
    # 3. Timestamp_UTC (sequential timestamp)
    record["Timestamp_UTC"] = event_time.isoformat()
    
    # 4. ActionType
    action = random.choice(ACTION_TYPE_OPTIONS)
    record["ActionType"] = action
    
    # 5. Application (always "Microsoft 365")
    record["Application"] = APPLICATION_VALUE
    
    # 6. LogonType
    record["LogonType"] = random.choice(LOGON_TYPE_OPTIONS)
    
    # 7. Protocol
    record["Protocol"] = random.choice(PROTOCOL_OPTIONS)
    
    # 8. FailureReason: if ActionType is "LogonFailed", set to FAILURE_REASON_VALUE; otherwise blank.
    if action == "LogonFailed":
        record["FailureReason"] = FAILURE_REASON_VALUE
    else:
        record["FailureReason"] = ""
    
    # 9. AccountName: choose from the global ACCOUNT_NAMES list
    account_name = random.choice(ACCOUNT_NAMES)
    record["AccountName"] = account_name
    
    # 10. AccountDomain (always fixed)
    record["AccountDomain"] = FIXED_ACCOUNT_DOMAIN
    
    # 11. AccountUpn
    record["AccountUpn"] = fake.email()
    
    # 12. AccountSid
    record["AccountSid"] = random_sid()
    
    # 13. AccountObjectId
    record["AccountObjectId"] = fake.uuid4()
    
    # 14. AccountDisplayName: using the same account name (capitalized)
    record["AccountDisplayName"] = account_name.capitalize()
    
    # 15. DeviceName: choose from DEVICE_NAME_OPTIONS
    record["DeviceName"] = random.choice(DEVICE_NAME_OPTIONS)
    
    # 16. DeviceType
    record["DeviceType"] = random.choice(DEVICE_TYPES)
    
    # 17. OSPlatform
    record["OSPlatform"] = random.choice(OS_PLATFORMS)
    
    # 18. IPAddress
    record["IPAddress"] = fake.ipv4()
    
    # 19. Port
    record["Port"] = random.randint(1024, 65535)
    
    # 20. DestinationDeviceName
    record["DestinationDeviceName"] = random.choice(DEVICE_NAME_OPTIONS)
    
    # 21. DestinationIPAddress
    record["DestinationIPAddress"] = fake.ipv4()
    
    # 22. DestinationPort
    record["DestinationPort"] = random.randint(1024, 65535)
    
    # 23. TargetDeviceName
    record["TargetDeviceName"] = random.choice(DEVICE_NAME_OPTIONS)
    
    # 24. TargetAccountDisplayName
    record["TargetAccountDisplayName"] = random.choice(ACCOUNT_NAMES).capitalize()
    
    # 25. Location: now a state abbreviation (use a small list)
    state_abbrevs = ["CA", "TX", "NY", "FL", "IL"]
    record["Location"] = random.choice(state_abbrevs)
    
    # 26. ISP: choose from the provided list
    isp_options = [
        "at&t enterprises llc",
        "total play telecomunicaciones sa de cv",
        "telmex colombia s.a.",
        "comcast",
        "013 netvision",
        "elisa oyj",
        "Microsoft Azure"
    ]
    record["ISP"] = random.choice(isp_options)
    
    # 27. ReportId
    record["ReportId"] = fake.uuid4()
    
    # 28. AdditionalFields: updated to use the helper function and substitute account name and domain.
    record["AdditionalFields"] = get_identity_additional_fields(account_name, FIXED_ACCOUNT_DOMAIN)
    
    # 29. SourceSystem (empty)
    record["SourceSystem"] = ""
    
    # 30. Type
    record["Type"] = "IdentityLogonEvent"
    
    return record

def generate_identity_logon_events(num_events, start_time, end_time, output_file):
    total_seconds = (end_time - start_time).total_seconds()
    delta = timedelta(seconds=(total_seconds / num_events))
    with open(output_file, 'w', encoding='utf-8') as f:
        for i in range(num_events):
            event = generate_identity_logon_event(i, start_time, delta)
            f.write(json.dumps(event) + "\n")

if __name__ == "__main__":
    days = prompt_for_days()
    events_per_day = 1000  # Adjust as needed
    total_events = days * events_per_day
    
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    output_filename = "identity_logon_events.json"
    
    generate_identity_logon_events(total_events, start_time, end_time, output_filename)
    print(f"Generated {total_events} identity logon events for the past {days} day(s) in '{output_filename}'.")
