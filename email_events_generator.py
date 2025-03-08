from collections import OrderedDict
import json
import random
from datetime import datetime, timedelta
from faker import Faker

# Initialize Faker
fake = Faker()

# ------------------------
# Constants & Shared Lists
# ------------------------

TENANT_ID = "d63f3f4b-6e5b-4e10-a8b8-2d7e2a8b5f72"

# These lists ensure consistency with other Device* events
ACCOUNT_DOMAINS = ["nt authority", "azuread", "govtenant", "govavd-1", ""]
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
NT_AUTHORITY_DEVICEIDS = [
    "656643b4100353b62fbc2ad5748081dba6ee41b8",
    "8a243ab5100a3b62fbc2ad5748081dba6ee42b9c",
    "b4e541c7201453b62fbc2ad5748081dba6ee43c1",
    "d3f842d8302453b62fbc2ad5748081dba6ee44d2",
    "f1a953e9403453b62fbc2ad5748081dba6ee45e3",
    "c2b064fa504553b62fbc2ad5748081dba6ee46f4"
]

# ------------------------
# EmailEvent-Specific Constants
# ------------------------

# Predefined JSON objects for AuthenticationDetails
AUTH_DETAILS_OPTIONS = [
    {"DKIM": "none", "DMARC": "none"},
    {"DKIM": "pass", "DMARC": "none"},
    {"DKIM": "none", "DMARC": "pass"},
    {"DKIM": "pass", "DMARC": "pass"}
]

# Predefined values (or None) for AdditionalFields
ADDITIONAL_FIELDS_OPTIONS = [
    {"customField": "value"},
    {"userAgent": "Mozilla/5.0"},
    {"messageType": "transactional"},
    None
]

# EmailAction can be one of these or "None"
EMAIL_ACTION_OPTIONS = ["Blocked", "Delivered", "Quarantined", "None"]

CONNECTORS = ["Exchange Online", "Office365", "SMTP", "IMAP"]
DETECTION_METHODS = ["Signature", "Heuristic", "MachineLearning", "Sandbox"]
DELIVERY_ACTIONS = ["Delivered", "Blocked", "Quarantined", "Deferred"]
DELIVERY_LOCATIONS = ["Inbox", "Junk", "Spam", "Quarantine"]
EMAIL_DIRECTIONS = ["Inbound", "Outbound"]
EMAIL_LANGUAGES = ["en", "es", "fr", "de", "it"]
EMAIL_ACTION_POLICIES = ["DefaultPolicy", "CustomPolicy"]
ORG_LEVEL_ACTIONS = ["None", "Notify", "Block"]
ORG_LEVEL_POLICIES = ["OrgPolicy1", "OrgPolicy2"]
THREAT_TYPES_OPTIONS = ["Malware", "Phishing", "Spam", "Ransomware"]
THREAT_NAMES_OPTIONS = ["Emotet", "TrickBot", "Dridex", "Zeus"]

# Fields populated only if EmailAction != "None"
USER_LEVEL_ACTIONS = ["Clicked", "Reported"]
USER_LEVEL_POLICIES = ["Policy1", "Policy2"]
BULK_COMPLAINT_LEVEL_OPTIONS = ["None", "Low", "Medium", "High"]
LATEST_DELIVERY_LOCATIONS = ["Inbox", "Junk", "Spam", "Quarantine"]
LATEST_DELIVERY_ACTIONS = ["Delivered", "Blocked", "Quarantined", "Deferred"]

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

# ------------------------
# EmailEvents Generation
# ------------------------

def generate_email_event(event_index, start_time, delta):
    # Compute sequential event timestamp (used for Timestamp_UTC)
    event_time = start_time + (event_index * delta)
    
    record = OrderedDict()
    
    # 1. TenantId
    record["TenantId"] = TENANT_ID
    
    # 2. AttachmentCount (0-5)
    record["AttachmentCount"] = random.randint(0, 5)
    
    # 3. AuthenticationDetails (predefined JSON)
    record["AuthenticationDetails"] = random.choice(AUTH_DETAILS_OPTIONS)
    
    # 4. AdditionalFields (predefined JSON or empty string)
    additional = random.choice(ADDITIONAL_FIELDS_OPTIONS)
    record["AdditionalFields"] = additional if additional is not None else ""
    
    # 5. ConfidenceLevel (0-100)
    record["ConfidenceLevel"] = random.randint(0, 100)
    
    # 6. Connectors
    record["Connectors"] = random.choice(CONNECTORS)
    
    # 7. DetectionMethods (comma-separated)
    methods_sample = random.sample(DETECTION_METHODS, k=random.randint(1, len(DETECTION_METHODS)))
    record["DetectionMethods"] = ",".join(methods_sample)
    
    # 8. DeliveryAction
    record["DeliveryAction"] = random.choice(DELIVERY_ACTIONS)
    
    # 9. DeliveryLocation
    record["DeliveryLocation"] = random.choice(DELIVERY_LOCATIONS)
    
    # 10. EmailClusterId – populated only if EmailAction != "None"
    # (We will set it after determining EmailAction.)
    
    # 11. EmailDirection
    record["EmailDirection"] = random.choice(EMAIL_DIRECTIONS)
    
    # 12. EmailLanguage
    record["EmailLanguage"] = random.choice(EMAIL_LANGUAGES)
    
    # 13. EmailAction – select from options
    email_action = random.choice(EMAIL_ACTION_OPTIONS)
    record["EmailAction"] = email_action
    
    # 14. EmailActionPolicy
    record["EmailActionPolicy"] = random.choice(EMAIL_ACTION_POLICIES)
    
    # 15. EmailActionPolicyGuid
    record["EmailActionPolicyGuid"] = fake.uuid4()
    
    # 16. OrgLevelAction
    record["OrgLevelAction"] = random.choice(ORG_LEVEL_ACTIONS)
    
    # 17. OrgLevelPolicy
    record["OrgLevelPolicy"] = random.choice(ORG_LEVEL_POLICIES)
    
    # 18. InternetMessageId
    record["InternetMessageId"] = f"<{fake.uuid4()}@example.com>"
    
    # 19. NetworkMessageId
    record["NetworkMessageId"] = f"<{fake.uuid4()}@example.com>"
    
    # 20. RecipientEmailAddress
    record["RecipientEmailAddress"] = fake.email()
    
    # 21. RecipientObjectId
    record["RecipientObjectId"] = fake.uuid4()
    
    # 22. ReportId
    record["ReportId"] = fake.uuid4()
    
    # 23. SenderDisplayName
    record["SenderDisplayName"] = fake.name()
    
    # 24 & 25. FromEmail and FromDomain – only if EmailAction != "None"
    if email_action != "None":
        from_email = fake.email()
        record["FromEmail"] = from_email
        record["FromDomain"] = from_email.split("@")[1] if "@" in from_email else ""
    else:
        record["FromEmail"] = ""
        record["FromDomain"] = ""
    
    # 26. SenderObjectId
    record["SenderObjectId"] = fake.uuid4()
    
    # 27. SenderIPv4
    record["SenderIPv4"] = fake.ipv4()
    
    # 28. SenderIPv6
    record["SenderIPv6"] = fake.ipv6()
    
    # 29. SenderMailFromAddress
    sender_mail = fake.email()
    record["SenderMailFromAddress"] = sender_mail
    # 30. SenderMailFromDomain
    record["SenderMailFromDomain"] = sender_mail.split("@")[1] if "@" in sender_mail else ""
    
    # 31. EmailSubject – only if EmailAction != "None"
    if email_action != "None":
        record["EmailSubject"] = fake.sentence(nb_words=6)
    else:
        record["EmailSubject"] = ""
    
    # 32. ThreatTypes (random subset)
    sample_threats = random.sample(THREAT_TYPES_OPTIONS, k=random.randint(0, len(THREAT_TYPES_OPTIONS)))
    record["ThreatTypes"] = ",".join(sample_threats) if sample_threats else "None"
    
    # 33. ThreatNames (random subset)
    sample_threat_names = random.sample(THREAT_NAMES_OPTIONS, k=random.randint(0, len(THREAT_NAMES_OPTIONS)))
    record["ThreatNames"] = ",".join(sample_threat_names) if sample_threat_names else "None"
    
    # 34. TimeGenerated_UTC (current run time)
    record["TimeGenerated_UTC"] = datetime.utcnow().isoformat()
    
    # 35. Timestamp_UTC (sequential event timestamp)
    record["Timestamp_UTC"] = event_time.isoformat()
    
    # 36. UrlCount – only if EmailAction != "None"
    if email_action != "None":
        record["UrlCount"] = random.randint(0, 5)
    else:
        record["UrlCount"] = ""
    
    # 37. UserLevelAction – only if EmailAction != "None"
    if email_action != "None":
        record["UserLevelAction"] = random.choice(USER_LEVEL_ACTIONS)
    else:
        record["UserLevelAction"] = ""
    
    # 38. UserLevelPolicy – only if EmailAction != "None"
    if email_action != "None":
        record["UserLevelPolicy"] = random.choice(USER_LEVEL_POLICIES)
    else:
        record["UserLevelPolicy"] = ""
    
    # 39. BulkComplaintLevel – only if EmailAction != "None"
    if email_action != "None":
        record["BulkComplaintLevel"] = random.choice(BULK_COMPLAINT_LEVEL_OPTIONS)
    else:
        record["BulkComplaintLevel"] = ""
    
    # 40. LatestDeliveryLocation – only if EmailAction != "None"
    if email_action != "None":
        record["LatestDeliveryLocation"] = random.choice(DELIVERY_LOCATIONS)
    else:
        record["LatestDeliveryLocation"] = ""
    
    # 41. LatestDeliveryAction – only if EmailAction != "None"
    if email_action != "None":
        record["LatestDeliveryAction"] = random.choice(DELIVERY_ACTIONS)
    else:
        record["LatestDeliveryAction"] = ""
    
    # 42. SourceSystem (empty)
    record["SourceSystem"] = ""
    
    # 43. Type
    record["Type"] = "EmailEvent"
    
    # Additionally, if EmailAction is not "None", populate EmailClusterId; otherwise blank.
    if email_action != "None":
        record["EmailClusterId"] = fake.uuid4()
    else:
        record["EmailClusterId"] = ""
    
    return record

def generate_email_events(num_events, start_time, end_time, output_file):
    total_seconds = (end_time - start_time).total_seconds()
    delta = timedelta(seconds=(total_seconds / num_events))
    with open(output_file, 'w', encoding='utf-8') as f:
        for i in range(num_events):
            event = generate_email_event(i, start_time, delta)
            f.write(json.dumps(event) + "\n")

if __name__ == "__main__":
    days = prompt_for_days()
    events_per_day = 1000  # Adjust as desired
    total_events = days * events_per_day
    
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    output_filename = "email_events.json"
    
    generate_email_events(total_events, start_time, end_time, output_filename)
    print(f"Generated {total_events} email events for the past {days} day(s) in '{output_filename}'.")
1
