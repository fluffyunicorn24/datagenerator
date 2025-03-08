import json
import random
from collections import OrderedDict
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()

# ------------------------
# Global Shared Constants
# ------------------------
TENANT_ID = "d63f3f4b-6e5b-4e10-a8b8-2d7e2a8b5f72"
AAD_TENANT_ID = "0527ecb7-06fb-4769-b324-fd4a3bb865eb"
DOMAIN = "govtesttenant.net"

ACCOUNT_NAMES = ["jdoe", "msmith", "ajones", "bwilliams", "cjohnson", "Admin"]
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
# SecurityAlert-Specific Constants
# ------------------------
DISPLAYNAME_LIST = [
    "Anonymous IP address",
    "Administrative action submitted by an Administrator",
    "DLP policy (Block sharing sensitive information in Teams) matched for document (Feb 2025 - Hard.json) in OneDrive",
    "Mail with Malware",
    "Unfamiliar sign-in properties",
    "DLP policy (Audit emailing sensitive information externally) matched for email with subject (Request for Invoice Access)",
    "DLP policy (Audit emailing sensitive information externally) matched for email with subject (Lee your file are attached)",
    "Email messages containing malicious URL removed after delivery\u200b",
    "A potentially malicious URL click was detected",
    "DLP policy (Audit emailing sensitive information externally) matched for email with subject (Your file is ready)"
]
ALERTNAME_LIST = DISPLAYNAME_LIST
ALERTSEVERITY_LIST = ["Low", "Informational", "Medium", "High"]

DESCRIPTION_LIST = [
    "Sign-in from an anonymous IP address (e.g. Tor browser, anonymizer VPNs)",
    "An administrator in your organization requested to soft-delete email messages. (Message query referencing old domain...)",
    "Mail with Malware",
    "The following properties of this sign-in are unfamiliar for the given user: ASN, Device, IP, Location, EASId, TenantIPsubnet",
    "Sign-in with properties we have not seen recently for the given user",
    "Emails with malicious URL that were delivered and later removed -V1.0.0.3",
    "We have detected that one of your users has recently clicked on a link that was found to be malicious. -V1.0.0.5",
    "An administrator in your organization requested to soft-delete email messages. (Long text...)",
    "A contained user’s attempt to create, delete, or modify files over SMB was automatically blocked by attack disruption."
]

PROVIDERNAME_LIST = [
    "IPC",
    "MicrosoftThreatProtection",
    "MicrosoftEndPointDlp",
    "OATP",
    "Azure Advanced Threat Protection",
    "MCAS",
    "MDATP"
]
VENDORNAME_LIST = ["Microsoft"]
CONFIDENCE_LEVELS = ["Low", "Medium", "High"]
REMEDIATION_STEPS = [
    "Quarantine the device",
    "Reset user password",
    "Block the IP address",
    "Isolate the host from network"
]
STATUS_OPTIONS = ["New", "Active", "Resolved", "Dismissed"]
PRODUCT_NAMES = ["Microsoft Defender for Endpoint", "Microsoft 365 Defender", "Azure Security Center"]
PRODUCT_COMPONENT_NAMES = ["EndpointDetection", "ThreatAnalytics", "CloudProtection"]
SOURCE_SYSTEM_OPTIONS = ["Azure Sentinel", "MDE", "Defender for Cloud"]
IS_INCIDENT_OPTIONS = [True, False]

fake = Faker()

def prompt_for_days():
    valid_options = ['1', '3', '5']
    while True:
        inp = input("Enter the number of days for data replication (1, 3, or 5): ").strip()
        if inp in valid_options:
            return int(inp)
        else:
            print("Invalid input. Please enter 1, 3, or 5.")

def random_time_window():
    start = fake.date_time_between(start_date="-30d", end_date="now")
    end = start + timedelta(minutes=random.randint(1, 1440))
    return start, end

def replace_domain_references(text: str) -> str:
    return text.replace("alpineskihouse", "govtesttenant")

# ---------------------------------------
# EXTENDEDPROPERTIES TEMPLATES
# ---------------------------------------
# We'll define two example templates based on your provided examples, and fill them with random data

def generate_extendedproperties_template_1():
    """
    Example:
    {
      "Client IP Address": "79.127.184.130",
      "Client Location": "Zuerich, Zuerich, CH",
      "Detail Description": "This risk event type indicates sign-ins from an anonymous IP address (Tor)...",
      "Request Id": "f82c9943-1fb4-4843-bc35-7b3416e01400",
      "State": "Closed",
      "UpdateOwner": "Ipc",
      "Comments": "Risk detail: User passed multifactor authentication",
      "ProcessedBySentinel": "True",
      "Alert generation status": "Full alert created"
    }
    """
    ip_addr = fake.ipv4()
    city = fake.city()
    state = fake.state()
    country_code = fake.country_code()
    detail_desc = "This risk event type indicates sign-ins from an anonymous IP address (e.g. Tor)."
    template = {
        "Client IP Address": ip_addr,
        "Client Location": f"{city}, {state}, {country_code}",
        "Detail Description": detail_desc,
        "Request Id": str(fake.uuid4()),
        "State": random.choice(["Closed", "Active", "Resolved"]),
        "UpdateOwner": random.choice(["Ipc", "MDE", "UserAction"]),
        "Comments": "Risk detail: User passed multifactor authentication",
        "ProcessedBySentinel": "True",
        "Alert generation status": "Full alert created"
    }
    return template

def generate_extendedproperties_template_2():
    """
    Example:
    {
      "IncidentId": "5332",
      "OriginSource": "Microsoft 365 defender",
      "Category": "SuspiciousActivity",
      "DetectionSource": "manual",
      "AssignedTo": "API-Automated Investigation and Response",
      "Determination": null,
      "Classification": null,
      "ThreatName": null,
      "ThreatFamilyName": null,
      "DetectorId": "917b376c-f30d-48cc-aaa3-0559a9e144bb",
      "LastUpdated": "03/07/2025 13:35:44",
      "ProcessedBySentinel": "True",
      "Alert generation status": "Full alert created"
    }
    """
    template = {
        "IncidentId": str(random.randint(1000, 9999)),
        "OriginSource": "Microsoft 365 defender",
        "Category": "SuspiciousActivity",
        "DetectionSource": random.choice(["manual", "automated"]),
        "AssignedTo": "API-Automated Investigation and Response",
        "Determination": None,
        "Classification": None,
        "ThreatName": None,
        "ThreatFamilyName": None,
        "DetectorId": str(fake.uuid4()),
        "LastUpdated": datetime.utcnow().strftime("%m/%d/%Y %H:%M:%S"),
        "ProcessedBySentinel": "True",
        "Alert generation status": "Full alert created"
    }
    return template

def pick_extendedproperties():
    # We'll pick one of the two templates at random
    if random.choice([True, False]):
        return generate_extendedproperties_template_1()
    else:
        return generate_extendedproperties_template_2()

# We'll keep Tactics, Techniques, SubTechniques logic simple or empty
tactic_options = [["LateralMovement"], ["Collection"], ["Impact"], ["Execution"], ["Persistence"]]
technique_options = [["T1021"], ["T1039"], ["T1486"], ["T1570"], ["T1059"]]
subtech_options = [["T1021.001"], ["T1021.002"], ["T1059.001"], ["T1550.002"]]

def generate_security_alert(event_index, start_time, delta):
    event_time = start_time + (event_index * delta)
    record = OrderedDict()
    
    # 1. TenantId
    record["TenantId"] = TENANT_ID
    
    # 2. TimeGenerated_UTC
    record["TimeGenerated_UTC"] = event_time.isoformat()
    
    # 3. DisplayName
    record["DisplayName"] = random.choice(DISPLAYNAME_LIST)
    
    # 4. AlertName
    record["AlertName"] = random.choice(ALERTNAME_LIST)
    
    # 5. AlertSeverity
    record["AlertSeverity"] = random.choice(ALERTSEVERITY_LIST)
    
    # 6. Description
    desc = random.choice(DESCRIPTION_LIST)
    desc = replace_domain_references(desc)
    record["Description"] = desc
    
    # 7. ProviderName
    record["ProviderName"] = random.choice(PROVIDERNAME_LIST)
    
    # 8. VendorName
    record["VendorName"] = random.choice(VENDORNAME_LIST)
    
    # 9. VendorOriginalId
    record["VendorOriginalId"] = str(fake.uuid4())
    
    # 10. SystemAlertId
    record["SystemAlertId"] = str(fake.uuid4())
    
    # 11. ResourceId
    record["ResourceId"] = f"/subscriptions/{fake.uuid4()}/resourceGroups/{fake.word()}/providers/Microsoft.Security/alerts/{fake.uuid4()}"
    
    # 12. SourceComputerId
    record["SourceComputerId"] = str(fake.uuid4())
    
    # 13. AlertType
    record["AlertType"] = "SecurityAlert"
    
    # 14. ConfidenceLevel
    record["ConfidenceLevel"] = random.choice(CONFIDENCE_LEVELS)
    
    # 15. ConfidenceScore
    record["ConfidenceScore"] = random.randint(0, 100)
    
    # 16. IsIncident
    record["IsIncident"] = random.choice(IS_INCIDENT_OPTIONS)
    
    # 17, 18. StartTime_UTC, EndTime_UTC
    start_dt = fake.date_time_between(start_date="-30d", end_date="now")
    end_dt = start_dt + timedelta(minutes=random.randint(1, 1440))
    record["StartTime_UTC"] = start_dt.isoformat()
    record["EndTime_UTC"] = end_dt.isoformat()
    
    # 19. ProcessingEndTime_UTC
    record["ProcessingEndTime_UTC"] = (end_dt + timedelta(minutes=random.randint(1, 60))).isoformat()
    
    # 20. RemediationSteps
    record["RemediationSteps"] = random.choice(REMEDIATION_STEPS)
    
    # 21. ExtendedProperties - now uses the two new templates
    extended_props = pick_extendedproperties()
    record["ExtendedProperties"] = json.dumps(extended_props)
    
    # 22. Entities - pick from a simpler or more realistic approach (from prior snippet)
    # For brevity, we'll do a simple approach or re-use your old logic
    # We'll just do 1 or 2 items to keep it short
    # Or define a function for "realistic_entities"
    # For example:
    entities = []
    
    # We'll do a random choice: either the "template 1" or "template 2" approach from previous logic
    # Or keep it simpler
    if random.choice([True, False]):
        # Template 1 style
        template = [
            {
                "$id": "4",
                "AadTenantId": AAD_TENANT_ID,
                "AadUserId": str(fake.uuid4()),
                "IsDomainJoined": True,
                "Type": "account"
            },
            {
                "$id": "5",
                "SessionId": str(fake.uuid4()),
                "Account": {"$ref": "4"},
                "UserAgent": fake.user_agent(),
                "StartTimeUtc": datetime.utcnow().isoformat(),
                "Type": "cloud-logon-session"
            },
            {
                "$id": "6",
                "RequestId": str(fake.uuid4()),
                "Type": "cloud-logon-request"
            },
            {
                "$id": "7",
                "Address": fake.ipv4(),
                "Location": {
                    "CountryCode": fake.country_code(),
                    "State": fake.state(),
                    "City": fake.city(),
                    "Longitude": round(random.uniform(-180, 180), 5),
                    "Latitude": round(random.uniform(-90, 90), 5),
                    "Asn": random.randint(10000, 99999)
                },
                "Type": "ip"
            }
        ]
        entities = template
    else:
        # Template 2 style
        acct_name = random.choice(ACCOUNT_NAMES)
        template = [
            {
                "$id": "3",
                "Name": acct_name + "@" + DOMAIN,
                "UPNSuffix": DOMAIN,
                "Sid": "S-1-12-1-" + str(random.randint(1000000000, 9999999999)),
                "AadUserId": str(fake.uuid4()),
                "IsDomainJoined": True,
                "CreatedTimeUtc": datetime.utcnow().isoformat(),
                "Type": "account",
                "UserPrincipalName": acct_name + "@" + DOMAIN,
                "AccountName": acct_name
            },
            {
                "$id": "4",
                "Directory": "https://" + fake.domain_name() + "/Documents/CTF%20Questions",
                "Name": fake.word() + ".json",
                "CreatedTimeUtc": datetime.utcnow().isoformat(),
                "Type": "file"
            },
            {
                "$id": "5",
                "AppId": random.randint(10000, 99999),
                "Name": "Microsoft OneDrive for Business",
                "CreatedTimeUtc": datetime.utcnow().isoformat(),
                "Type": "cloud-application"
            }
        ]
        entities = template
    
    record["Entities"] = json.dumps(entities)
    
    # 23. SourceSystem
    record["SourceSystem"] = random.choice(SOURCE_SYSTEM_OPTIONS)
    
    # 24. WorkspaceSubscriptionId
    record["WorkspaceSubscriptionId"] = str(fake.uuid4())
    
    # 25. WorkspaceResourceGroup
    record["WorkspaceResourceGroup"] = "SecurityWorkspaceRG"
    
    # 26. ExtendedLinks
    record["ExtendedLinks"] = json.dumps({
        "AlertDocumentation": fake.url(),
        "VendorPage": fake.url()
    })
    
    # 27. ProductName
    record["ProductName"] = random.choice(PRODUCT_NAMES)
    
    # 28. ProductComponentName
    record["ProductComponentName"] = random.choice(PRODUCT_COMPONENT_NAMES)
    
    # 29. AlertLink
    record["AlertLink"] = fake.url()
    
    # 30. Status
    record["Status"] = random.choice(STATUS_OPTIONS)
    
    # 31. CompromisedEntity
    if random.choice([True, False]):
        record["CompromisedEntity"] = random.choice(ACCOUNT_NAMES) + "@" + DOMAIN
    else:
        record["CompromisedEntity"] = random.choice(DEVICE_NAME_OPTIONS)
    
    # 32-34. Tactics, Techniques, SubTechniques
    # We'll just pick a random short set here
    tactic_options = [["LateralMovement"], ["Collection"], ["Impact"], ["Execution"], ["Persistence"]]
    technique_options = [["T1021"], ["T1039"], ["T1486"], ["T1570"], ["T1059"]]
    subtech_options = [["T1021.001"], ["T1021.002"], ["T1059.001"], ["T1550.002"]]
    
    chosen_tactics = random.choice(tactic_options)
    chosen_techniques = random.choice(technique_options)
    chosen_subtechs = random.choice(subtech_options)
    
    record["Tactics"] = json.dumps(chosen_tactics)
    record["Techniques"] = json.dumps(chosen_techniques)
    record["SubTechniques"] = json.dumps(chosen_subtechs)
    
    # 35. Type
    record["Type"] = "SecurityAlert"
    
    return record

def generate_security_alerts(num_events, start_time, end_time, output_file):
    total_seconds = (end_time - start_time).total_seconds()
    delta = timedelta(seconds=(total_seconds / num_events))
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for i in range(num_events):
            alert = generate_security_alert(i, start_time, delta)
            f.write(json.dumps(alert) + "\n")

if __name__ == "__main__":
    days = prompt_for_days()
    events_per_day = 1000  # Adjust as needed
    total_events = days * events_per_day
    
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    output_filename = "security_alerts.json"
    
    generate_security_alerts(total_events, start_time, end_time, output_filename)
    print(f"Generated {total_events} security alerts for the past {days} day(s) in '{output_filename}'.")
