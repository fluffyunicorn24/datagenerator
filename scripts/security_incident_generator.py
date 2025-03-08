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
# SecurityIncident-Specific Constants
# ------------------------
INCIDENT_NAMES = [
    "Suspected Ransomware Attack",
    "Unauthorized Access Attempt",
    "Potential Data Exfiltration",
    "Malicious PowerShell Execution",
    "Phishing Campaign Detected",
    "Suspicious Remote Activity",
    "Malware Outbreak"
]
TITLES = [
    "Malware infection on endpoint",
    "Potential exfiltration of sensitive data",
    "Phishing attempt targeting multiple users",
    "Suspicious activity from unknown IP",
    "Privilege escalation suspected"
]
DESCRIPTIONS = [
    "Incident triggered due to suspicious activity observed in the environment.",
    "Potential compromise of user credentials leading to unauthorized access attempts.",
    "Endpoint detected with advanced malware signature. Investigation needed.",
    "Multiple alerts correlated indicating possible data exfiltration via OneDrive.",
    "Phishing emails detected with malicious links targeting finance department."
]
SEVERITIES = ["Informational", "Low", "Medium", "High"]
STATUSES = ["New", "Active", "Resolved", "Closed", "InProgress"]
CLASSIFICATIONS = ["TruePositive", "BenignPositive", "FalsePositive", "Undetermined"]
CLASSIFICATION_REASONS = ["SuspiciousActivity", "SecurityTesting", "ConfirmedThreat", "CustomerDefined"]

def pick_owner():
    if random.choice([True, False]):
        return {"objectId": None, "email": None, "assignedTo": None, "userPrincipalName": None}
    else:
        return {"objectId": None, "email": None, "assignedTo": "Mimik Emails - govtesttenant", "userPrincipalName": None}

PROVIDER_NAMES = ["Azure Sentinel", "MDE", "Microsoft 365 Defender", "CrowdStrike Falcon", "MCAS"]

# ------------------------
# Time & Utility Functions
# ------------------------
def random_time_window():
    start = fake.date_time_between(start_date="-30d", end_date="now")
    end = start + timedelta(minutes=random.randint(1, 1440))
    return start, end

def prompt_for_days():
    valid_options = ['1', '3', '5']
    while True:
        inp = input("Enter the number of days for data replication (1, 3, or 5): ").strip()
        if inp in valid_options:
            return int(inp)
        else:
            print("Invalid input. Please enter 1, 3, or 5.")

def replace_domain_references(text: str) -> str:
    # Replace any occurrence of "alpineskihouse" with "govtesttenant"
    return text.replace("alpineskihouse", "govtesttenant")

# ------------------------
# Extended AdditionalData Templates
# ------------------------
def generate_extendedproperties_template_exfiltration():
    tid = str(fake.uuid4())
    return {
        "alertsCount": 1,
        "bookmarksCount": 0,
        "commentsCount": 0,
        "alertProductNames": ["Microsoft Data Loss Prevention"],
        "tactics": ["Exfiltration"],
        "techniques": [],
        "providerIncidentUrl": f"https://security.microsoft.com/incidents/5314?tid={tid}"
    }

def generate_extendedproperties_template_malware():
    tid = str(fake.uuid4())
    return {
        "alertsCount": 43,
        "bookmarksCount": 0,
        "commentsCount": 0,
        "alertProductNames": [
            "Azure Advanced Threat Protection",
            "Microsoft Defender Advanced Threat Protection",
            "Microsoft 365 Defender",
            "Azure Sentinel"
        ],
        "tactics": ["InitialAccess", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement", "Execution"],
        "techniques": ["T1550", "T1046", "T1018", "T1490", "T1003", "T1021", "T1039", "T1486", "T1105", "T1219", "T1555", "T1047", "T1528", "T1059", "T1007", "T1016", "T1049", "T1069", "T1087", "T1135", "T1570", "T1552", "T1078"],
        "providerIncidentUrl": f"https://security.microsoft.com/incidents/5176?tid={tid}"
    }

def generate_extendedproperties_template_phishing():
    tid = str(fake.uuid4())
    return {
        "alertsCount": 1,
        "bookmarksCount": 0,
        "commentsCount": 0,
        "alertProductNames": ["Office 365 Advanced Threat Protection"],
        "tactics": ["InitialAccess"],
        "techniques": ["T1566"],
        "providerIncidentUrl": f"https://security.microsoft.com/incidents/5308?tid={tid}"
    }

def generate_extendedproperties_template_suspicious_ip():
    tid = str(fake.uuid4())
    return {
        "alertsCount": 1,
        "bookmarksCount": 0,
        "commentsCount": 0,
        "alertProductNames": ["Azure Active Directory Identity Protection"],
        "tactics": ["InitialAccess"],
        "techniques": [],
        "providerIncidentUrl": f"https://security.microsoft.com/incidents/5316?tid={tid}"
    }

def generate_extendedproperties_template_privilege():
    tid = str(fake.uuid4())
    return {
        "alertsCount": 1,
        "bookmarksCount": 0,
        "commentsCount": 0,
        "alertProductNames": ["Microsoft 365 Defender"],
        "tactics": [],
        "techniques": [],
        "providerIncidentUrl": f"https://security.microsoft.com/incidents/5332?tid={tid}"
    }

def pick_additional_data(title: str) -> dict:
    title_lower = title.lower()
    if "potential exfiltration of sensitive data" in title_lower:
        return generate_extendedproperties_template_exfiltration()
    elif "malware infection on endpoint" in title_lower:
        return generate_extendedproperties_template_malware()
    elif "phishing attempt targeting multiple users" in title_lower:
        return generate_extendedproperties_template_phishing()
    elif "suspicious activity from unknown ip" in title_lower:
        return generate_extendedproperties_template_suspicious_ip()
    elif "privilege escalation suspected" in title_lower:
        return generate_extendedproperties_template_privilege()
    else:
        # Default fallback additional data
        return {"alertsCount": 0, "bookmarksCount": 0, "commentsCount": 0}

# ------------------------
# Generate SecurityIncident
# ------------------------
def generate_security_incident(event_index, start_time, delta):
    event_time = start_time + (event_index * delta)
    record = OrderedDict()
    
    record["TenantId"] = TENANT_ID
    record["TimeGenerated_UTC"] = event_time.isoformat()
    record["IncidentName"] = random.choice(INCIDENT_NAMES)
    record["Title"] = random.choice(TITLES)
    record["Description"] = random.choice(DESCRIPTIONS)
    record["Severity"] = random.choice(SEVERITIES)
    
    status_choice = random.choice(STATUSES)
    record["Status"] = status_choice
    if status_choice == "New":
        record["Classification"] = ""
    elif status_choice == "Closed":
        record["Classification"] = "Undetermined"
    else:
        record["Classification"] = random.choice(CLASSIFICATIONS)
        
    record["ClassificationComment"] = fake.sentence(nb_words=8)
    record["ClassificationReason"] = random.choice(CLASSIFICATION_REASONS)
    
    record["Owner"] = json.dumps(pick_owner())
    record["ProviderName"] = random.choice(PROVIDER_NAMES)
    record["ProviderIncidentId"] = str(fake.uuid4())
    
    start_dt, end_dt = random_time_window()
    record["FirstActivityTime_UTC"] = start_dt.isoformat()
    record["LastActivityTime_UTC"] = end_dt.isoformat()
    first_modified = start_dt + timedelta(minutes=random.randint(1, 60))
    last_modified = end_dt + timedelta(minutes=random.randint(1, 60))
    record["FirstModifiedTime_UTC"] = first_modified.isoformat()
    record["LastModifiedTime_UTC"] = last_modified.isoformat()
    created_time = start_dt + timedelta(minutes=random.randint(0, 30))
    record["CreatedTime_UTC"] = created_time.isoformat()
    if status_choice in ["Resolved", "Closed"]:
        closed_time = last_modified + timedelta(minutes=random.randint(1, 60))
        record["ClosedTime_UTC"] = closed_time.isoformat()
    else:
        record["ClosedTime_UTC"] = ""
    
    record["IncidentNumber"] = random.randint(1000, 99999)
    rule_count = random.randint(0, 2)
    record["RelatedAnalyticRuleIds"] = json.dumps([str(fake.uuid4()) for _ in range(rule_count)])
    alert_count = random.randint(0, 3)
    record["AlertIds"] = json.dumps([str(fake.uuid4()) for _ in range(alert_count)])
    bookmark_count = random.randint(0, 2)
    record["BookmarkIds"] = json.dumps([str(fake.uuid4()) for _ in range(bookmark_count)])
    
    # Set Comments, Tasks, and Labels as empty arrays
    record["Comments"] = "[]"
    record["Tasks"] = "[]"
    record["Labels"] = "[]"
    
    # For IncidentUrl, we'll use a default generated URL
    record["IncidentUrl"] = fake.url()
    
    # AdditionalData is set based on Title contents
    additional_data = pick_additional_data(record["Title"])
    record["AdditionalData"] = json.dumps(additional_data)
    
    record["ModifiedBy"] = random.choice(["Security Analyst 1", "Automation", "SOC Lead"])
    record["SourceSystem"] = random.choice(["Azure Sentinel", "MDE", "Microsoft 365 Defender"])
    record["Type"] = "SecurityIncident"
    
    return record

def generate_security_incidents(num_events, start_time, end_time, output_file):
    total_seconds = (end_time - start_time).total_seconds()
    delta = timedelta(seconds=(total_seconds / num_events))
    with open(output_file, 'w', encoding='utf-8') as f:
        for i in range(num_events):
            incident = generate_security_incident(i, start_time, delta)
            f.write(json.dumps(incident) + "\n")

if __name__ == "__main__":
    days = prompt_for_days()
    events_per_day = 500  # Adjust as needed
    total_events = days * events_per_day
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    output_filename = "security_incidents.json"
    generate_security_incidents(total_events, start_time, end_time, output_filename)
    print(f"Generated {total_events} security incidents for the past {days} day(s) in '{output_filename}'.")
