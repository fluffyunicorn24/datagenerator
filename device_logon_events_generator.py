from collections import OrderedDict
import json
import random
from datetime import datetime, timedelta
from faker import Faker

# Initialize Faker for realistic fake data
fake = Faker()

# ------------------------
# Constants & Shared Lists
# ------------------------

TENANT_ID = "d63f3f4b-6e5b-4e10-a8b8-2d7e2a8b5f72"

# Shared fields for consistency with other Device* events
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
# DeviceLogonEvents-Specific Constants
# ------------------------

# ActionType options for logon events
LOGON_ACTION_TYPES = [
    "LogonFailed", "LogonSuccess", "LogonAttempted", "LogonSuccessAggregatedReport"
]

# FailureReason options – now updated: if ActionType is "LogonFailed", use "InvalidUserNameOrPassword"
# Otherwise, FailureReason is blank.
# (The script now forces the failure reason to "InvalidUserNameOrPassword" if ActionType is "LogonFailed".)
FAILURE_REASONS = ["InvalidUserNameOrPassword"]

# Common logon types
LOGON_TYPES = ["Interactive", "RemoteInteractive", "Network", "Batch", "Service", "Unlock", "CachedInteractive"]

# Logon Protocols
LOGON_PROTOCOLS = ["Kerberos", "NTLM", "CredSSP"]

# MachineGroup options
MACHINE_GROUP_OPTIONS = [
    "Windows Defender ATP", "GCCCloudSecure", "AzureSecurityMonitoring",
    "MSCloudMonitoring", "EnterpriseSecurityGroup"
]

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
# DeviceLogonEvents Generation
# ------------------------

def generate_device_logon_event(event_index, start_time, delta):
    # Compute sequential event timestamp for Timestamp_UTC
    event_time = start_time + (event_index * delta)
    
    record = OrderedDict()
    
    # 1. TenantId
    record["TenantId"] = TENANT_ID
    
    # 2. AccountDomain (default from shared list; may be overridden later)
    acct_domain = random.choice(ACCOUNT_DOMAINS)
    record["AccountDomain"] = acct_domain
    
    # 3. AccountName
    record["AccountName"] = fake.user_name()
    
    # 4. AccountSid
    record["AccountSid"] = random_sid()
    
    # 5. ActionType (choose from LOGON_ACTION_TYPES)
    action_type = random.choice(LOGON_ACTION_TYPES)
    record["ActionType"] = action_type
    
    # 6. AdditionalFields (empty string for now; could be enhanced similarly to other scripts)
    record["AdditionalFields"] = ""
    
    # 7. AppGuardContainerId (empty)
    record["AppGuardContainerId"] = ""
    
    # 8. DeviceId
    if acct_domain == "" or acct_domain == "nt authority":
        record["DeviceId"] = random.choice(NT_AUTHORITY_DEVICEIDS)
    else:
        record["DeviceId"] = fake.uuid4()
    
    # 9. DeviceName
    record["DeviceName"] = random.choice(DEVICE_NAME_OPTIONS)
    
    # 10. FailureReason: if ActionType is LogonFailed, set to "InvalidUserNameOrPassword"; otherwise blank.
    if action_type == "LogonFailed":
        record["FailureReason"] = "InvalidUserNameOrPassword"
    else:
        record["FailureReason"] = ""
    
    # 11. InitiatingProcessAccountDomain
    record["InitiatingProcessAccountDomain"] = fake.domain_name()
    
    # 12. InitiatingProcessAccountName
    record["InitiatingProcessAccountName"] = fake.user_name()
    
    # 13. InitiatingProcessAccountObjectId (GUID)
    record["InitiatingProcessAccountObjectId"] = fake.uuid4()
    
    # 14. InitiatingProcessAccountSid
    record["InitiatingProcessAccountSid"] = random_sid()
    
    # 15. InitiatingProcessAccountUpn
    record["InitiatingProcessAccountUpn"] = fake.email()
    
    # 16. InitiatingProcessCommandLine – simulate a logon-related command
    record["InitiatingProcessCommandLine"] = random.choice(["logonui.exe /start", "winlogon.exe", "lsass.exe /monitor"])
    
    # 17. InitiatingProcessFileName
    record["InitiatingProcessFileName"] = random.choice(["logonui.exe", "winlogon.exe", "lsass.exe"])
    
    # 18. InitiatingProcessFolderPath
    record["InitiatingProcessFolderPath"] = random.choice(["C:\\Windows\\System32", "C:\\Windows\\System32\\drivers", "C:\\Windows\\System32\\wbem"])
    
    # 19. InitiatingProcessId
    record["InitiatingProcessId"] = random.randint(1000, 9999)
    
    # 20. InitiatingProcessIntegrityLevel
    record["InitiatingProcessIntegrityLevel"] = random.choice([4096, 8192, 12288])
    
    # 21. InitiatingProcessMD5
    record["InitiatingProcessMD5"] = random_md5()
    
    # 22. InitiatingProcessParentFileName
    record["InitiatingProcessParentFileName"] = fake.file_name()
    
    # 23. InitiatingProcessParentId
    record["InitiatingProcessParentId"] = random.randint(1000, 9999)
    
    # 24. InitiatingProcessSHA1
    record["InitiatingProcessSHA1"] = random_sha1()
    
    # 25. InitiatingProcessSHA256
    record["InitiatingProcessSHA256"] = random_sha256()
    
    # 26. InitiatingProcessTokenElevation
    record["InitiatingProcessTokenElevation"] = False
    
    # 27. IsLocalAdmin (random Boolean)
    record["IsLocalAdmin"] = random.choice([True, False])
    
    # 28. LogonId
    record["LogonId"] = random.randint(1000, 9999)
    
    # 29. LogonType
    record["LogonType"] = random.choice(LOGON_TYPES)
    
    # 30. MachineGroup
    record["MachineGroup"] = random.choice(MACHINE_GROUP_OPTIONS)
    
    # 31. Protocol
    record["Protocol"] = random.choice(LOGON_PROTOCOLS)
    
    # 32. RemoteDeviceName – if remote logon type, populate; else empty.
    if record["LogonType"] in ["RemoteInteractive", "Network"]:
        record["RemoteDeviceName"] = random.choice(DEVICE_NAME_OPTIONS)
    else:
        record["RemoteDeviceName"] = ""
    
    # 33. RemoteIP – if remote, generate; else empty.
    if record["LogonType"] in ["RemoteInteractive", "Network"]:
        record["RemoteIP"] = fake.ipv4()
    else:
        record["RemoteIP"] = ""
    
    # 34. RemoteIPType – if RemoteIP is present, choose IPv4 or IPv6; else empty.
    if record["RemoteIP"]:
        record["RemoteIPType"] = random.choice(["IPv4", "IPv6"])
    else:
        record["RemoteIPType"] = ""
    
    # 35. RemotePort – if remote, generate; else empty.
    if record["RemoteIP"]:
        record["RemotePort"] = random.randint(1024, 65535)
    else:
        record["RemotePort"] = ""
    
    # 36. ReportId
    record["ReportId"] = fake.uuid4()
    
    # 37. Timestamp_UTC (renamed from "Timestamp [UTC]")
    record["Timestamp_UTC"] = event_time.isoformat()
    
    # 38. TimeGenerated_UTC (renamed from "TimeGenerated [UTC]")
    record["TimeGenerated_UTC"] = datetime.utcnow().isoformat()
    
    # 39. InitiatingProcessParentCreationTime_UTC – simulate as event_time minus 15-30 minutes
    record["InitiatingProcessParentCreationTime_UTC"] = (event_time - timedelta(minutes=random.randint(15, 30))).isoformat()
    
    # 40. InitiatingProcessCreationTime_UTC – simulate as event_time minus 5-14 minutes
    record["InitiatingProcessCreationTime_UTC"] = (event_time - timedelta(minutes=random.randint(5, 14))).isoformat()
    
    # 41. InitiatingProcessFileSize
    record["InitiatingProcessFileSize"] = random.randint(1000, 10000000)
    
    # 42. InitiatingProcessVersionInfoCompanyName
    comp_names = ["Microsoft Corporation", "Google LLC", "OpenHandleCollector", "Microsoft CoreXT", "azgaext", "MicrosoftDnsAgent"]
    record["InitiatingProcessVersionInfoCompanyName"] = random.choice(comp_names)
    
    # 43. InitiatingProcessVersionInfoFileDescription
    file_descs = ["Antimalware Service Executable", "Microsoft Azure", "Windows PowerShell",
                  "Google Updater", "Windows Logon Application", "Microsoft Edge WebView2",
                  "Windows Explorer", "Microsoft Teams", "Microsoft OneDrive"]
    record["InitiatingProcessVersionInfoFileDescription"] = random.choice(file_descs)
    
    # 44. InitiatingProcessVersionInfoInternalFileName
    internal_names = ["MsMpEng.exe", "WaAppAgent", "PowerShell", "explorer", "msedgewebview2_exe",
                      "OfficeClickToRun.exe", "Teams.exe", "SearchIndexer.exe", "OneDrive.exe"]
    record["InitiatingProcessVersionInfoInternalFileName"] = random.choice(internal_names)
    
    # 45. InitiatingProcessVersionInfoOriginalFileName
    original_names = ["MsMpEng.exe", "PowerShell.EXE", "EXPLORER.EXE", "msedgewebview2.exe",
                      "OfficeC2RClient.exe", "ms-teams.exe", "SearchIndexer.exe", "OneDriveSetup.exe",
                      "MetricsExtension.Native.exe"]
    record["InitiatingProcessVersionInfoOriginalFileName"] = random.choice(original_names)
    
    # 46. InitiatingProcessVersionInfoProductName
    prod_names = ["Microsoft® Windows® Operating System", "Microsoft Edge", "Google Updater",
                  "Microsoft Teams", "Microsoft OneDrive", "Microsoft Edge Update",
                  "Microsoft 365 and Office", "Microsoft SharePoint"]
    record["InitiatingProcessVersionInfoProductName"] = random.choice(prod_names)
    
    # 47. InitiatingProcessVersionInfoProductVersion
    record["InitiatingProcessVersionInfoProductVersion"] = f"v{random.randint(1,10)}.{random.randint(0,9)}"
    
    # 48. InitiatingProcessSessionId
    record["InitiatingProcessSessionId"] = random.randint(1000, 9999)
    
    # 49. IsInitiatingProcessRemoteSession
    record["IsInitiatingProcessRemoteSession"] = random.choice([True, False])
    
    # 50. InitiatingProcessRemoteSessionDeviceName
    record["InitiatingProcessRemoteSessionDeviceName"] = random.choice(DEVICE_NAME_OPTIONS)
    
    # 51. InitiatingProcessRemoteSessionIP
    record["InitiatingProcessRemoteSessionIP"] = fake.ipv4()
    
    # 52. SourceSystem (empty per instructions)
    record["SourceSystem"] = ""
    
    # 53. Type
    record["Type"] = "DeviceLogonEvent"
    
    # ------------------------
    # AdditionalFields: use predefined JSON templates.
    # Use the initiating process account fields for substitution.
    record["AdditionalFields"] = get_additional_fields(record["InitiatingProcessAccountName"],
                                                       record["InitiatingProcessAccountDomain"],
                                                       record["InitiatingProcessAccountUpn"])
    
    # If ActionType is LogonFailed, force AccountDomain to be blank.
    if action_type == "LogonFailed":
        record["AccountDomain"] = ""
    
    return record

def get_additional_fields(init_acct_name, init_acct_domain, init_acct_upn):
    templates = []
    # Template 1: Empty JSON object
    templates.append({})
    # Template 2: Cron job details with Posix user and group information
    templates.append({
        "Terminal": "cron",
        "PosixUserId": random.randint(500, 1000),
        "PosixPrimaryGroupName": "omiusers",
        "PosixPrimaryGroupId": random.randint(900, 1000),
        "PosixSecondaryGroups": "[{\"Name\":\"omi\",\"PosixGroupId\":998}]",
        "InitiatingAccountName": init_acct_name,
        "InitiatingAccountDomain": init_acct_domain,
        "InitiatingAccountPosixUserId": random.randint(500, 1000),
        "InitiatingAccountPosixGroupName": "omiusers",
        "InitiatingAccountPosixGroupId": random.randint(900, 1000)
    })
    # Template 3: Local logon details
    local_logon = {"IsLocalLogon": random.choice([True, False])}
    if not local_logon["IsLocalLogon"]:
        local_logon["Upn"] = init_acct_upn
    templates.append(local_logon)
    # Template 4: Aggregated unique events
    templates.append({"uniqueEventsAggregated": random.randint(1, 200)})
    # Template 5: Another cron job / Posix combination
    templates.append({
        "Terminal": "cron",
        "PosixUserId": 0,
        "PosixPrimaryGroupName": "root",
        "PosixPrimaryGroupId": 0,
        "PosixSecondaryGroups": "[]",
        "InitiatingAccountName": "root",
        "InitiatingAccountDomain": "ip-192-168-140-0.eu-north-1.compute.internal",
        "InitiatingAccountPosixUserId": 0,
        "InitiatingAccountPosixGroupName": "root",
        "InitiatingAccountPosixGroupId": 0
    })
    return json.dumps(random.choice(templates))

def generate_device_logon_events(num_events, start_time, end_time, output_file):
    total_seconds = (end_time - start_time).total_seconds()
    delta = timedelta(seconds=(total_seconds / num_events))
    with open(output_file, 'w', encoding='utf-8') as f:
        for i in range(num_events):
            event = generate_device_logon_event(i, start_time, delta)
            f.write(json.dumps(event) + "\n")

if __name__ == "__main__":
    days = prompt_for_days()
    events_per_day = 1000  # Adjust as desired
    total_events = days * events_per_day
    
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    output_filename = "device_logon_events.json"
    
    generate_device_logon_events(total_events, start_time, end_time, output_filename)
    print(f"Generated {total_events} device logon events for the past {days} day(s) in '{output_filename}'.")
