import json
import random
from datetime import datetime, timedelta
from faker import Faker

# Initialize Faker for realistic fake data
fake = Faker()

# Constant TenantId for all records
TENANT_ID = "d63f3f4b-6e5b-4e10-a8b8-2d7e2a8b5f72"

# A sample list for ActionType choices (for non-nt authority, non govtenant, and non azuread records)
ACTION_TYPES = ['Created', 'Modified', 'Deleted']

# AccountDomain possible choices
ACCOUNT_DOMAINS = ["nt authority", "azuread", "govtenant", "govavd-1", ""]

# Allowed DeviceName options
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

# nt authority specific fields (for ActionType)
NT_AUTHORITY_ACTIONTYPE = {
    "values": [
        "ReadProcessMemoryApiCall",
        "NamedPipeEvent",
        "OpenProcessApiCall"
    ],
    "distribution": {
        "ReadProcessMemoryApiCall": 0.68,
        "NamedPipeEvent": 0.16,
        "OpenProcessApiCall": 0.16
    }
}

# DeviceId values for nt authority
NT_AUTHORITY_DEVICEIDS = [
    "656643b4100353b62fbc2ad5748081dba6ee41b8",
    "8a243ab5100a3b62fbc2ad5748081dba6ee42b9c",
    "b4e541c7201453b62fbc2ad5748081dba6ee43c1",
    "d3f842d8302453b62fbc2ad5748081dba6ee44d2",
    "f1a953e9403453b62fbc2ad5748081dba6ee45e3",
    "c2b064fa504553b62fbc2ad5748081dba6ee46f4"
]

# FileName weighted distribution for nt authority
NT_AUTHORITY_FILENAMES = {
    "lsass.exe": 0.99,
    "services.exe": 0.005,
    "winlogon.exe": 0.0025,
    "svchost.exe": 0.0025,
    "csrss.exe": 0.0025
}

# Realistic folder path options
FOLDER_PATHS = {
    "Windows_System": [
        "C:\\Windows\\System32",
        "C:\\Windows\\System32\\drivers",
        "C:\\Windows\\System32\\Dism",
        "C:\\Windows\\System32\\wbem",
        "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch"
    ],
    "Program_Files": [
        "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\131.0.2903.99",
        "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\131.0.2903.112",
        "C:\\Program Files\\Microsoft RDInfra\\RDMonitoringAgent_46.5.1\\WvdLauncher",
        "C:\\Program Files\\Microsoft RDInfra\\RDMonitoringAgent_46.5.1\\Agent"
    ],
    "ProgramData_Defender": [
        "C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\{049AE4B9-BDBE-4B86-829F-F04BDD5D1E24}",
        "C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\{FDCD252F-9091-44FD-A5B0-851642E24F9B}",
        "C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\{6185ED4D-E876-49F7-92C3-176D909CEB7B}"
    ],
    "User_Directories": [
        "C:\\Users\\Public\\Desktop",
        "C:\\Users\\MichaelCrane\\AppData\\Roaming\\Microsoft\\Windows\\Recent"
    ],
    "WinSxS": [
        "C:\\Windows\\WinSxS\\amd64_microsoft-windows-performancetoolsgui_31bf3856ad364e35_10.0.26100.2454_none_37d045a450f69011",
        "C:\\Windows\\WinSxS\\amd64_microsoft-windows-charmap_31bf3856ad364e35_10.0.26100.2454_none_8e2044d7545dc6e9",
        "C:\\Windows\\WinSxS\\amd64_microsoft-windows-osk_31bf3856ad364e35_10.0.26100.2454_none_46835ae509f15182"
    ]
}

# Realistic InitiatingProcessCommandLine options
COMMAND_LINE_OPTIONS = [
    "MsMpEng.exe",
    "WaAppAgent.exe",
    "pmfexe.exe -PerfMode single -event -quickscan",
    "wmiprvse.exe -secured -Embedding",
    "powershell.exe -ExecutionPolicy AllSigned -NoProfile -NonInteractive -Command \"& {script logic here}\"",
    "powershell.exe -NoProfile -WindowStyle Hidden -Command \"Start-Process notepad.exe\"",
    "updater.exe --server --service=update-internal -Embedding",
    "updater.exe --server --service=update -Embedding",
    "updater.exe --crash-handler --database=C:\\Users\\MichaelCrane\\AppData\\Local\\Google\\GoogleUpdater\\132.0.6833.0\\Crashpad --url=https://clients2.google.com/cr/report",
    "RDAgentBootLoader.exe",
    "notepad.exe",
    "cmd.exe /c dir C:\\",
    "explorer.exe C:\\Users\\Public",
    "taskmgr.exe"
]

# Realistic version information lists
COMPANY_NAMES = [
    "Microsoft Corporation", "Google LLC", "OpenHandleCollector",
    "Microsoft CoreXT", "azgaext", "MicrosoftDnsAgent"
]

FILE_DESCRIPTIONS = [
    "Antimalware Service Executable", "Microsoft Azure", "Windows PowerShell",
    "Google Updater", "Windows Logon Application", "Microsoft Edge WebView2",
    "Windows Explorer", "Microsoft Teams", "Microsoft OneDrive"
]

INTERNAL_FILE_NAMES = [
    "MsMpEng.exe", "WaAppAgent", "PowerShell", "explorer", "msedgewebview2_exe",
    "OfficeClickToRun.exe", "Teams.exe", "SearchIndexer.exe", "OneDrive.exe"
]

ORIGINAL_FILE_NAMES = [
    "MsMpEng.exe", "PowerShell.EXE", "EXPLORER.EXE", "msedgewebview2.exe",
    "OfficeC2RClient.exe", "ms-teams.exe", "SearchIndexer.exe", "OneDriveSetup.exe",
    "MetricsExtension.Native.exe"
]

PRODUCT_NAMES = [
    "Microsoft® Windows® Operating System", "Microsoft Edge", "Google Updater",
    "Microsoft Teams", "Microsoft OneDrive", "Microsoft Edge Update",
    "Microsoft 365 and Office", "Microsoft SharePoint"
]

# New realistic options for additional fields
MACHINE_GROUP_OPTIONS = [
    "Windows Defender ATP", "GCCCloudSecure", "AzureSecurityMonitoring",
    "MSCloudMonitoring", "EnterpriseSecurityGroup"
]

PROCESS_COMMANDLINE_OPTIONS = [
    "C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted",
    "C:\\Windows\\System32\\svchost.exe -k UnistackSvcGroup",
    "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\msedgewebview2.exe --type=renderer",
    "powershell.exe -ExecutionPolicy Bypass -File 'C:\\Scripts\\DefenderScan.ps1'",
    "C:\\Program Files\\Microsoft RDInfra\\RDMonitoringAgent_46.5.1\\Agent\\RDMonitoringAgentLauncher.exe"
]

REGISTRY_VALUE_DATA_OPTIONS = [
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "1",
    "0",
    "Enabled",
    "Disabled",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth",
    "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
]

REGISTRY_VALUE_NAME_OPTIONS = [
    "SecurityHealth",
    "Start",
    "EnableLUA",
    "ConsentPromptBehaviorAdmin",
    "DisableAntiSpyware",
    "TamperProtection",
    "PendingFileRenameOperations"
]

# Helper function to randomly select a folder path from FOLDER_PATHS
def random_folder_path():
    category = random.choice(list(FOLDER_PATHS.keys()))
    return random.choice(FOLDER_PATHS[category])

# Helper function to generate a random SID (for non-overridden records)
def random_sid():
    return "S-1-5-21-" + "-".join(str(random.randint(1000000000, 9999999999)) for _ in range(3))

# Helper functions for hash strings
def random_md5():
    return ''.join(random.choices('0123456789abcdef', k=32))

def random_sha1():
    return ''.join(random.choices('0123456789abcdef', k=40))

def random_sha256():
    return ''.join(random.choices('0123456789abcdef', k=64))

def random_bool():
    return random.choice([True, False])

# Helper for weighted choice
def weighted_choice(weight_dict):
    total = sum(weight_dict.values())
    r = random.uniform(0, total)
    upto = 0
    for item, weight in weight_dict.items():
        if upto + weight >= r:
            return item
        upto += weight
    return None

def prompt_for_days():
    valid_options = ['1', '3', '5']
    while True:
        days_input = input("Enter the number of days for data replication (1, 3, or 5): ").strip()
        if days_input in valid_options:
            return int(days_input)
        else:
            print("Invalid input. Please enter 1, 3, or 5.")

def generate_device_event(event_index, start_time, delta):
    # Compute the sequential event time
    event_time = start_time + (event_index * delta)
    
    # Select AccountDomain from the specified choices.
    account_domain = random.choice(ACCOUNT_DOMAINS)
    
    # Default overrides for fields
    account_name = fake.user_name()
    account_sid = random_sid()
    action_type = random.choice(ACTION_TYPES)
    additional_fields = {}
    # Always force IsProcessRemoteSession to False
    is_process_remote_session = False
    is_initiating_process_remote_session = random_bool()
    event_type = "DeviceEvent"

    # For DeviceId and DeviceName, use defaults
    device_id = fake.uuid4()
    device_name = random.choice(DEVICE_NAME_OPTIONS)
    file_name = fake.file_name()

    # Use realistic folder paths
    folder_path = random_folder_path()
    initiating_process_folder = random_folder_path()

    # Use realistic command line for initiating process (from our predefined list)
    initiating_process_command = random.choice(COMMAND_LINE_OPTIONS)
    
    # Conditional overrides based on AccountDomain
    if account_domain == "govtenant":
        account_name = "adcs$"
        account_sid = "S-1-5-18"
        action_type = "AuditPolicyModificationm"
        additional_fields = {
            "AuditPolicyChanges": "%%8450",
            "CategoryId": "%%8272",
            "SubcategoryGuid": "0cce9211-69ae-11d9-bed3-505054503030",
            "SubcategoryId": "%%12289"
        }
    elif account_domain == "azuread":
        account_name = "janedoe"
        account_sid = "S-1-12-1-1597586183-1127946816-2562028733-1572361970"
        action_type = "NtAllocateVirtualMemoryRemoteApiCall"
        additional_fields = {
            "IntegrityLevel": 4096
        }
    elif account_domain == "nt authority":
        account_name = "system"
        account_sid = "S-1-5-18"
        is_process_remote_session = False
        is_initiating_process_remote_session = False
        event_type = "DeviceEvents"
        action_type = NT_AUTHORITY_ACTIONTYPE
        device_id = random.choice(NT_AUTHORITY_DEVICEIDS)
        device_name = random.choice(DEVICE_NAME_OPTIONS)
        file_name = weighted_choice(NT_AUTHORITY_FILENAMES)
    
    record = {
        "TenantId": TENANT_ID,
        "AccountDomain": account_domain,
        "AccountName": account_name,
        "AccountSid": account_sid,
        "ActionType": action_type,
        "AdditionalFields": additional_fields,
        "AppGuardContainerId": fake.uuid4(),
        "DeviceId": device_id,
        "DeviceName": device_name,
        "FileName": file_name,
        "FileOriginIP": fake.ipv4(),
        "FileOriginUrl": f"http://{fake.domain_name()}/{fake.word()}",
        "FolderPath": folder_path,
        "InitiatingProcessAccountDomain": fake.domain_name(),
        "InitiatingProcessAccountName": fake.user_name(),
        "InitiatingProcessAccountObjectId": fake.uuid4(),
        "InitiatingProcessAccountSid": random_sid(),
        "InitiatingProcessAccountUpn": fake.email(),
        "InitiatingProcessCommandLine": initiating_process_command,
        "InitiatingProcessFileName": fake.file_name(),
        "InitiatingProcessFolderPath": initiating_process_folder,
        "InitiatingProcessId": random.randint(1000, 9999),
        "InitiatingProcessLogonId": random.randint(1000, 9999),
        "InitiatingProcessMD5": random_md5(),
        "InitiatingProcessParentFileName": fake.file_name(),
        "InitiatingProcessParentId": random.randint(1000, 9999),
        "InitiatingProcessSHA1": random_sha1(),
        "InitiatingProcessSHA256": random_sha256(),
        "LocalIP": fake.ipv4(),
        "LocalPort": random.randint(1024, 65535),
        "LogonId": random.randint(1000, 9999),
        "MD5": random_md5(),
        "MachineGroup": random.choice(MACHINE_GROUP_OPTIONS),
        "ProcessCommandLine": random.choice(PROCESS_COMMANDLINE_OPTIONS),
        "ProcessId": random.randint(1000, 9999),
        "ProcessTokenElevation": random_bool(),
        "RegistryKey": f"HKEY_LOCAL_MACHINE\\Software\\{fake.word()}",
        "RegistryValueData": random.choice(REGISTRY_VALUE_DATA_OPTIONS),
        "RegistryValueName": random.choice(REGISTRY_VALUE_NAME_OPTIONS),
        "RemoteDeviceName": random.choice(DEVICE_NAME_OPTIONS),
        "RemoteIP": fake.ipv4(),
        "RemotePort": random.randint(1024, 65535),
        "RemoteUrl": f"http://{fake.domain_name()}/{fake.word()}",
        "ReportId": fake.uuid4(),
        "SHA1": random_sha1(),
        "SHA256": random_sha256(),
        "Timestamp_UTC": event_time.isoformat(),
        "TimeGenerated_UTC": datetime.utcnow().isoformat(),
        "FileSize": random.randint(1000, 10000000),
        "InitiatingProcessCreationTime_UTC": (event_time - timedelta(minutes=random.randint(1, 10))).isoformat(),
        "InitiatingProcessFileSize": random.randint(1000, 10000000),
        "InitiatingProcessParentCreationTime_UTC": (event_time - timedelta(minutes=random.randint(11, 20))).isoformat(),
        "InitiatingProcessVersionInfoCompanyName": random.choice(COMPANY_NAMES),
        "InitiatingProcessVersionInfoFileDescription": random.choice(FILE_DESCRIPTIONS),
        "InitiatingProcessVersionInfoInternalFileName": random.choice(INTERNAL_FILE_NAMES),
        "InitiatingProcessVersionInfoOriginalFileName": random.choice(ORIGINAL_FILE_NAMES),
        "InitiatingProcessVersionInfoProductName": random.choice(PRODUCT_NAMES),
        "ProcessCreationTime_UTC": (event_time - timedelta(minutes=random.randint(1, 5))).isoformat(),
        "CreatedProcessSessionId": random.randint(1000, 9999),
        "IsProcessRemoteSession": is_process_remote_session,
        "ProcessRemoteSessionDeviceName": random.choice(DEVICE_NAME_OPTIONS),
        "ProcessRemoteSessionIP": fake.ipv4(),
        "InitiatingProcessSessionId": random.randint(1000, 9999),
        "IsInitiatingProcessRemoteSession": is_initiating_process_remote_session,
        "InitiatingProcessRemoteSessionDeviceName": random.choice(DEVICE_NAME_OPTIONS),
        "InitiatingProcessRemoteSessionIP": fake.ipv4(),
        "SourceSystem": "Custom",
        "Type": event_type
    }
    return record

def generate_device_events(num_events, start_time, end_time, output_file):
    total_seconds = (end_time - start_time).total_seconds()
    delta = timedelta(seconds=(total_seconds / num_events))
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for i in range(num_events):
            event = generate_device_event(i, start_time, delta)
            json_line = json.dumps(event)
            f.write(json_line + "\n")

if __name__ == "__main__":
    days = prompt_for_days()
    events_per_day = 1000
    total_events = days * events_per_day

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    
    output_filename = "device_events.json"
    generate_device_events(total_events, start_time, end_time, output_filename)
    
    print(f"Generated {total_events} device events for the past {days} day(s) in '{output_filename}'.")
