import json
import random
from datetime import datetime, timedelta
from faker import Faker

# Initialize Faker for realistic fake data
fake = Faker()

# ------------------------
# Constants & Lists
# ------------------------

TENANT_ID = "d63f3f4b-6e5b-4e10-a8b8-2d7e2a8b5f72"

# AccountDomain choices
ACCOUNT_DOMAINS = ["nt authority", "azuread", "govtenant", "govavd-1", ""]

# Device names (shared with DeviceEvents)
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

# For nt authority, specific device IDs
NT_AUTHORITY_DEVICEIDS = [
    "656643b4100353b62fbc2ad5748081dba6ee41b8",
    "8a243ab5100a3b62fbc2ad5748081dba6ee42b9c",
    "b4e541c7201453b62fbc2ad5748081dba6ee43c1",
    "d3f842d8302453b62fbc2ad5748081dba6ee44d2",
    "f1a953e9403453b62fbc2ad5748081dba6ee45e3",
    "c2b064fa504553b62fbc2ad5748081dba6ee46f4"
]

# Folder paths for file events
FILE_FOLDER_PATHS = [
    "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Results\\Quick",
    "C:\\Windows\\System32",
    "C:\\Users\\Public\\Desktop",
    "C:\\Program Files\\Microsoft Teams",
    "C:\\Users\\Administrator\\Downloads",
    "C:\\Windows\\Temp",
    "C:\\Users\\janedoe\\AppData\\Roaming\\Microsoft\\Windows\\Recent"
]

# File event action types
FILE_EVENT_ACTIONS = [
    "FileCreated", "FileDeleted", "FileModified", "FileRenamed", "FileRead"
]

# Realistic file names
FILE_NAMES = [
    "WindowsDefender.log", "MsMpEng.exe", "SecurityHealthService.exe", "explorer.exe",
    "notepad.exe", "chrome.exe", "Teams.exe", "OneDriveSetup.exe", "taskmgr.exe"
]

# Initiating process file names and command lines
INIT_PROCESS_FILE_NAMES = [
    "MsMpEng.exe", "explorer.exe", "powershell.exe", "cmd.exe", "svchost.exe",
    "taskmgr.exe", "chrome.exe", "Teams.exe", "OneDrive.exe"
]

INIT_PROCESS_COMMAND_LINES = [
    "cmd.exe /c del C:\\Users\\Public\\test.txt",
    "powershell.exe -Command Remove-Item -Path 'C:\\Temp\\malware.exe' -Force",
    "explorer.exe C:\\Users\\Public\\Desktop",
    "notepad.exe C:\\Windows\\System32\\drivers\\etc\\hosts",
    "msedge.exe --profile-directory=Default --app-id=hmmclmdkeigohiagmbokmcliblcfaocm"
]

# Machine group options
MACHINE_GROUP_OPTIONS = [
    "Windows Defender ATP", "GCCCloudSecure", "AzureSecurityMonitoring",
    "MSCloudMonitoring", "EnterpriseSecurityGroup"
]

# Process command line options (for the process that performed the file event)
PROCESS_COMMANDLINE_OPTIONS = [
    "C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted",
    "C:\\Windows\\System32\\svchost.exe -k UnistackSvcGroup",
    "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\msedgewebview2.exe --type=renderer",
    "powershell.exe -ExecutionPolicy Bypass -File 'C:\\Scripts\\DefenderScan.ps1'",
    "C:\\Program Files\\Microsoft RDInfra\\RDMonitoringAgent_46.5.1\\Agent\\RDMonitoringAgentLauncher.exe"
]

# Version information for initiating process
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

# ------------------------
# Columns to Return Empty
# ------------------------
# The following columns are to be returned as empty strings:
# AppGuardContainerId, FileOriginIP, FileOriginReferrerUrl, FileOriginUrl,
# InitiatingProcessAccountObjectId, IsAzureInfoProtectionApplied,
# RequestAccountDomain, RequestAccountName, RequestAccountSid, RequestProtocol,
# RequestSourceIP, RequestSourcePort, SensitivityLabel, SensitivitySubLabel,
# ShareName, SourceSystem

# ------------------------
# Helper Functions
# ------------------------

def random_folder_path_from_list(path_list):
    return random.choice(path_list)

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
# DeviceFileEvents Generation
# ------------------------

def generate_device_file_event(event_index, start_time, delta):
    # Compute sequential event timestamp
    event_time = start_time + (event_index * delta)
    
    # -- Account & Device Fields --
    account_domain = random.choice(ACCOUNT_DOMAINS)
    account_name = fake.user_name()
    account_sid = random_sid()
    file_event_action = random.choice(FILE_EVENT_ACTIONS)
    
    # Conditional overrides for special account domains
    if account_domain == "govtenant":
        account_name = "adcs$"
        account_sid = "S-1-5-18"
        file_event_action = random.choice(FILE_EVENT_ACTIONS)
    elif account_domain == "azuread":
        account_name = "janedoe"
        account_sid = "S-1-12-1-1597586183-1127946816-2562028733-1572361970"
        file_event_action = random.choice(FILE_EVENT_ACTIONS)
    elif account_domain == "nt authority":
        account_name = "system"
        account_sid = "S-1-5-18"
        file_event_action = "FileRead"
    
    if account_domain == "nt authority":
        device_id = random.choice(NT_AUTHORITY_DEVICEIDS)
    else:
        device_id = fake.uuid4()
    device_name = random.choice(DEVICE_NAME_OPTIONS)
    
    # -- File Fields --
    file_name = random.choice(FILE_NAMES)
    folder_path = random.choice(FILE_FOLDER_PATHS)
    # FilePath is constructed but not returned as a separate column per instructions.
    file_size = random.randint(1000, 10000000)
    file_hash_md5 = random_md5()
    file_hash_sha1 = random_sha1()
    file_hash_sha256 = random_sha256()
    
    # -- Process Fields --
    process_command_line = random.choice(PROCESS_COMMANDLINE_OPTIONS)
    process_id = random.randint(1000, 9999)
    machine_group = random.choice(MACHINE_GROUP_OPTIONS)
    
    # -- Initiating Process Fields --
    init_proc_file_name = random.choice(INIT_PROCESS_FILE_NAMES)
    init_proc_command_line = random.choice(INIT_PROCESS_COMMAND_LINES)
    initiating_process_folder = random_folder_path_from_list(FILE_FOLDER_PATHS)
    initiating_process_id = random.randint(1000, 9999)
    initiating_process_integrity = random.choice([4096, 8192, 12288])
    initiating_process_md5 = random_md5()
    initiating_process_parent_file_name = fake.file_name()
    initiating_process_parent_id = random.randint(1000, 9999)
    initiating_process_sha1 = random_sha1()
    initiating_process_sha256 = random_sha256()
    initiating_process_token_elevation = False
    initiating_process_creation_time = (event_time - timedelta(minutes=random.randint(1, 10))).isoformat()
    initiating_process_parent_creation_time = (event_time - timedelta(minutes=random.randint(11, 20))).isoformat()
    initiating_process_file_size = random.randint(1000, 10000000)
    initiating_process_session_id = random.randint(1000, 9999)
    is_initiating_process_remote = random.choice([True, False])
    initiating_process_remote_device = random.choice(DEVICE_NAME_OPTIONS)
    initiating_process_remote_ip = fake.ipv4()
    
    # Version Information for initiating process
    init_proc_version_company = random.choice(COMPANY_NAMES)
    init_proc_version_file_desc = random.choice(FILE_DESCRIPTIONS)
    init_proc_version_internal_file = random.choice(INTERNAL_FILE_NAMES)
    init_proc_version_original_file = random.choice(ORIGINAL_FILE_NAMES)
    init_proc_version_product_name = random.choice(PRODUCT_NAMES)
    init_proc_version_product_ver = f"v{random.randint(1,10)}.{random.randint(0,9)}"
    
    # ------------------------
    # Build the Complete Record (62 columns)
    # ------------------------
    record = {
        "TenantId": TENANT_ID,
        "ActionType": file_event_action,
        "AdditionalFields": "",
        "AppGuardContainerId": "",
        "DeviceId": device_id,
        "DeviceName": device_name,
        "FileName": file_name,
        "FileOriginIP": "",
        "FileOriginReferrerUrl": "",
        "FileOriginUrl": "",
        "FileSize": file_size,
        "FolderPath": folder_path,
        "InitiatingProcessAccountDomain": fake.domain_name(),
        "InitiatingProcessAccountName": fake.user_name(),
        "InitiatingProcessAccountObjectId": "",
        "InitiatingProcessAccountSid": random_sid(),
        "InitiatingProcessAccountUpn": fake.email(),
        "InitiatingProcessCommandLine": init_proc_command_line,
        "InitiatingProcessFileName": init_proc_file_name,
        "InitiatingProcessFolderPath": initiating_process_folder,
        "InitiatingProcessId": initiating_process_id,
        "InitiatingProcessIntegrityLevel": initiating_process_integrity,
        "InitiatingProcessMD5": initiating_process_md5,
        "InitiatingProcessParentFileName": initiating_process_parent_file_name,
        "InitiatingProcessParentId": initiating_process_parent_id,
        "InitiatingProcessSHA1": initiating_process_sha1,
        "InitiatingProcessSHA256": initiating_process_sha256,
        "InitiatingProcessTokenElevation": initiating_process_token_elevation,
        "IsAzureInfoProtectionApplied": "",
        "MD5": file_hash_md5,
        "MachineGroup": machine_group,
        "PreviousFileName": "",
        "PreviousFolderPath": "",
        "ReportId": fake.uuid4(),
        "RequestAccountDomain": "",
        "RequestAccountName": "",
        "RequestAccountSid": "",
        "RequestProtocol": "",
        "RequestSourceIP": "",
        "RequestSourcePort": "",
        "SHA1": file_hash_sha1,
        "SHA256": file_hash_sha256,
        "SensitivityLabel": "",
        "SensitivitySubLabel": "",
        "ShareName": "",
        "Timestamp [UTC]": event_time.isoformat(),
        "TimeGenerated [UTC]": datetime.utcnow().isoformat(),
        "InitiatingProcessParentCreationTime [UTC]": initiating_process_parent_creation_time,
        "InitiatingProcessCreationTime [UTC]": initiating_process_creation_time,
        "InitiatingProcessFileSize": initiating_process_file_size,
        "InitiatingProcessVersionInfoCompanyName": init_proc_version_company,
        "InitiatingProcessVersionInfoFileDescription": init_proc_version_file_desc,
        "InitiatingProcessVersionInfoInternalFileName": init_proc_version_internal_file,
        "InitiatingProcessVersionInfoOriginalFileName": init_proc_version_original_file,
        "InitiatingProcessVersionInfoProductName": init_proc_version_product_name,
        "InitiatingProcessVersionInfoProductVersion": init_proc_version_product_ver,
        "InitiatingProcessSessionId": initiating_process_session_id,
        "IsInitiatingProcessRemoteSession": is_initiating_process_remote,
        "InitiatingProcessRemoteSessionDeviceName": initiating_process_remote_device,
        "InitiatingProcessRemoteSessionIP": initiating_process_remote_ip,
        "SourceSystem": "",
        "Type": "DeviceFileEvent"
    }
    # Rename keys that contain spaces/brackets for ADX mapping compatibility
    # Replace "Timestamp [UTC]" -> "Timestamp_UTC"
    # Replace "TimeGenerated [UTC]" -> "TimeGenerated_UTC"
    # Replace "InitiatingProcessParentCreationTime [UTC]" -> "InitiatingProcessParentCreationTime_UTC"
    # Replace "InitiatingProcessCreationTime [UTC]" -> "InitiatingProcessCreationTime_UTC"
    record["Timestamp_UTC"] = record.pop("Timestamp [UTC]")
    record["TimeGenerated_UTC"] = record.pop("TimeGenerated [UTC]")
    record["InitiatingProcessParentCreationTime_UTC"] = record.pop("InitiatingProcessParentCreationTime [UTC]")
    record["InitiatingProcessCreationTime_UTC"] = record.pop("InitiatingProcessCreationTime [UTC]")
    
    return record

def generate_device_file_events(num_events, start_time, end_time, output_file):
    total_seconds = (end_time - start_time).total_seconds()
    delta = timedelta(seconds=(total_seconds / num_events))
    with open(output_file, 'w', encoding='utf-8') as f:
        for i in range(num_events):
            event = generate_device_file_event(i, start_time, delta)
            f.write(json.dumps(event) + "\n")

if __name__ == "__main__":
    days = prompt_for_days()
    events_per_day = 1000  # Adjust as needed for simulation size
    total_events = days * events_per_day

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    output_filename = "device_file_events.json"
    
    generate_device_file_events(total_events, start_time, end_time, output_filename)
    print(f"Generated {total_events} device file events for the past {days} day(s) in '{output_filename}'.")
