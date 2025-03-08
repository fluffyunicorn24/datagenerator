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
# Field Option Lists & Constants for DeviceProcessEvents
# ------------------------
FILE_NAMES = ["(blank)", "busybox", "conhost.exe", "powershell.exe", "ps"]
FOLDER_PATHS = ["(blank)", "/bin/busybox", "C:\\Windows\\System32\\conhost.exe"]
MACHINE_GROUP_OPTIONS = ["ModernWork - Semi automation", "UnassignedGroup"]

VERSION_COMPANIES = ["Microsoft Corporation", "Windows (R) Win 7 DDK provider", "Microsoft CoreXT"]
VERSION_PRODUCTS = ["Windows"]

COMMAND_LINES = [
    "(blank)",
    "/bin/sh -c 'kill -2 2099014'"
]

# ------------------------
# Helper Functions
# ------------------------
def random_sid():
    return "S-1-5-21-" + "-".join(str(random.randint(1000000000, 9999999999)) for _ in range(3))

def random_hex(n):
    return ''.join(random.choices('0123456789abcdef', k=n))

def maybe_blank(value, blank_prob=0.2):
    return "" if random.random() < blank_prob else value

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

# ------------------------
# Generate DeviceProcessEvent Record
# ------------------------
def generate_device_process_event(event_index, start_time, delta):
    event_time = start_time + (event_index * delta)
    record = OrderedDict()
    
    # 1. TenantId
    record["TenantId"] = TENANT_ID
    
    # 2. AccountDomain (always global domain)
    record["AccountDomain"] = DOMAIN
    
    # 3. AccountName (from global list)
    record["AccountName"] = random.choice(ACCOUNT_NAMES)
    
    # 4. AccountObjectId (completely blank)
    record["AccountObjectId"] = ""
    
    # 5. AccountSid
    record["AccountSid"] = random_sid()
    
    # 6. AccountUpn (blank)
    record["AccountUpn"] = ""
    
    # 7. ActionType – choose among process events.
    record["ActionType"] = random.choice(["ProcessCreated", "ProcessTerminated", "ProcessModified"])
    
    # 8. AdditionalFields – may be blank sometimes.
    record["AdditionalFields"] = maybe_blank("{}", 0.3)
    
    # 9. AppGuardContainerId (blank)
    record["AppGuardContainerId"] = ""
    
    # 10. DeviceId
    record["DeviceId"] = str(fake.uuid4())
    
    # 11. DeviceName (from global device list)
    record["DeviceName"] = random.choice(DEVICE_NAME_OPTIONS)
    
    # 12-14. FileName, FolderPath, FileSize – populated only if ActionType is "ProcessCreated"
    if record["ActionType"] == "ProcessCreated":
        record["FileName"] = random.choice(FILE_NAMES)
        record["FolderPath"] = random.choice(FOLDER_PATHS)
        record["FileSize"] = random.choice([0.0, round(random.uniform(47104.0, 446976.0), 1)])
    else:
        record["FileName"] = ""
        record["FolderPath"] = ""
        record["FileSize"] = ""
    
    # 15-19. InitiatingProcessAccountDomain, AccountName, AccountObjectId, AccountSid, AccountUpn
    # These are populated with valid metadata 70% of the time; otherwise, blank.
    if random.random() < 0.7:
        record["InitiatingProcessAccountDomain"] = random.choice(["nt authority", "fluffzU"])
        record["InitiatingProcessAccountName"] = random.choice(["root", "system", "network service"])
        record["InitiatingProcessAccountObjectId"] = ""  # always blank
        record["InitiatingProcessAccountSid"] = random.choice(["(blank)", "S-1-5-18", "S-1-5-20"])
        record["InitiatingProcessAccountUpn"] = ""  # blank
    else:
        record["InitiatingProcessAccountDomain"] = ""
        record["InitiatingProcessAccountName"] = ""
        record["InitiatingProcessAccountObjectId"] = ""
        record["InitiatingProcessAccountSid"] = ""
        record["InitiatingProcessAccountUpn"] = ""
    
    # 20. InitiatingProcessCommandLine – if valid metadata then fill; else blank.
    record["InitiatingProcessCommandLine"] = random.choice(COMMAND_LINES) if record["InitiatingProcessAccountName"] != "" else ""
    
    # 21. InitiatingProcessFileName – if command line exists, then fill; else blank.
    record["InitiatingProcessFileName"] = random.choice(FILE_NAMES) if record["InitiatingProcessCommandLine"] != "" else ""
    
    # 22. InitiatingProcessFolderPath – if file name exists then choose; else blank.
    record["InitiatingProcessFolderPath"] = random.choice(FOLDER_PATHS) if record["InitiatingProcessFileName"] != "" else ""
    
    # 23. InitiatingProcessId – random int if file name exists; else blank.
    record["InitiatingProcessId"] = random.randint(1000, 9999) if record["InitiatingProcessFileName"] != "" else ""
    
    # 24. InitiatingProcessIntegrityLevel – populated if metadata available.
    record["InitiatingProcessIntegrityLevel"] = random.choice(["System"]) if record["InitiatingProcessFileName"] != "" and random.random() < 0.5 else ""
    
    # 25. InitiatingProcessLogonId – if initiating process metadata exists.
    record["InitiatingProcessLogonId"] = random.randint(1000, 9999) if record["InitiatingProcessAccountDomain"] != "" else ""
    
    # 26. InitiatingProcessMD5 – if file exists.
    record["InitiatingProcessMD5"] = random_hex(32) if record["InitiatingProcessFileName"] != "" else ""
    
    # 27. InitiatingProcessParentFileName – may be blank.
    record["InitiatingProcessParentFileName"] = maybe_blank(fake.file_name(), 0.3) if record["InitiatingProcessFileName"] != "" else ""
    
    # 28. InitiatingProcessParentId – random int if file exists.
    record["InitiatingProcessParentId"] = random.randint(1000, 9999) if record["InitiatingProcessFileName"] != "" else ""
    
    # 29. InitiatingProcessSHA1 – if file exists.
    record["InitiatingProcessSHA1"] = random_hex(40) if record["InitiatingProcessFileName"] != "" else ""
    
    # 30. InitiatingProcessSHA256 – if file exists.
    record["InitiatingProcessSHA256"] = random_hex(64) if record["InitiatingProcessFileName"] != "" else ""
    
    # 31. InitiatingProcessTokenElevation – if file exists.
    record["InitiatingProcessTokenElevation"] = random.choice([True, False]) if record["InitiatingProcessFileName"] != "" else ""
    
    # 32. InitiatingProcessFileSize – if file exists.
    record["InitiatingProcessFileSize"] = random.randint(1000, 1000000) if record["InitiatingProcessFileName"] != "" else ""
    
    # 33. InitiatingProcessVersionInfoCompanyName – if file exists.
    record["InitiatingProcessVersionInfoCompanyName"] = random.choice(VERSION_COMPANIES) if record["InitiatingProcessFileName"] != "" else ""
    
    # 34. InitiatingProcessVersionInfoProductName – if file exists.
    record["InitiatingProcessVersionInfoProductName"] = random.choice(VERSION_PRODUCTS) if record["InitiatingProcessFileName"] != "" else ""
    
    # 35. InitiatingProcessVersionInfoProductVersion – if file exists.
    record["InitiatingProcessVersionInfoProductVersion"] = f"v{random.randint(1,10)}.{random.randint(0,9)}" if record["InitiatingProcessFileName"] != "" else ""
    
    # 36. InitiatingProcessVersionInfoInternalFileName – maybe blank.
    record["InitiatingProcessVersionInfoInternalFileName"] = maybe_blank(fake.file_name(), 0.3) if record["InitiatingProcessFileName"] != "" else ""
    
    # 37. InitiatingProcessVersionInfoOriginalFileName – maybe blank.
    record["InitiatingProcessVersionInfoOriginalFileName"] = maybe_blank(fake.file_name(), 0.3) if record["InitiatingProcessFileName"] != "" else ""
    
    # 38. InitiatingProcessVersionInfoFileDescription – maybe blank.
    record["InitiatingProcessVersionInfoFileDescription"] = maybe_blank(fake.sentence(nb_words=6), 0.3) if record["InitiatingProcessFileName"] != "" else ""
    
    # 39. LogonId
    record["LogonId"] = random.randint(1000, 9999)
    
    # 40. MD5 – for process event, if FileName exists.
    record["MD5"] = random_hex(32) if record["FileName"] != "" else ""
    
    # 41. MachineGroup
    record["MachineGroup"] = random.choice(MACHINE_GROUP_OPTIONS)
    
    # 42. ProcessCommandLine – populated only if FileName exists.
    record["ProcessCommandLine"] = random.choice(COMMAND_LINES) if record["FileName"] != "" else ""
    
    # 43. ProcessCreationTime_UTC – if FileName exists.
    record["ProcessCreationTime_UTC"] = fake.date_time_between(start_date="-30d", end_date="now").isoformat() if record["FileName"] != "" else ""
    
    # 44. ProcessId
    record["ProcessId"] = random.randint(1000, 9999) if record["FileName"] != "" else ""
    
    # 45. ProcessIntegrityLevel
    record["ProcessIntegrityLevel"] = random.choice([4096, 8192, 12288]) if record["FileName"] != "" else ""
    
    # 46. ProcessTokenElevation
    record["ProcessTokenElevation"] = random.choice([True, False]) if record["FileName"] != "" else ""
    
    # 47. ProcessVersionInfoCompanyName
    record["ProcessVersionInfoCompanyName"] = random.choice(VERSION_COMPANIES) if record["FileName"] != "" else ""
    
    # 48. ProcessVersionInfoProductName
    record["ProcessVersionInfoProductName"] = random.choice(VERSION_PRODUCTS) if record["FileName"] != "" else ""
    
    # 49. ProcessVersionInfoProductVersion
    record["ProcessVersionInfoProductVersion"] = f"v{random.randint(1,10)}.{random.randint(0,9)}" if record["FileName"] != "" else ""
    
    # 50. ProcessVersionInfoInternalFileName – maybe blank.
    record["ProcessVersionInfoInternalFileName"] = maybe_blank(fake.file_name(), 0.3) if record["FileName"] != "" else ""
    
    # 51. ProcessVersionInfoOriginalFileName – maybe blank.
    record["ProcessVersionInfoOriginalFileName"] = maybe_blank(fake.file_name(), 0.3) if record["FileName"] != "" else ""
    
    # 52. ProcessVersionInfoFileDescription – maybe blank.
    record["ProcessVersionInfoFileDescription"] = maybe_blank(fake.sentence(nb_words=6), 0.3) if record["FileName"] != "" else ""
    
    # 53. InitiatingProcessSignerType
    record["InitiatingProcessSignerType"] = random.choice(["Signed", "Unsigned", "Unknown"]) if record["FileName"] != "" else ""
    
    # 54. InitiatingProcessSignatureStatus
    record["InitiatingProcessSignatureStatus"] = random.choice(["Valid", "Invalid", "NotSigned"]) if record["FileName"] != "" else ""
    
    # 55. ReportId
    record["ReportId"] = str(fake.uuid4())
    
    # 56. SHA1
    record["SHA1"] = random_hex(40) if record["FileName"] != "" else ""
    
    # 57. SHA256
    record["SHA256"] = random_hex(64) if record["FileName"] != "" else ""
    
    # 58. TimeGenerated_UTC (current UTC time)
    record["TimeGenerated_UTC"] = datetime.utcnow().isoformat()
    
    # 59. Timestamp_UTC (event time)
    record["Timestamp_UTC"] = event_time.isoformat()
    
    # 60. InitiatingProcessParentCreationTime_UTC
    iparent_creation = fake.date_time_between(start_date="-30d", end_date="now")
    record["InitiatingProcessParentCreationTime_UTC"] = iparent_creation.isoformat() if record["InitiatingProcessFileName"] != "" else ""
    
    # 61. InitiatingProcessCreationTime_UTC (simulate same as parent creation)
    record["InitiatingProcessCreationTime_UTC"] = iparent_creation.isoformat() if record["InitiatingProcessFileName"] != "" else ""
    
    # 62. CreatedProcessSessionId
    record["CreatedProcessSessionId"] = str(fake.uuid4())
    
    # 63. IsProcessRemoteSession
    record["IsProcessRemoteSession"] = random.choice([True, False])
    
    # 64. ProcessRemoteSessionDeviceName (always blank)
    record["ProcessRemoteSessionDeviceName"] = ""
    
    # 65. ProcessRemoteSessionIP (always blank)
    record["ProcessRemoteSessionIP"] = ""
    
    # 66. InitiatingProcessSessionId
    record["InitiatingProcessSessionId"] = str(fake.uuid4())
    
    # 67. IsInitiatingProcessRemoteSession
    record["IsInitiatingProcessRemoteSession"] = random.choice([True, False])
    
    # 68. InitiatingProcessRemoteSessionDeviceName (always blank)
    record["InitiatingProcessRemoteSessionDeviceName"] = ""
    
    # 69. InitiatingProcessRemoteSessionIP (always blank)
    record["InitiatingProcessRemoteSessionIP"] = ""
    
    # 70. SourceSystem (completely blank)
    record["SourceSystem"] = ""
    
    # 71. Type
    record["Type"] = "DeviceProcessEvents"
    
    return record

def generate_device_process_events(num_events, start_time, end_time, output_file):
    total_seconds = (end_time - start_time).total_seconds()
    delta = timedelta(seconds=(total_seconds / num_events))
    with open(output_file, 'w', encoding='utf-8') as f:
        for i in range(num_events):
            event = generate_device_process_event(i, start_time, delta)
            f.write(json.dumps(event) + "\n")

if __name__ == "__main__":
    days = prompt_for_days()
    events_per_day = 1000  # Adjust as needed
    total_events = days * events_per_day
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)
    output_filename = "device_process_events.json"
    generate_device_process_events(total_events, start_time, end_time, output_filename)
    print(f"Generated {total_events} device process events for the past {days} day(s) in '{output_filename}'.")
