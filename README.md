
# Suspected Data Exfiltration Employee


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management has raised concerns that John may be planning to steal proprietary information and then quit the company. Your task is to investigate John's activities on his corporate device (windows-target-1) using Microsoft Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.
---
##  Hypothesis based on threat intelligence and security gaps

John is an administrator on his device and is not limited on which applications he uses. He may try to archive/compress sensitive information and send it to a private drive or something.

## Steps Taken

###  Step 1

I did a search within MDE DeviceFileEvents for any activities with zip files, and found a lot of regular activity of archiving stuff and moving to a “backup” folder

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "windows-target-1" 
| where FileName endswith "zip"
| order by Timestamp desc 
```
<img width="1212" alt="image" src="Screenshot 2025-03-12 125459.png">

---

### Step 2

I took one of the instances of a zip file being created, took the timestamp and searched under DeviceProcessEvents for anything happening 2 minutes before the archive was created and 2 minutes after.I discovered around the same time, a powershell script silently installed 7zip, and then used 7zip to zip up employee data into an archive. 

**Query used to locate event:**

```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-03-12T00:50:00.4847981Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```
<img width="1212" alt="image" src="Screenshot 2025-03-12 130920.png">

---

### Step 3 
I searched around the same time period for any evidence of exfiltration form the network but I didn’t see any logs indicating as such

---

## Summary


T1560: Archive Collected Data

T1059: Command and Scripting Interpreter

T1027: Obfuscated Files or Information

T1047: Windows Management Instrumentation

T1070: Indicator Removal on Host

T1105: Ingress Tool Transfer

T1055: Process Injection

---

## Response Action
I relayed the information to the employees manager, including everything with the archive being created  at regular intervals via powershell script. There didn’t appear to be any evidence of exfiltration.Standing by for further instruction from management.


---
