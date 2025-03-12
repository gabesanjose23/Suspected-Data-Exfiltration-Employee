
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

### 1. Inspecting the logs for excessive successful/failed connections from any devices.  

"windows-target-1" was found failing several connection requests against itself and another host on the same network:

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count()by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```
<img width="1212" alt="image" src="Screenshot 2025-03-11 140302.png">

---

### 2. Investigate the failed connection logs

After observing failed connection request from a suspected host (10.0.0.5) in chronological order, I noticed a port scan was taking place due to the sequential order of the port.There were several port scans being conducted.

**Query used to locate event:**

```kql
let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```
<img width="1212" alt="image" src="Screenshot 2025-03-11 140218.png">

---

### 3. Check out the log event for the port scan 

I pivoted to the DeviceProccessEvent table to see if we could see anything that was suspicious around the time the port scan started.We noticed a PowerShell script named portscan.ps1  launching at:2025-03-11T04:37:00.5366227Z

**Query used to locate events:**

```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-03-11T04:43:48.5646128Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="Screenshot 2025-03-11 140134.png">

---

### 4. Investigate the suspect

I logged into the suspect computer and observed the powershell script that was used to conduct port scan.


<img width="1212" alt="image" src="Screenshot 2025-03-11 140911.png">

---

## Summary


TA0043: Reconnaissance & T1046: Network Service Scanning

TA0002: Execution & T1059: Command and Scripting Interpreter

TA0004: Privilege Escalation & T1078: Valid Accounts

TA0007: Discovery & T1049: System Network Connections Discovery

TA0008: Lateral Movement & T1021: Remote Services

---

## Response Action
We observed the port scan script was launched by the SYSTEM account,this is not expected behavior and is not something that was setup by the admins,so I isolated the device and ran a malware scan.The malware scan produced no result , so out of cation,we kept the device isolated and put in a ticket to have it re-imagine/rebuild.


---
