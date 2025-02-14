# Threat Hunting: Investigating Internet-Exposed Devices

## Introduction/Objectives
In this project, I conducted a comprehensive threat-hunting investigation focused on identifying and analyzing malicious activity targeting internet-exposed devices. The primary objective was to detect unauthorized access attempts, assess the extent of brute-force attacks, and evaluate the effectiveness of security controls within a virtualized environment. This research was carried out using Microsoft Defender for Endpoint (MDE) and Kusto Query Language (KQL) within a Microsoft Azure-hosted virtual machine.

## Components, Tools, and Technologies Employed
- **Cloud Environment:** Microsoft Azure (VM-hosted threat-hunting lab)
- **Threat Detection Platform:** Microsoft Defender for Endpoint (MDE)
- **Query Language:** Kusto Query Language (KQL) for log analysis

## Disclaimer
I am operating in a shared learning environment hosted within the same Microsoft Azure subscription. As a result, private IP addresses appearing in failed logon attempt logs may include values related to internal testing activities. The term "bad actors" in this project refers strictly to remote IP addresses originating from external, unauthorized sources. These actors are identified as entities attempting unauthorized access to the virtual machine without any association with the Azure subscription or corporate environment.

## Scenario
A virtual machine, **windows-target-1**, was left exposed to the public internet to observe and analyze real-world threats. Over several weeks, multiple remote IPs made repeated unauthorized login attempts, exhibiting clear patterns of brute-force attacks. This investigation aims to determine whether any of these attempts resulted in successful compromise, identify attacker techniques, and propose mitigation strategies to enhance system security.

## High-Level IoC Discovery Plan
1. **Identify Internet-Facing Devices**: Query logs to list devices currently exposed to the internet.
2. **Analyze Failed Logon Attempts**: Detect anomalous login attempts from remote IPs.
3. **Correlate IP Activity**: Compare failed logins across different account names and attack patterns.
4. **Investigate Potential Brute-Force Successes**: Identify whether unauthorized access was achieved.
5. **Assess System Logs for Persistence Techniques**: Look for indicators of post-compromise activity.
6. **Map Observations to the MITRE ATT&CK Framework**: Classify attack techniques for deeper analysis.

## Steps Taken
### STEP 1: Identifying Internet-Facing Devices
There are a total of **18 virtual machines** currently exposed to the public internet. After initial analysis, **17 virtual machines** were confirmed to be safe and isolated. The focus of this investigation is on the remaining **target virtual machine, "windows-target-1"**.

**KQL Query Used:**
```kql
DeviceInfo
| where IsInternetFacing == True
| where Timestamp >= ago(30d)
| order by Timestamp asc
| distinct DeviceName
| summarize count()
```
![image](https://github.com/user-attachments/assets/ec5b1368-e46f-4289-9c6d-fdbf40942b20)


### STEP 2: Duration of Exposure for Windows-Target-1
The device has been exposed to the public internet for more than a month by now
**KQL Query Used:**
```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == True
| order by Timestamp desc
```
Last Internet-Facing time: **Jan 6, 2025 4:15:03 PM**
![image](https://github.com/user-attachments/assets/80c7a551-d4ba-42c8-a0cb-c2ae4a0a7595)

### STEP 3: Identifying Malicious Logon Attempts
Over 100 failed logon attempts were detected from numerous remote IPs.
**KQL Query Used:**
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
![image](https://github.com/user-attachments/assets/a8f263cb-2443-4698-800d-5e04a05bc4fa)


### STEP 4: Brute Force Attempts and Account Name Variations
A remote IP (**92.63.197.***) made **142** failed logon attempts, constantly changing account names.
**KQL Query Used:**
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName, AccountName
| where RemoteIP contains "92.63.197"
| order by Attempts desc
```
![image](https://github.com/user-attachments/assets/c326f1a3-7824-42b9-a6a6-097fdfd957e8)

### STEP 5: Failed and Successful Logon Correlation
A malicious actor using **RemoteIP 194.180.48.11** attempted logins with different account names. The query below identifies failed logon attempts and correlates them with successful logins.
**KQL Query Used:**
```kql
let FailedLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| where DeviceName == "windows-target-1"
| summarize FailedLogonAttempts = count() by RemoteIP, DeviceName, AccountName
| order by FailedLogonAttempts;
let SuccessfulLogons =  DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| summarize SuccessfulLogons = count() by RemoteIP, DeviceName, AccountName;
FailedLogons
| join kind=leftouter SuccessfulLogons on RemoteIP
| project RemoteIP, DeviceName, FailedLogonAttempts = coalesce(FailedLogonAttempts, 0), SuccessfulLogons = coalesce(SuccessfulLogons, 0), AccountName
```
![image](https://github.com/user-attachments/assets/6cd5a1e9-f421-464d-948e-3316fed7a8f5)


### STEP 6: Remote IPs with Most Failed Logons And No Successful Attempts
**KQL Query Used:**
```kql
let RemoteIPsInQuestion = dynamic(["92.63.197.55","194.0.234.49", "77.90.185.225", "194.180.48.11", "45.151.99.126"]);
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
| summarize Attempts = count() by RemoteIP, DeviceName
| order by Attempts desc
```
![image](https://github.com/user-attachments/assets/960e3c95-32c2-447a-9f83-44de31c62054)

### STEP 7: Only Successful Logons 
The only successful logon for the last 30 days was the “labuser” account and similar common identifiers. I’ve checked the logs associated with no RemoteIP and verified that they are system related activities. There were also no failed logon attempts for the labuser account, indicating that a brute force attempt did not take place for this account and a 1-time password is unlikely.
**KQL query used:**
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| summarize Attempts = count() by RemoteIP, DeviceName, AccountName
| order by Attempts desc
```

### STEP 8: No Unauthorized Successes
No unauthorized logins were detected. The only successful logons in the past **30 days** were from legitimate accounts (**labuser**), commonly used within the Azure subscription.

## Tactics, Techniques, and Procedures (TTPs) from MITRE ATT&CK Framework
- **T1071** - Application Layer Protocol: Remote access attempts over RDP
- **T1071.001** - Application Layer Protocol: RDP brute-force attempts
- **T1110** - Brute Force: Multiple failed login attempts
- **T1110.001** - Brute Force: Password Guessing
- **T1070.003** - Indicator Removal on Host: Erasing failed logon logs

## Response Actions
- **Hardened the NSG for windows-target-1**: Restricted RDP traffic to specific endpoints.
- **Implemented Account Lockout Policies**: Prevented repeated failed logon attempts.
- **Enabled Multi-Factor Authentication (MFA)**: Enhanced security for legitimate users.

This project highlights the importance of continuous monitoring, proactive threat hunting, and the implementation of robust security controls to prevent unauthorized access in cloud environments.

