# AD-02 Investigation Report: Credential Dumping & Domain Compromise

## 1. Overview

AD-02 is the second investigation in my Active Directory SOC lab series. The objective was to build and validate Splunk detections for suspicious LSASS process access, DCSync-related directory access, and privileged-account activity.

The investigation uses endpoint telemetry from `SOC-LAB-1` and Windows Security events collected from the domain controller `DC01` in the `CORP.LOCAL` lab.

## 2. Environment

- **Domain:** `CORP.LOCAL`
- **Domain Controller:** `DC01`
- **Endpoint:** `SOC-LAB-1`
- **SIEM:** Splunk Enterprise
- **Endpoint telemetry:** Sysmon
- **Primary endpoint event:** Sysmon Event ID 10 — Process Access
- **Primary domain-controller events:** Security Event IDs 4662 and 4672

## 3. Investigation Objectives

- Review Sysmon Event ID 10 events where the target process is `lsass.exe`.
- Separate potentially suspicious LSASS access from selected known process patterns using a risk heuristic.
- Search for Event ID 4662 activity containing Active Directory replication-right GUIDs associated with DCSync investigations.
- Review Event ID 4672 for logons assigned special privileges.
- Present the findings through an AD-02 Splunk dashboard and event-level investigation searches.

## 4. Detection Logic

### 4.1 LSASS Process Access

The LSASS panels search Sysmon Event ID 10 and filter for events whose `TargetImage` ends in or contains `lsass.exe`. The event-level searches expose fields such as:

- Timestamp
- Source host and user
- Source process
- Target process
- `GrantedAccess`
- Target user, when available

Event ID 10 records process access. By itself, it does **not** prove that credentials were read, dumped, or successfully recovered.

### 4.2 High-Risk LSASS Access

The dashboard assigns heuristic risk labels based on the source-process name:

- **HIGH:** `powershell.exe`, `cmd.exe`, and `rundll32.exe`
- **CRITICAL:** process names containing `procdump` or `mimikatz`
- **MEDIUM:** other source processes that remain after the dashboard's exclusions

These labels are triage hints, not conclusive verdicts. Legitimate administrative activity and security tools can also access LSASS, so source process, user, access mask, host context, and surrounding events must be reviewed.

### 4.3 DCSync-Related Activity

The DCSync searches examine Security Event ID 4662 on `DC01` and look for these replication-right GUIDs:

- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`
- `89e95b76-444d-4c62-991a-0facbeda640c`

The exported dashboard excludes the `DC01$` machine account from the matching results. A matching event is treated as a high-priority DCSync-related signal that requires investigation; it is not, by itself, proof that credentials were extracted.

### 4.4 Privileged Account Activity

The dashboard counts Event ID 4672 events from `DC01`, excluding account names ending in `$`. The live event stream also displays selected events such as 4662, 4672, 4624, and 4648 to provide context around directory access, special privileges, successful logons, and explicit credential use.

## 5. Findings and Validation

- The Splunk dashboard contains panels for LSASS access, high-risk LSASS access, DCSync detection, recent DCSync activity, privileged-account activity, recent LSASS events, and a live security event stream.
- A controlled, query-only LSASS process-access test was previously observed on `SOC-LAB-1` as Sysmon Event ID 10, with PowerShell as the source process, `lsass.exe` as the target, and `GrantedAccess` value `0x1000`.
- This test demonstrated process access telemetry and helped validate the LSASS search path. It did **not** demonstrate credential dumping.
- Baseline Event ID 4662 events were observed on `DC01`, including legitimate replication-related activity from `DC01$`.
- After filtering the domain controller machine account, no non-`DC01$` replication-right event was confirmed in the observed time window.
- A synthetic `makeresults` test was used to check the DCSync SPL logic. This validated the query's classification path only; it did **not** create a real Windows Event ID 4662 or prove an actual DCSync attempt.
- The dashboard and event-level SPL searches were organized into separate files for repeatable investigation.

## 6. Limitations

- Successful credential dumping was not demonstrated.
- An attacker-originated DCSync event was not confirmed in the observed telemetry.
- The synthetic SPL test was a logic test, not endpoint or domain-controller evidence.
- Event availability depends on audit policy, Sysmon configuration, forwarding configuration, and the selected Splunk time range.
- The risk labels are heuristic and can produce false positives or false negatives.

## 7. Conclusion

AD-02 produced a Splunk-based investigation workflow for reviewing LSASS process access, DCSync-related directory-access events, and privileged-account activity. The available evidence validates parts of the telemetry and detection workflow, but does not support claiming that credentials were successfully dumped or that an attacker successfully performed DCSync.

**Status:** Dashboard and detection searches documented; successful credential dumping and attacker-originated DCSync remain unverified.

This lab was conducted in an authorized environment for defensive cybersecurity learning and detection engineering.
