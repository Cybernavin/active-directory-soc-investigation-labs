# AD-03 Investigation Report: Lateral Movement & Privilege Escalation

## 1. Overview

AD-03 is the third investigation in my Active Directory SOC lab series. The objective was to build and review Splunk searches for authentication and remote-access activity that may be relevant to lateral movement and privilege escalation.

The investigation focuses on Windows Security events from the `CORP.LOCAL` lab, using `DC01` as the domain controller and `SOC-LAB-1` as the client endpoint.

## 2. Environment

- **Domain:** `CORP.LOCAL`
- **Domain Controller:** `DC01`
- **Client endpoint:** `SOC-LAB-1`
- **SIEM:** Splunk Enterprise
- **Primary index for DC events:** `AD-DC-01`
- **Client-side index:** `main`

## 3. Objectives

- Monitor successful RDP logons using Event ID `4624` with Logon Type `10`.
- Review SMB activity using Event IDs `5140` and `5145`.
- Identify service installation events using Event ID `7045`.
- Investigate explicit-credential activity using Event ID `4648`.
- Combine relevant events into recent-activity and live-event dashboard panels.

## 4. Detection Coverage

### 4.1 RDP Logons — Event ID 4624, Logon Type 10

The dashboard filters successful logons to Logon Type `10`, which represents a Remote Interactive logon. A matching event should be investigated with its source address, target host, account, and surrounding activity.

**Observed result:** The dashboard showed `0` RDP logons for the selected time range. This does not prove that RDP activity never occurred.

### 4.2 SMB Activity — Event IDs 5140 and 5145

These searches count SMB share-access and detailed share-access-check events. The detail searches attempt to expose the user, source address, share name, and relative target name where available.

**Observed result:** The dashboard screenshot showed `0` for the SMB panel at that point in time. Results depend on audit configuration, event forwarding, and the selected time range.

### 4.3 Remote Service — Event ID 7045

This panel counts service-installation events. Event ID `7045` can be relevant when investigating remote service creation, but legitimate software installation can generate it too.

**Observed result:** The dashboard showed `0` matching events for the selected time range.

### 4.4 Explicit Credential Use — Event ID 4648

The client endpoint's Security log contained Event ID `4648` records, and Splunk confirmed two events with:

```spl
index=main host=SOC-LAB-1 EventCode=4648
| stats count
```

The event detail search exposed fields including the subject account, process name, target server, and network address. A local event included `Ajit.Yadav` under “Account Whose Credentials Were Used,” with `localhost` as the target server and `lsass.exe` as the process. Other events involved Windows system accounts and processes.

These are explicit-credential activity records, but they do not establish that credentials were successfully used to log on to a remote host. The `Subject` account and the “Account Whose Credentials Were Used” field must be treated as separate identities.

### 4.5 Recent Lateral Movement and Live Security Event Stream

These panels combine selected events such as `4624`, `4648`, `5140`, `5145`, and `7045` across the configured indexes. They are intended to provide investigative context, not to label every matching event as malicious.

**Observed result:** The supplied dashboard screenshot showed no rows in the recent lateral-movement table and no rows in the live stream for the selected time range.

## 5. Findings

- The AD-03 dashboard was created with six panels covering RDP, SMB, service installation, explicit credentials, recent lateral-movement activity, and a live event stream.
- Client-side Event ID `4648` telemetry is present in Splunk under `index=main`, host `SOC-LAB-1`.
- The reviewed 4648 records include both Windows system activity and an event where `Ajit.Yadav` was listed as the account whose credentials were used.
- The dashboard screenshot showed no matching RDP logons, service-installation events, or recent lateral-movement rows in the selected time range.
- No evidence supplied for this report confirms successful lateral movement or privilege escalation.

## 6. Limitations

- Event coverage depends on Windows audit policy, event forwarding, parsing, and time-range selection.
- Event ID `4648` records explicit-credential use attempts; it does not prove a successful remote authentication.
- Event ID `7045` is not inherently malicious.
- Empty dashboard panels mean no matching events were found within the selected time range, not that the activity never occurred.
- A stronger conclusion requires correlating source-side events with destination-side successful logons and related SMB, RDP, or service activity.

## 7. Conclusion

AD-03 establishes a Splunk investigation workflow for reviewing remote logons, SMB access, service installation, and explicit-credential use. Event ID `4648` was verified on `SOC-LAB-1` in `index=main`. However, the available evidence does not demonstrate a confirmed lateral-movement operation or privilege escalation.

**Status:** Dashboard and SPL investigation workflow documented; successful lateral movement and privilege escalation remain unverified.

This lab was conducted in an authorized environment for defensive cybersecurity learning and detection engineering.
