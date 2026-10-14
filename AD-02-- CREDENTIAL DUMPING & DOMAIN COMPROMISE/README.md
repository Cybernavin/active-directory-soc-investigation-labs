# AD-02 — Credential Dumping & Domain Compromise

AD-02 is the second project in my Active Directory SOC investigation lab series. In this lab, I built Splunk detections and investigation searches for suspicious LSASS process access, DCSync-related directory access, and privileged-account activity.

> **Investigation status:** Dashboard and detection searches documented. Successful credential dumping and attacker-originated DCSync were not confirmed in the available evidence.

## Lab Environment

| Component | Details |
|---|---|
| Active Directory domain | `CORP.LOCAL` |
| Domain Controller | `DC01` |
| Endpoint | `SOC-LAB-1` |
| SIEM | Splunk Enterprise |
| Endpoint telemetry | Sysmon |
| Main LSASS event | Sysmon Event ID `10` |
| Main directory-access event | Windows Security Event ID `4662` |
| Privileged logon event | Windows Security Event ID `4672` |a

## Investigation Objectives

- Investigate Sysmon Event ID 10 events targeting `lsass.exe`.
- Apply a source-process-based risk heuristic to help prioritize LSASS access events.
- Search Event ID 4662 for Active Directory replication-right GUIDs associated with DCSync investigations.
- Review Event ID 4672 for special-privilege assignments.
- Build dashboard panels and event-level SPL searches to support investigation.

## Dashboard Panels

1. **LSASS Access** — count of Sysmon Event ID 10 events targeting `lsass.exe`.
2. **High-Risk LSASS Access** — LSASS access grouped by source-process risk heuristic.
3. **Recent DCSync Activity** — event-level results matching replication-right GUIDs.
4. **DCSync Detection** — detection results for matching Event ID 4662 activity.
5. **Privileged Account Activity (4672)** — count of matching privileged logon events.
6. **Recent LSASS Access Activity** — recent process-access details.
7. **AD-02 Live Security Event Stream** — selected security events for investigation context.

## Detection Logic

### LSASS process access

The LSASS searches use Sysmon Event ID `10` and filter for `TargetImage` matching `lsass.exe`. The detail searches show fields such as source user, source process, target process, access mask, and event time.

The dashboard applies these source-process heuristics:

- **HIGH:** `powershell.exe`, `cmd.exe`, `rundll32.exe`
- **CRITICAL:** process names containing `procdump` or `mimikatz`
- **MEDIUM:** other source processes that remain after the exclusions

These are triage labels only. Process names and Event ID 10 do not, by themselves, prove credential dumping.

### DCSync-related activity

The DCSync searches examine Event ID `4662` on `DC01` and look for these replication-right GUIDs:

- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`
- `89e95b76-444d-4c62-991a-0facbeda640c`

The dashboard excludes the `DC01$` machine account from its DCSync result set. A matching event is a signal to investigate, not proof that credentials were extracted.

## Repository Structure

```text
AD-02-credential-dumping-domain-compromise/
├── README.md
├── investigation-report.md
├── detection-logic/
│   ├── dashboard-01-lsass-access.spl
│   ├── dashboard-02-high-risk-lsass-access.spl
│   ├── dashboard-03-recent-dcsync-activity.spl
│   ├── dashboard-04-dcsync-detection.spl
│   ├── dashboard-05-privileged-account-activity-4672.spl
│   ├── dashboard-06-recent-lsass-access-activity.spl
│   ├── dashboard-07-ad02-live-security-event-stream.spl
│   ├── details-01-lsass-access-events.spl
│   ├── details-02-high-risk-lsass-events.spl
│   ├── details-03-dcsync-replication-rights-events.spl
│   ├── details-04-privileged-account-events-4672.spl
│   └── details-05-ad02-security-event-stream.spl
└── screenshots/
    └── (dashboard and investigation screenshots)
```

Adjust the folder names if your repository uses a different structure. The dashboard export uses the same query for **Recent DCSync Activity** and **DCSync Detection**; both are retained as separate SPL files for clarity.

## Validation and Findings

- A controlled, query-only LSASS process-access test was observed on `SOC-LAB-1` as Sysmon Event ID 10, with PowerShell as the source process, `lsass.exe` as the target, and `GrantedAccess` of `0x1000`.
- This confirmed process-access telemetry for the test; it did **not** demonstrate credential dumping.
- Baseline Event ID 4662 events were observed on `DC01`, including legitimate replication-related activity from `DC01$`.
- No non-`DC01$` replication-right event was confirmed in the observed time window.
- A synthetic `makeresults` test was used to validate the DCSync SPL classification logic. It did not create a real Windows Event ID 4662 event and did not demonstrate an actual DCSync attempt.

For the full methodology and limitations, see [`investigation-report.md`](investigation-report.md).

## Important Notes

- Empty results mean no matching events were found in the selected time range; they do not prove the activity never occurred.
- Event collection depends on audit policy, Sysmon configuration, forwarding configuration, field extraction, and the selected Splunk time range.
- Risk labels are heuristic and may produce false positives or false negatives.
- Do not interpret these detections as proof of successful credential extraction without supporting evidence.

## Tools Used

- Splunk Enterprise
- Windows Active Directory
- Windows Security Event Logging
- Sysmon
- Splunk Search Processing Language (SPL)
- PowerShell

## Disclaimer

This project was performed in an authorized lab environment for defensive cybersecurity learning and detection engineering. It focuses on telemetry collection, SIEM detection logic, and investigation workflow.
