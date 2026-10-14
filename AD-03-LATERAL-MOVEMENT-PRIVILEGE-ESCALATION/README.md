# AD-03 — Lateral Movement & Privilege Escalation Investigation Lab

AD-03 is the third lab in my Active Directory SOC investigation series. I built a Splunk dashboard to investigate Windows authentication and remote-access events that may help identify lateral movement.

## Lab Environment

- **Domain:** `CORP.LOCAL`
- **Domain Controller:** `DC01`
- **Client endpoint:** `SOC-LAB-1`
- **SIEM:** Splunk Enterprise
- **Telemetry:** Windows Security logs

## Dashboard Panels

1. **RDP Logons** — Event ID `4624`, Logon Type `10`
2. **SMB Activity** — Event IDs `5140` and `5145`
3. **Remote Service** — Event ID `7045`
4. **Explicit Credential Use** — Event ID `4648`
5. **Recent Lateral Movement Activity**
6. **Live Security Event Stream**

The dashboard searches the `AD-DC-01` index for domain-controller events and uses `index=main` for relevant client-side telemetry, including Event ID 4648 on `SOC-LAB-1`.

## What I Investigated

- Successful remote-interactive logons that may indicate RDP access.
- SMB share access and detailed share checks.
- Windows service installation events.
- Explicit-credential logon attempts and the account whose credentials were used.
- Related events that could provide context for remote activity.

## Current Results

In the dashboard's selected time range, RDP Logons and Remote Service counts were `0`, and the recent lateral-movement table returned no results. SMB counts shown by the dashboard can vary with the selected time range and ingested events.

I also verified that Event ID `4648` is being indexed from `SOC-LAB-1` in `index=main`. The event-level investigation search can show the subject account, the account whose credentials were used, target server, process, and network address when those fields are present in the event.

These findings confirm that the dashboard and event searches can be used to review relevant telemetry. They do **not** establish that lateral movement or privilege escalation was successfully performed.

## Detection Logic Notes

- Event ID `4624` with Logon Type `10` indicates a successful Remote Interactive logon; investigate the source and destination context.
- Event IDs `5140` and `5145` relate to SMB share access.
- Event ID `7045` records service installation and is not automatically malicious.
- Event ID `4648` records an attempt to use explicitly specified credentials. It does not, by itself, prove a successful remote logon.
- Correlate events across the source endpoint and destination system before concluding that lateral movement occurred.

## Files

- `README.md` — project overview and current findings.
- `investigation-report.md` — investigation scope, evidence, and limitations.
- `detection-logic/` — dashboard and event-detail SPL searches.
- `screenshots/` — screenshots of the dashboard and validated searches.

## Tools Used

Splunk Enterprise, Windows Active Directory, Windows Security Event Logging, PowerShell, and Kali Linux.

**Disclaimer:** This project is for authorized lab use and defensive SOC detection engineering.
