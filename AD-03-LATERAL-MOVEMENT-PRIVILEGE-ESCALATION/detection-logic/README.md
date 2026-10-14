# AD-03 — Lateral Movement & Privilege Escalation SPL

This package contains the six SPL searches used by the AD-03 tab in the uploaded `CORP AD SOC — Attack & Detection Center` dashboard, plus six event-level detail searches.

## Dashboard SPLs
1. `dashboard-01-rdp-logons-4624-type10.spl` — counts successful logons with Logon Type 10.
2. `dashboard-02-smb-activity-5140-5145.spl` — counts SMB share access events.
3. `dashboard-03-remote-service-7045.spl` — counts service-installation events.
4. `dashboard-04-explicit-credential-use-4648.spl` — counts explicit-credential-use events.
5. `dashboard-05-recent-lateral-movement-activity.spl` — summarizes RDP/network logons, explicit credential use, SMB access, and service events.
6. `dashboard-06-live-security-event-stream.spl` — live stream of selected security events.

## Detail SPLs
The `details-*.spl` searches show event-level rows to help investigate users, source IPs, event types, share/service fields, and timestamps. Field availability depends on the event's XML and how Splunk ingests it.

## Data sources from the dashboard
- Main dashboard searches use `index=AD-DC-01`.
- Explicit credential use searches `index=AD-DC-01 OR index=main`.
- The live stream searches `index=AD-DC-01 OR index=main`.
- The dashboard global time picker defaults to the last 24 hours, while individual searches may use a narrower time window.
