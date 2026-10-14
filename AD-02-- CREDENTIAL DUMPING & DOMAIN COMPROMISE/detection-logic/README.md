# AD-02 — Credential Dumping & Domain Compromise

Contains the SPL searches extracted from the uploaded Splunk dashboard JSON, plus event-level detail searches.

## Dashboard SPLs 
1. `dashboard-01-lsass-access.spl` — Sysmon Event ID 10 LSASS-access KPI.
2. `dashboard-02-high-risk-lsass-access.spl` — LSASS events grouped by assigned risk.
3. `dashboard-03-recent-dcsync-activity.spl` — recent DCSync table.
4. `dashboard-04-dcsync-detection.spl` — DCSync detection table.
5. `dashboard-05-privileged-account-activity-4672.spl` — privileged-account event count.
6. `dashboard-06-recent-lsass-access-activity.spl` — recent LSASS activity table.
7. `dashboard-07-ad02-live-security-event-stream.spl` — relevant Domain Controller security event stream.

The exported dashboard uses identical SPL for “Recent DCSync Activity” and “DCSync Detection”; both are preserved as separate files.

## Detail SPLs
The `details-*.spl` files show event-level fields for investigating the corresponding event types. These are additional detail searches derived from the dashboard's field extractions and filters.

## Indexes and hosts
- LSASS Sysmon searches: `index=main`; the exported recent-LSASS search filters `host=SOC-LAB-1`.
- Domain Controller searches: `index=AD-DC-01 host=DC01`.

## Interpretation notes
- Sysmon Event ID 10 indicates process access; it does not by itself prove credentials were successfully dumped.
- Event ID 4662 matching replication-right GUIDs is a DCSync-related signal; the dashboard excludes `DC01$`.
- Zero results means no matching events in the selected time window, not that the activity never happened.
- Do not claim a successful credential dump or attacker-originated DCSync without matching evidence.
