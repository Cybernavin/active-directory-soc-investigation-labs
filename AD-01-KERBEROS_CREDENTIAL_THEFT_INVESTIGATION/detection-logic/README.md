# AD-01 — Kerberos Credential Theft

These SPL searches correspond to the four panels in the AD-01 tab of the **CORP AD SOC — Attack & Detection Center** dashboard.

## Files

- `01-tgt-requests-4768.spl` — counts Kerberos Ticket-Granting Ticket requests.
- `02-service-tickets-4769.spl` — counts service-ticket requests.
- `03-pre-auth-failures-4771.spl` — counts Kerberos pre-authentication failures.
- `04-top-service-ticket-requests.spl` — summarizes service-ticket activity by source IP and user.

## Run the searches

1. Open Splunk Search.
2. Copy a query from the relevant `.spl` file into the search bar.
3. Choose the investigation time range and run it.
4. Compare the result with the matching dashboard panel.

## Notes

- The searches use `index=AD-DC-01` and `host=DC01`, matching this lab's configuration.
