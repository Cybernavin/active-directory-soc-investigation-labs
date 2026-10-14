# AD-01 Investigation Report: Kerberos Credential Theft

## Overview
I used Splunk to investigate Kerberos activity in my Active Directory lab and look for suspicious service-ticket requests.

## Investigation
- Reviewed Event IDs **4768, 4769, and 4771**.
- Identified the `svc_sql` service account and its SPN: `MSSQLSvc/sql01.corp.local:1433`.
- Observed normal AES Kerberos activity (`0x12`).
- Tested SPN enumeration with Impacket but encountered `KDC_ERR_ETYPE_NOSUPP` during ticket extraction.
- Created SPL searches to review service-ticket patterns and encryption-related errors.

## Findings
The SPN was identified, but successful ticket extraction or password cracking was not achieved. The encryption error was documented rather than changing the domain's security settings to force the test to work.

## Conclusion
This investigation helped me understand Kerberos event analysis, service accounts, and how Splunk can help identify suspicious authentication patterns.

**Status:** Completed and documented. The Impacket ticket-extraction issue remains unresolved.