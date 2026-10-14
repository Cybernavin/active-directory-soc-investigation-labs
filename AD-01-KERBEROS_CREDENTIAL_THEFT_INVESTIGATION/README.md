# AD-01: Kerberos Credential Theft Investigation

This project is part of my Active Directory SOC lab series. I used Splunk to investigate Kerberos authentication activity and identify suspicious service-ticket requests.

### Tools Used
- Splunk Enterprise
- Windows Active Directory(2022)
- Kali Linux
- SPL (Search Processing Language)

### What I Did
- Analyzed Windows Event IDs 4768, 4769, and 4771.
- Identified the `svc_sql` service account and its SPN.
- Investigated suspicious ticket requests and encryption-related errors.
- Created SPL searches and a dashboard to monitor Kerberos activity.

### Key Learning
I learned how to investigate Kerberos events, distinguish normal activity from suspicious patterns, and build SIEM detections.


This lab was performed in an authorized environment for cybersecurity learning and defensive detection engineering.