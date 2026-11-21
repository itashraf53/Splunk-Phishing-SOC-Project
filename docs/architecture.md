# Project Architecture

## Data Flow
1. *Email Logs* (synthetic / BOTSv3 dataset) → uploaded to Splunk.
2. *Splunk Index* (phishing_lab) → stores raw email logs.
3. *SPL Detection Queries* → extract fields via rex, apply risk scoring.
4. *Dashboard* → visualizes trends, top senders, high-risk events.
5. *Scheduled Alert* → triggers every 15 minutes when risk_score >= 5.
6. *SOC Analyst* → follows the Incident Response Playbook.

## Tools Used
- Splunk Enterprise (Free Trial)
- SPL (Search Processing Language)
- Regex (rex command)
- MITRE ATT&CK Framework (T1566 - Phishing)
