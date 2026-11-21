# Phishing Incident Response Playbook

## Trigger
Splunk alert: "HIGH-RISK PHISHING DETECTED" (risk_score >= 5)

## Step 1: Alert Validation
- Open the triggered alert in Splunk.
- Review the raw email log entry.
- Confirm indicators: sender domain, subject, attachment, URL.

## Step 2: IOC Enrichment
- Submit the sender domain to *VirusTotal* and *URLScan.io*.
- Check URL reputation via *WHOIS*.
- Record findings in the incident ticket.

## Step 3: Correlation
- Search Splunk for other emails from the same sender: index=phishing_lab sender="<suspicious_sender>"
- Identify all affected recipients.

## Step 4: Classification
- *True Positive:* Malicious indicators confirmed → proceed to containment.
- *False Positive:* Legitimate email flagged → tune the detection (add to allowlist lookup).

## Step 5: Containment & Response
- Quarantine the email from all recipient inboxes.
- Block the sender domain and URL at the email gateway/proxy.
- Force password reset for any user who clicked the link (check proxy logs).
- Notify affected users via the security awareness team.

## Step 6: Documentation
- Log the incident in the ticketing system (Jira/ServiceNow).
- Update the SOC knowledge base with new IOCs.
