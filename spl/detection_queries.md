# Splunk Detection Queries - Phishing SOC Lab

## Query 1: Detect Malicious Attachments
*Purpose:* Flags emails with high-risk executable file extensions.
*MITRE ATT&CK:* T1566.001 (Spearphishing Attachment)

spl
index=phishing_lab sourcetype=email_raw
| rex field=_raw "Attachment:\s(?<attachment>.*)"
| where match(attachment, "(?i)\.(exe|scr|ps1|hta|js|vbs|lnk|iso)$")
| table _time, sender, recipient, subject, attachment


## Query 2: Detect Suspicious Subject Lines
*Purpose:* Identifies social engineering lures using urgency keywords.

spl
index=phishing_lab sourcetype=email_raw
| rex field=_raw "Subject:\s(?<subject>.*)"
| search subject="*password*" OR subject="*urgent*" OR subject="*verify*" OR subject="*reset*" OR subject="*invoice*" OR subject="*action required*"
| stats count by subject, sender
| sort - count


## Query 3: Detect Spoofed Senders (Typosquatting)
*Purpose:* Finds external senders mimicking internal domains.

spl
index=phishing_lab sourcetype=email_raw
| rex field=_raw "From:\s(?<sender>.*)"
| rex field=_raw "To:\s(?<recipient>.*)"
| eval sender_domain=mvindex(split(sender,"@"),1)
| eval recipient_domain=mvindex(split(recipient,"@"),1)
| where sender_domain != recipient_domain AND (match(sender_domain, "company") OR match(sender_domain, "micros0ft") OR match(sender_domain, "paypa1"))
| table _time, sender, recipient, sender_domain


## Query 4: Detect Suspicious URLs
*Purpose:* Flags URLs not on the trusted domain allowlist.

spl
index=phishing_lab sourcetype=email_raw
| rex field=_raw "URL:\s(?<url>.*)"
| where isnotnull(url) AND NOT match(url, "(?i)company\.com|microsoft\.com|office\.com")
| table _time, sender, recipient, subject, url


## Query 5: Consolidated Risk Scoring (Correlation Alert)
*Purpose:* Combines multiple indicators into a single high-fidelity alert.

spl
index=phishing_lab sourcetype=email_raw
| rex field=_raw "From:\s(?<sender>.*)"
| rex field=_raw "To:\s(?<recipient>.*)"
| rex field=_raw "Subject:\s(?<subject>.*)"
| rex field=_raw "Attachment:\s(?<attachment>.*)"
| rex field=_raw "URL:\s(?<url>.*)"
| eval risk_score=0
| eval risk_score=if(match(attachment, "(?i)\.(exe|ps1|hta)$"), risk_score+3, risk_score)
| eval risk_score=if(match(subject, "(?i)(urgent|password|verify|invoice)"), risk_score+2, risk_score)
| eval risk_score=if(NOT match(url, "(?i)company\.com"), risk_score+2, risk_score)
| where risk_score >= 5
| table _time, sender, recipient, subject, attachment, url, risk_score
| sort - risk_score
