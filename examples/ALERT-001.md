# Incident Report: ALERT-001

## Summary
User jdoe successfully logged in from IP 203.0.113.45 after 14 failed attempts, indicating a potential brute force attack. Threat intelligence confirmed that the source IP has a malicious reputation with a 95% confidence score and is tagged for brute-force and botnet activity. Based on this behavior and intelligence, the alert was triaged as a True Positive.

## Severity and Verdict
- **Severity:** High
- **Verdict:** True Positive
- **Confidence:** 90%
- **Reasoning:** The alert shows a successful login for user jdoe following 14 failed attempts from the source IP 203.0.113.45. Threat intelligence confirms that this IP has a malicious reputation, specifically tagged with brute-force and botnet activity, aligning directly with the observed login behavior.

## Evidence
- **Type:** suspicious_login
- **Source IP:** 203.0.113.45
- **User:** jdoe
- **Detail:** Login succeeded after 14 failed attempts
- **Timestamp:** 2026-11-14T03:12:00Z
- **Threat intel** (`lookup_ip` on `203.0.113.45`): reputation: malicious; confidence: 95; tags: brute-force, botnet; last_seen: 2026-11-13

## Indicators of Compromise
- **IP:** 203.0.113.45
- **User:** jdoe

## Recommended Actions
- Reset the password for user jdoe immediately
- Block the source IP 203.0.113.45 at the firewall
- Review authentication logs for any additional suspicious activity or lateral movement associated with user jdoe
