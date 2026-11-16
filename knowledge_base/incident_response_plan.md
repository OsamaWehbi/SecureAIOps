# Incident Response Plan (IR-PLAN-001)

Version 2026-Q3 · Aligned to NIST SP 800-61 Rev. 3 and the NIST CSF 2.0 Respond function · Classification: Internal (sample data)

## IR-1 Severity Matrix
IR-1.1 CRITICAL: active ransomware, confirmed data exfiltration, compromise of a domain controller or other Tier-0 asset, or unauthorized firewall changes. Response SLA: 15 minutes, 24x7.
IR-1.2 HIGH: confirmed malware execution, compromised privileged account, or lateral movement. Response SLA: 1 hour.
IR-1.3 MEDIUM: suspicious activity requiring investigation, such as brute-force attempts without success or policy violations. Response SLA: 4 business hours.
IR-1.4 LOW: reconnaissance, blocked attacks, or informational alerts. Response SLA: next business day.

## IR-2 Escalation
IR-2.1 CRITICAL and HIGH incidents must be escalated to the on-call Incident Commander immediately and to the CISO within 1 hour.
IR-2.2 Suspected personal-data breaches must be reported to the Privacy Officer within 24 hours to preserve the 72-hour GDPR notification window.
IR-2.3 Law enforcement contact is coordinated exclusively by Legal.

## IR-3 Containment Authority
IR-3.1 Containment actions that impact production (host isolation, account disablement, firewall blocks) require approval from the Incident Commander or an on-call SOC Tier-3 lead.
IR-3.2 Automated or AI-generated recommendations must never be executed without human approval.
IR-3.3 Evidence (memory, disk, logs) must be preserved before eradication whenever doing so does not increase business risk.

## IR-4 Ransomware Response
IR-4.1 Immediately isolate affected network segments and disconnect backup systems from the network.
IR-4.2 Do not power off encrypted hosts; capture memory where possible.
IR-4.3 Ransom payment decisions are reserved for the Executive Crisis Team with Legal counsel.

## IR-5 Post-Incident Activity
IR-5.1 A lessons-learned review is mandatory for every HIGH or CRITICAL incident within 10 business days.
IR-5.2 Detection gaps identified must be tracked as engineering tickets with an owner and due date.
