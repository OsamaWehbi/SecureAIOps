"""Response playbooks aligned to NIST SP 800-61r3 (Incident Response).

Actions that change production state (containment / eradication) are marked
``requires_approval`` — the platform is *human-on-the-loop*: agents recommend,
analysts authorise.
"""

from __future__ import annotations

from app.intel.ioc import IOC
from app.intel.mitre import TechniqueMatch

# tactic -> list of (phase, action, requires_approval)
_TACTIC_PLAYBOOK: dict[str, list[tuple[str, str, bool]]] = {
    "Credential Access": [
        ("Containment", "Force password reset and revoke active sessions/tokens for affected accounts", True),
        ("Containment", "Temporarily block offending source IPs at the perimeter firewall / WAF", True),
        ("Eradication", "Enforce phishing-resistant MFA on the targeted accounts", False),
    ],
    "Initial Access": [
        ("Containment", "Quarantine the delivered artefact (email / file) across all mailboxes", True),
        ("Analysis", "Identify all recipients and users who interacted with the lure", False),
    ],
    "Execution": [
        ("Containment", "Isolate the affected endpoint via EDR network containment", True),
        ("Analysis", "Collect process tree, command line and parent/child lineage from EDR", False),
    ],
    "Persistence": [
        ("Eradication", "Remove the persistence mechanism (task / run key / account) after evidence capture", True),
        ("Analysis", "Hunt for the same persistence artefact across the fleet", False),
    ],
    "Privilege Escalation": [
        ("Containment", "Remove unauthorised privileged group memberships", True),
        ("Analysis", "Review privileged-access audit trail (4672/4728/4732) for the last 72h", False),
    ],
    "Defense Evasion": [
        ("Containment", "Restore and lock security tooling configuration via policy (GPO/MDM)", True),
        ("Analysis", "Confirm telemetry gap window and back-fill from secondary sources", False),
    ],
    "Discovery": [
        ("Analysis", "Correlate scanning source with asset inventory and change calendar", False),
    ],
    "Lateral Movement": [
        ("Containment", "Segment the affected hosts and block east-west admin protocols (SMB/RDP/WinRM)", True),
        ("Analysis", "Map authentication graph from the source host to identify reached systems", False),
    ],
    "Collection": [
        ("Analysis", "Identify staged archives and data classification of their contents", False),
    ],
    "Command and Control": [
        ("Containment", "Sinkhole / block C2 domains and IPs at DNS and egress proxy", True),
        ("Analysis", "Search proxy and DNS logs for other beaconing hosts", False),
    ],
    "Exfiltration": [
        ("Containment", "Block egress destination and suspend the involved identity", True),
        ("Analysis", "Quantify data volume and classification; engage Legal/Privacy for notification duty", False),
    ],
    "Impact": [
        ("Containment", "Activate the ransomware runbook: isolate segment, protect backups (offline/immutable)", True),
        ("Recovery", "Validate integrity of backups before restoration", False),
        ("Communication", "Notify CISO and Incident Commander — Critical Security Incident", False),
    ],
    "Reconnaissance": [
        ("Analysis", "Validate exposure of the scanned services against the external attack surface inventory", False),
    ],
}

# Technique-specific steps take precedence over the generic tactic playbook.
_TECHNIQUE_PLAYBOOK: dict[str, list[tuple[str, str, bool]]] = {
    "T1078": [
        ("Containment", "Disable the compromised account and terminate all of its active sessions", True),
        ("Analysis", "Reconstruct every action performed by the account since the first successful logon", False),
    ],
    "T1110": [
        ("Containment", "Block the brute-forcing source IPs at the perimeter firewall for 24h", True),
        ("Eradication", "Enforce key-based / phishing-resistant authentication on the targeted service", False),
    ],
    "T1566": [
        ("Containment", "Purge the phishing message from all mailboxes and block sender + URLs", True),
        ("Containment", "Reset credentials of users who clicked or submitted credentials", True),
        ("Analysis", "Identify all recipients and users who interacted with the lure", False),
    ],
}

_DETECTION: dict[str, list[str]] = {
    "Credential Access": [
        "Alert on 4625/4771 bursts and 4769 TGS requests using RC4 (0x17) for service accounts",
        "Monitor handle access to lsass.exe (Sysmon EID 10) from non-system processes",
    ],
    "Initial Access": ["Detonate attachments in a sandbox; alert on Office apps spawning script interpreters"],
    "Execution": ["Enable PowerShell Script Block Logging (EID 4104) and alert on encoded/hidden invocations"],
    "Persistence": ["Baseline scheduled tasks, services and Run keys; alert on new entries (4698, 7045)"],
    "Privilege Escalation": ["Alert on privileged group changes (4728/4732/4756) outside the PAM workflow"],
    "Defense Evasion": ["Alert on security-tool tampering and on log clearing (EID 1102 / 104)"],
    "Discovery": ["Detect high-fan-out connection attempts and LDAP enumeration from workstations"],
    "Lateral Movement": ["Alert on admin-protocol logons (type 3/10) between workstations"],
    "Collection": ["Detect password-protected archive creation in user-writable paths"],
    "Command and Control": ["Hunt for periodic beaconing (low jitter) and newly registered domains in proxy/DNS"],
    "Exfiltration": ["Alert on egress volume anomalies and uploads to unsanctioned cloud storage"],
    "Impact": ["Canary files + alert on mass file renames and vssadmin/wbadmin deletion commands"],
    "Reconnaissance": ["Correlate external scanning with exposed-asset inventory; rate-limit at the edge"],
}


def detection_hints(tactic: str) -> list[str]:
    return _DETECTION.get(tactic, [])


_PRIORITY = {"Containment": "P1", "Eradication": "P2", "Analysis": "P2", "Recovery": "P3", "Communication": "P1"}


def recommend_actions(
    techniques: list[TechniqueMatch], iocs: list[IOC], severity: str, max_actions: int = 7
) -> list[dict]:
    actions: list[dict] = []
    seen: set[str] = set()

    def add(phase: str, text: str, approval: bool) -> None:
        if text not in seen:
            seen.add(text)
            actions.append(
                {"phase": phase, "action": text, "priority": _PRIORITY.get(phase, "P3"), "requires_approval": approval}
            )

    if severity in {"HIGH", "CRITICAL"}:
        add("Communication", f"Open a {severity} incident ticket and page the on-call Incident Commander", False)
    generic_tactics: list[str] = []
    for t in techniques:
        override = _TECHNIQUE_PLAYBOOK.get(t.id.split(".")[0])
        if override:
            for phase, text, approval in override:
                add(phase, text, approval)
        elif t.tactic not in generic_tactics:
            generic_tactics.append(t.tactic)
    for tactic in generic_tactics:
        for phase, text, approval in _TACTIC_PLAYBOOK.get(tactic, []):
            add(phase, text, approval)
    if iocs:
        add(
            "Analysis",
            f"Enrich and sweep {len(iocs)} IOC(s) across SIEM, EDR and proxy telemetry (last 30 days)",
            False,
        )
    add("Lessons Learned", "Document root cause and detection gaps; update detections and this playbook", False)
    order = {"P1": 0, "P2": 1, "P3": 2}
    actions.sort(key=lambda a: order.get(a["priority"], 3))
    return actions[:max_actions]
