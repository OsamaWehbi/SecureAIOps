"""Curated subset of MITRE ATT&CK (Enterprise) used for deterministic mapping.

Each entry pairs a technique with high-signal detection patterns observed in
SOC telemetry (Windows Security events, Sysmon, EDR, Linux auth logs, proxy
logs). Patterns are intentionally conservative: false positives in an
automated triage pipeline erode analyst trust faster than misses.

Source: https://attack.mitre.org (ATT&CK® is a registered trademark of The
MITRE Corporation).
"""

from __future__ import annotations

# tactic -> base weight used by the risk engine (0-1).
TACTIC_WEIGHTS: dict[str, float] = {
    "Reconnaissance": 0.15,
    "Initial Access": 0.55,
    "Execution": 0.55,
    "Persistence": 0.6,
    "Privilege Escalation": 0.7,
    "Defense Evasion": 0.65,
    "Credential Access": 0.8,
    "Discovery": 0.3,
    "Lateral Movement": 0.75,
    "Collection": 0.5,
    "Command and Control": 0.7,
    "Exfiltration": 0.85,
    "Impact": 0.95,
}

TECHNIQUES: list[dict] = [
    # ---- Credential Access
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "patterns": [
            r"brute[\s-]?forc",
            r"failed (password|login|logon)",
            r"event ?id[:\s]*4625",
            r"authentication fail",
            r"invalid user",
            r"\b\d{2,}\s+failed",
        ],
    },
    {
        "id": "T1110.003",
        "name": "Password Spraying",
        "tactic": "Credential Access",
        "patterns": [r"password[\s-]?spray", r"multiple (users|accounts).{0,40}(failed|single password)"],
    },
    {
        "id": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "patterns": [r"lsass", r"mimikatz", r"sekurlsa", r"procdump.{0,40}lsass", r"comsvcs\.dll.{0,30}minidump"],
    },
    {
        "id": "T1558.003",
        "name": "Kerberoasting",
        "tactic": "Credential Access",
        "patterns": [r"kerberoast", r"event ?id[:\s]*4769.{0,80}(0x17|rc4)", r"rubeus"],
    },
    {
        "id": "T1555",
        "name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "patterns": [r"(chrome|browser).{0,30}(login data|saved passwords)", r"lazagne", r"keychain dump"],
    },
    {
        "id": "T1056.001",
        "name": "Input Capture: Keylogging",
        "tactic": "Credential Access",
        "patterns": [r"keylog", r"setwindowshookex"],
    },
    # ---- Initial Access
    {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "patterns": [
            r"phish",
            r"malicious attachment",
            r"macro[- ]enabled",
            r"\.docm\b",
            r"invoice.{0,20}\.(zip|iso|lnk)",
        ],
    },
    {
        "id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "patterns": [r"(clicked|click).{0,30}(link|url)", r"credential harvest", r"fake login page"],
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "patterns": [
            r"\bcve-\d{4}-\d{4,7}\b",
            r"sql ?injection",
            r"union\s+select",
            r"\.\./\.\./",
            r"\$\{jndi:",
            r"remote code execution",
            r"\brce\b",
            r"web ?shell",
        ],
    },
    {
        "id": "T1133",
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "patterns": [r"vpn.{0,30}(anomal|unusual|impossible travel)", r"impossible travel", r"citrix.{0,20}login"],
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "patterns": [
            r"(successful|accepted) (login|logon|password).{0,60}(after|following).{0,30}fail",
            r"(?s)fail(ed|ure).{0,4000}\b(accepted (password|publickey)|successful (login|logon)|logon success)",
            r"event ?id[:\s]*4624.{0,80}(after|following)",
            r"compromised (account|credential)",
        ],
    },
    # ---- Execution
    {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "patterns": [
            r"powershell(\.exe)?\s.{0,40}(-enc|-encodedcommand|-e\s|-nop|-w(indowstyle)?\s+hidden|iex|invoke-expression|downloadstring)",
            r"invoke-mimikatz",
            r"frombase64string",
        ],
    },
    {
        "id": "T1059.003",
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "patterns": [r"cmd(\.exe)?\s+/c", r"cmd\.exe.{0,30}spawned"],
    },
    {
        "id": "T1059.004",
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "patterns": [r"(curl|wget)\s+[^|]{0,120}\|\s*(ba)?sh", r"bash -i >& /dev/tcp", r"/bin/sh -c"],
    },
    {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "patterns": [
            r"(opened|executed|ran).{0,30}(attachment|\.exe|\.scr|\.lnk|\.iso)",
            r"winword\.exe.{0,40}(spawn|child)",
        ],
    },
    {
        "id": "T1047",
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
        "patterns": [r"\bwmic\b.{0,60}process call create", r"wmiprvse\.exe.{0,40}spawn"],
    },
    # ---- Persistence / Privilege Escalation
    {
        "id": "T1053.005",
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
        "patterns": [r"schtasks(\.exe)?\s+/create", r"event ?id[:\s]*4698", r"new scheduled task"],
    },
    {
        "id": "T1547.001",
        "name": "Boot or Logon Autostart: Registry Run Keys",
        "tactic": "Persistence",
        "patterns": [r"currentversion\\run", r"run ?key", r"reg(\.exe)? add.{0,60}\\run"],
    },
    {
        "id": "T1136",
        "name": "Create Account",
        "tactic": "Persistence",
        "patterns": [
            r"event ?id[:\s]*4720",
            r"net user .{1,40} /add",
            r"new (local )?(admin )?account created",
            r"useradd\b",
        ],
    },
    {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "patterns": [
            r"event ?id[:\s]*(4728|4732|4756)",
            r"added to .{0,30}(domain admins|administrators)",
            r"net localgroup administrators .{1,40} /add",
        ],
    },
    {
        "id": "T1505.003",
        "name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "patterns": [r"web ?shell", r"(china ?chopper|godzilla|behinder)", r"w3wp\.exe.{0,40}(cmd|powershell)"],
    },
    {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "patterns": [r"privilege escalation", r"\bsudo\b.{0,40}(cve|exploit)", r"token (impersonation|manipulation)"],
    },
    # ---- Defense Evasion
    {
        "id": "T1562.001",
        "name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "Defense Evasion",
        "patterns": [
            r"(disabl|stopp|tamper).{0,30}(defender|antivirus|edr|av\b|sysmon|firewall)",
            r"set-mppreference.{0,40}disable",
            r"sc(\.exe)? (stop|delete) .{0,30}(windefend|sense)",
        ],
    },
    {
        "id": "T1562.004",
        "name": "Impair Defenses: Disable or Modify System Firewall",
        "tactic": "Defense Evasion",
        "patterns": [
            r"netsh .{0,30}firewall .{0,30}(off|disable)",
            r"(firewall rule|iptables).{0,40}(modif|chang|flush|-f\b)",
            r"ufw disable",
        ],
    },
    {
        "id": "T1070.001",
        "name": "Indicator Removal: Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "patterns": [
            r"wevtutil(\.exe)?\s+cl",
            r"event ?id[:\s]*1102",
            r"(security )?log (was )?cleared",
            r"clear-eventlog",
        ],
    },
    {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "patterns": [r"obfuscat", r"base64.{0,20}(encoded|payload|blob)", r"-encodedcommand"],
    },
    {
        "id": "T1218",
        "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "patterns": [
            r"\b(rundll32|regsvr32|mshta|certutil)(\.exe)?\b.{0,60}(http|scrobj|javascript|-urlcache|-decode)"
        ],
    },
    # ---- Discovery
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "patterns": [r"port ?scan", r"\bnmap\b", r"masscan", r"syn scan", r"scann?ing .{0,20}ports"],
    },
    {
        "id": "T1087",
        "name": "Account Discovery",
        "tactic": "Discovery",
        "patterns": [r"net (user|group) .{0,30}/domain", r"bloodhound|sharphound", r"ldap enumeration"],
    },
    {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "patterns": [r"(vulnerability|vuln) scan", r"\bnikto\b", r"\bnuclei\b", r"directory (brute|enumerat)"],
    },
    # ---- Lateral Movement
    {
        "id": "T1021.001",
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "patterns": [r"\brdp\b", r"port 3389", r":3389\b", r"logon ?type[:\s]*10", r"mstsc"],
    },
    {
        "id": "T1021.002",
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "patterns": [r"psexec", r"\\\\[^\\\s]+\\(admin|c|ipc)\$", r"\bsmbexec\b"],
    },
    {
        "id": "T1021.004",
        "name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "patterns": [
            r"ssh\s+(-\S+\s+)*\S+@(10|192\.168|172\.(1[6-9]|2\d|3[01]))\.",
            r"lateral.{0,30}ssh",
            r"ssh.{0,40}(between|from) (internal|workstation|server)s?",
        ],
    },
    {
        "id": "T1550.002",
        "name": "Use Alternate Authentication Material: Pass the Hash",
        "tactic": "Lateral Movement",
        "patterns": [r"pass[\s-]the[\s-]hash", r"\bpth\b", r"logon ?type[:\s]*9.{0,40}seclogo"],
    },
    # ---- Collection / C2 / Exfiltration
    {
        "id": "T1560",
        "name": "Archive Collected Data",
        "tactic": "Collection",
        "patterns": [r"(7z|rar|zip)(\.exe)? a .{0,60}(-p|password)", r"staged .{0,20}archive"],
    },
    {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "patterns": [
            r"beacon(ing)?",
            r"\bc2\b|command[\s-]and[\s-]control",
            r"cobalt ?strike",
            r"sliver|havoc|brute ratel",
        ],
    },
    {
        "id": "T1071.004",
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "patterns": [r"dns tunnel", r"(long|high[- ]entropy|unusual) (txt )?dns (queries|requests)", r"iodine|dnscat"],
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "patterns": [
            r"certutil.{0,30}-urlcache",
            r"(invoke-webrequest|iwr|wget|curl)\s+.{0,80}\.(exe|ps1|dll|sh|bin)\b",
            r"bitsadmin .{0,20}/transfer",
        ],
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "patterns": [
            r"exfiltrat",
            r"(large|unusual|abnormal) (outbound|upload|egress)",
            r"\b\d+(\.\d+)?\s?(gb|tb)\b.{0,40}(outbound|upload|transferred|sent)",
        ],
    },
    {
        "id": "T1567.002",
        "name": "Exfiltration to Cloud Storage",
        "tactic": "Exfiltration",
        "patterns": [r"(mega\.nz|mega\.io|dropbox|transfer\.sh|anonfiles|rclone)", r"upload(ed)? to (personal )?cloud"],
    },
    # ---- Impact
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "patterns": [
            r"ransom",
            r"\.(locked|encrypted|crypt)\b",
            r"files? (were |being )?encrypted",
            r"lockbit|blackcat|alphv|akira|conti",
        ],
    },
    {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "patterns": [
            r"vssadmin(\.exe)?\s+delete\s+shadows",
            r"wbadmin .{0,20}delete",
            r"bcdedit .{0,40}recoveryenabled no",
            r"shadow ?cop(y|ies) (deleted|removed)",
        ],
    },
    {
        "id": "T1485",
        "name": "Data Destruction",
        "tactic": "Impact",
        "patterns": [r"wiper", r"rm -rf /", r"(mass|bulk) (file )?deletion"],
    },
    {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "patterns": [r"\bddos\b", r"syn flood", r"denial[\s-]of[\s-]service"],
    },
]
