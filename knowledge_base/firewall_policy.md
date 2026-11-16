# Network Firewall Policy (NET-POL-001)

Version 2026-Q2 · Owner: Network Security Engineering · Classification: Internal (sample data)

## FW-1 Inbound Traffic to Internal Networks
FW-1.1 All inbound traffic from external IP addresses to the 10.0.0.0/8 subnet is strictly prohibited unless explicitly whitelisted via an approved Change Request (CR).
FW-1.2 Whitelist entries must reference the CR number, a business owner and an expiry date not exceeding 12 months.
FW-1.3 Default policy on every perimeter firewall is deny-all; rules are evaluated top-down with an explicit final deny-and-log rule.

## FW-2 SSH Access
FW-2.1 SSH (port 22) access is restricted to the Bastion Host (192.168.1.50) only.
FW-2.2 Direct SSH from user workstations or the internet to servers is prohibited.
FW-2.3 SSH must use key-based authentication; password authentication and root login are disabled.
FW-2.4 More than 10 failed SSH authentications from one source within 5 minutes must trigger an automatic block for 24 hours and a SOC alert.

## FW-3 Remote Desktop (RDP)
FW-3.1 RDP (port 3389) is disabled globally on all perimeter and internal firewalls.
FW-3.2 Remote administrative access must use the secure VPN tunnel with MFA, then the privileged access workstation (PAW).
FW-3.3 Any observed RDP traffic crossing a security zone is treated as a policy violation and investigated as potential lateral movement.

## FW-4 Change Management and Logging
FW-4.1 Any attempt to modify firewall rules must be logged to the SIEM within 60 seconds of execution.
FW-4.2 Firewall rule changes require an approved Change Request and peer review (four-eyes principle).
FW-4.3 Disabling a host or network firewall outside an approved maintenance window is prohibited.

## FW-5 Violations
FW-5.1 Unauthorized firewall changes are considered a Critical Security Incident and follow the Incident Response Plan (IR-PLAN-001).
FW-5.2 Violations may result in revocation of administrative privileges.
