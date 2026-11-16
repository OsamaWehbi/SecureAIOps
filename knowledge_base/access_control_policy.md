# Identity and Access Control Policy (IAM-POL-002)

Version 2026-Q1 · Mapped to ISO/IEC 27001:2022 Annex A 5.15–5.18 and 8.2–8.5 · Classification: Internal (sample data)

## AC-1 Authentication
AC-1.1 Multi-factor authentication (MFA) is mandatory for all remote access, cloud consoles, email and privileged accounts.
AC-1.2 Phishing-resistant MFA (FIDO2 / passkeys) is required for administrators.
AC-1.3 Passwords must be at least 14 characters; breached-password screening is enforced at every change.

## AC-2 Account Lockout
AC-2.1 Accounts lock for 15 minutes after 10 consecutive failed sign-in attempts.
AC-2.2 Repeated lockouts across multiple accounts from a single source indicate password spraying and must be escalated to the SOC.

## AC-3 Privileged Access
AC-3.1 Membership of Domain Admins, Enterprise Admins and cloud Global Administrator roles is restricted to named break-glass and Tier-0 accounts.
AC-3.2 Privileged access is granted just-in-time (JIT) for a maximum of 8 hours via the PAM platform.
AC-3.3 Any addition to a privileged group outside PAM is treated as a HIGH severity incident.

## AC-4 Service Accounts
AC-4.1 Service accounts must not have interactive logon rights.
AC-4.2 Service-account credentials are stored in the secrets vault and rotated at least every 90 days.
AC-4.3 Kerberos service accounts must use AES encryption and long random passwords to resist Kerberoasting.

## AC-5 Access Reviews
AC-5.1 Managers recertify user access quarterly; privileged access is recertified monthly.
AC-5.2 Leaver accounts are disabled within 4 hours of HR termination.
