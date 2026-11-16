# Email Security and Phishing Response Standard (MAIL-STD-004)

Version 2026-Q3 · Mapped to NIST CSF 2.0 DE.CM / RS.MI and CIS Control 9 · Classification: Internal (sample data)

## PH-1 Reporting Suspected Phishing
PH-1.1 Employees must report suspected phishing emails using the "Report Phish" button within 15 minutes of noticing them.
PH-1.2 Users must not forward suspected phishing emails to colleagues or open attachments to "check" them.

## PH-2 Clicked Link or Submitted Credentials
PH-2.1 If a user clicked a phishing link or submitted credentials, the SOC must reset the user's password and revoke all active sessions and refresh tokens within 1 hour.
PH-2.2 The user's mailbox must be reviewed for malicious inbox rules and forwarding created after the click.
PH-2.3 Users who opened a malicious attachment must have their endpoint isolated pending EDR triage.

## PH-3 Containment of Phishing Campaigns
PH-3.1 Confirmed phishing messages are purged from all mailboxes tenant-wide.
PH-3.2 Sender domains, URLs and attachment hashes are blocked at the email gateway, web proxy and EDR.
PH-3.3 Look-alike domains impersonating the company or its suppliers are submitted for takedown.

## PH-4 Email Authentication
PH-4.1 All company domains publish SPF, DKIM and a DMARC policy of p=reject.
PH-4.2 External emails are tagged with an "EXTERNAL" banner.
