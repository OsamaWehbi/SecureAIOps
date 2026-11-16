# Data Protection and DLP Policy (DATA-POL-003)

Version 2026-Q2 · Mapped to NIST CSF 2.0 PR.DS and GDPR Art. 32 · Classification: Internal (sample data)

## DP-1 Data Classification
DP-1.1 Data is classified as Public, Internal, Confidential or Restricted.
DP-1.2 Customer personal data (PII), payment card data and credentials are Restricted.

## DP-2 Data Transfer and Exfiltration Controls
DP-2.1 Uploading Confidential or Restricted data to personal cloud storage (e.g. Dropbox, MEGA, personal Google Drive) is prohibited.
DP-2.2 Outbound transfers above 1 GB to destinations not on the approved list generate a DLP alert to the SOC.
DP-2.3 Use of unsanctioned file-transfer tools such as rclone or transfer.sh is prohibited on corporate endpoints.

## DP-3 Encryption
DP-3.1 Restricted data must be encrypted at rest (AES-256) and in transit (TLS 1.2 or higher).
DP-3.2 Encryption keys are managed in the corporate KMS/HSM; application teams never hold raw master keys.

## DP-4 AI and LLM Usage
DP-4.1 Restricted data must not be submitted to external AI services unless the service is approved and covered by a data processing agreement.
DP-4.2 AI assistants must apply output filtering to prevent disclosure of secrets and personal data.
DP-4.3 AI-generated security recommendations are advisory; humans remain accountable for decisions.
