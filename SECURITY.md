# Security Policy

## Report a vulnerability

Use the repository **Security** tab and **Report a vulnerability** for private security reports. Do not disclose a suspected vulnerability in a public issue before the maintainer has had a reasonable opportunity to investigate.

Do not include credentials, tokens, private prompts, source contents, customer data, or raw sensitive receipts in a report. Use minimal synthetic reproduction data.

## Security boundary

Agent Churn Control is local and skills-only. It has no network client, authentication, hosted service, telemetry, model execution, or external-action authority.

A valid receipt must not contain prompts, outputs, command strings, test logs, file contents, secrets, tokens, credentials, raw participant identities, or absolute paths. Externally supplied identifiers are stored as SHA-256 digests.

See [THREAT-MODEL.md](THREAT-MODEL.md) for trust boundaries and non-goals.
