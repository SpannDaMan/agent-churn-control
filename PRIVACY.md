# Privacy

Anti-Churn is a local, skills-only plugin.

## Data handling

- It does not send events, receipts, files, prompts, or validation results over the network.
- It has no telemetry, analytics, advertising, hosted account, authentication, tracking code, or remote storage.
- It does not require an API key or other credential.
- It reads and writes only paths selected by the user on the local machine.
- External event, task, attempt, model, fan-out, and source identifiers are stored in receipts as SHA-256 digests.

The plugin rejects content-bearing receipt fields, including prompts, outputs, commands, test logs, file contents, secrets, credentials, raw participant identities, and absolute paths.

## Host products

Codex, ChatGPT, GitHub, or another host may have separate privacy and telemetry behavior. Anti-Churn does not control or expand the host product's data handling.

## Contact

Use GitHub Issues for non-sensitive privacy defects and private vulnerability reporting for sensitive concerns. Remove private task content before sharing fixtures or receipts.
