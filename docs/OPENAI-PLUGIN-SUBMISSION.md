# OpenAI Plugin Submission Packet

Anti-Churn is a skills-only plugin. It has no MCP server, app, authentication, product-managed credentials, network access, telemetry, or hosted data storage.

## Package

- Plugin root: `plugins/agent-churn-control`
- Manifest: `plugins/agent-churn-control/.codex-plugin/plugin.json`
- Skill: `plugins/agent-churn-control/skills/agent-churn-control/SKILL.md`
- Local core: `plugins/agent-churn-control/scripts/churn_control.py`
- Submission data: `submission/openai-plugin-submission.json`

## Submission prerequisites

1. Freeze the public candidate and run `python tools/validate_release_candidate.py` once.
2. Publish `SpannDaMan/agent-churn-control` through the reviewed PR-first flow.
3. Confirm support, privacy, terms, repository, and release URLs resolve publicly.
4. Build the skills-only ZIP from the frozen release tree with no Git/cache residue.
5. Upload through OpenAI Platform Plugins > Create plugin > Skills only.
6. Verify the imported Orbral metadata, three prompts, one skill, and skills-only branding images; keep `interface.screenshots` excluded.
7. Run the positive and negative tests from the submission JSON.
8. Submit and publish only after the skill passes provider validation and the established policy attestations remain identical.

Submission, approval, and publication are separate states. Public availability requires independent Plugin Directory readback.
