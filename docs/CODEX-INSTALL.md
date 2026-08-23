# Codex Installation

## Public marketplace install

```text
codex plugin marketplace add SpannDaMan/agent-churn-control
codex plugin add agent-churn-control@agent-churn-control
```

Start a new Codex task after installation so the skill enters the new prompt context.

## Verify

```text
codex plugin list
python plugins/agent-churn-control/scripts/churn_control.py self-test
python plugins/agent-churn-control/scripts/churn_control.py verify-package
```

The installed plugin should report version `0.1.0`, developer `Orbral`, one skill, no apps, and no MCP server. Use the absolute installed plugin root shown by `codex plugin list` when invoking `scripts/churn_control.py`; do not assume the user's project contains the plugin scripts.

## Remove

Use the Codex plugin removal command shown by your installed Codex CLI, then remove the marketplace only when no other installed plugin depends on it.
