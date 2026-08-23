# Claude Code installation

Anti-Churn ships as a skills-only Claude Code plugin. It does not install an MCP server, request credentials, make network calls, publish, or change permissions.

After the public repository is available:

```text
/plugin marketplace add SpannDaMan/agent-churn-control
/plugin install anti-churn@agent-churn-control
```

Run `/reload-plugins` when Claude Code asks for it. The skill is namespaced under the `anti-churn` plugin identifier while the repository and package slug remain `agent-churn-control`.

Before distribution, validate both the repository marketplace and plugin package:

```text
claude plugin validate . --strict
claude plugin validate plugins/agent-churn-control --strict
```
