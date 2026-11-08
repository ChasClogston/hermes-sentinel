# Hermes Sentinel

**Experimental, audit-first action governance for Nous Research Hermes Agent.**
Targets **macOS and Linux**; requires Python 3.11+ and PyYAML 6.x.

Sentinel is an independent companion to Secret Guard. It does **not** copy Secret Guard code, ingest secret values, or require Secret Guard installed.

## What it actually does

- Registers a Hermes `pre_tool_call` hook.
- Classifies a **small, intentionally conservative** set of terminal action proposals.
- Evaluates deterministic YAML policies with hard-deny precedence.
- Uses Hermes's native `approve` gate in enforcement mode; Sentinel does **not** run its own authenticated approval UI.
- Appends strict-schema JSONL records with HMAC-correlated destination identifiers, **never raw commands, raw URLs, or tool arguments**.
- Defaults to **audit** mode: returns no blocking or approval directive even when its computed verdict is blocked.

**Not a firewall or security sandbox.** In-process hooks do not stop actions outside Hermes, opaque tool formats, redirects, DNS changes, subprocess egress, or all dangerous shell commands. Command parsing is a deliberately restricted heuristic, not a complete shell AST. A malformed or unsupported operation is a policy `unknown`.

## Demonstrated compatibility

- On macOS, Hermes 0.23.0: 39 unit tests passed, plugin catalog validation passed (15 checks), plugin doctor passed (1 registered hook).
- Tested real Hermes pre-tool hook dispatch in isolated audit and enforcement profiles using synthetic proposals, **without executing network commands**.
- Audited proposals produced expected `allowed`, `pending`, and `blocked` journal records.
- Verified disabling/removing the plugin leaves zero active Sentinel hooks in a new process.
- Linux: Python tests run independently; **a live Linux Hermes installation has not yet been validated**.
- A model-driven, end-to-end approval acceptance/denial test remains to be completed.

## Quick start (isolated test profile only)

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
hermes plugins validate . --install-deps
```

Copy this plugin directory to an isolated `$HERMES_HOME/plugins/hermes-sentinel`; **do not use your default production home for initial tests**.

```bash
export HERMES_HOME="$HOME/hermes-sentinel-test-profile"
mkdir -p "$HERMES_HOME/plugins"
cp -R /path/to/hermes-sentinel "$HERMES_HOME/plugins/hermes-sentinel"
export HERMES_SENTINEL_MODE=audit
hermes plugins enable hermes-sentinel --no-allow-tool-override
hermes plugins doctor --ci hermes-sentinel
```

Test enforcement only in this disposable profile:

```bash
export HERMES_SENTINEL_MODE=enforce
```

**Enforcement is deliberately restrictive:** `pytest` is allowed, obvious credential file transfers are blocked, a recognized external transfer requests Hermes native approval, and all other unrecognized operations are blocked. This default policy is unsuitable for ordinary daily use.

### Remove

```bash
hermes plugins disable hermes-sentinel
hermes plugins remove hermes-sentinel
```

A running gateway may require a restart to unload hooks. Audit files under `$HERMES_HOME/sentinel/` are not deleted by the remove command. Delete only the disposable test profile after verification.

## Test and demonstration

```bash
python3 -m unittest discover -s tests -v
python3 demo/hook_smoke.py
```

The smoke test uses **synthetic proposed tool calls only**. It does not run `curl`, `pytest`, or any arbitrary shell command. It verifies audit-only behavior, enforcement decisions, and that the canary never appears in Sentinel's journal.

## Audit schema

An append-only-by-convention `sentinel/audit.jsonl` contains: event and action IDs, UTC timestamp, tool class, operation, HMAC-SHA256 target identifier, policy ID, verdict, and execution status. The audit key is locally generated and stored at `sentinel/audit.key`; files use mode `0600`. Raw destinations and commands are not persisted by Sentinel.

This journal is **not a complete execution log**. A verdict of `allowed` does not prove execution happened; `pending` does not prove the operator approved. SQLite `ApprovalStore` is a standalone prototype, not yet wired into the runtime hook.

## Limitations and trust boundaries

- Raw tool arguments exist temporarily inside the hook and in Hermes itself. Sentinel only controls its own journal formatting.
- Exact secret confidentiality in other Hermes, MCP, shell, or frontend logs cannot be guaranteed by this plugin.
- The current `terminal` tool classifier is intentionally narrow; unsupported tools return `unknown`.
- A user or compromised tool with the same OS privileges can modify the plugin, policies, and local audit journal.
- Do not treat hook authorization as OS-level egress control.
- The ANSI/retro terminal presentation is a future milestone, not an implemented plugin frontend.

## License and development

Independent repository and release cadence from Secret Guard. No vendored code or runtime dependency. This plugin is experimental and should be evaluated with synthetic data in disposable profiles before any production use.

## Required disclosures

Sentinel itself makes no third-party network requests, executes no shell commands, runs no background processes, and reads no external credential stores. It inspects the proposed command arguments passed by Hermes to its hook and reads its own policy YAML and locally generated audit key. It writes only a local HMAC key and sanitized JSONL records under the active Hermes home. It does not store raw command arguments, URLs, or secret values. Hermes and other tools may separately log or transmit their own data.

## v0.5 security review remediation

An independent adversarial review identified weaknesses in v0.4.0. Version 0.5 narrows command recognition to a restricted, exact curl grammar, uses a fresh `rule_key` per approval request to prevent session/always grants carrying over, and displays only an operation, hostname and source classification in approval messages. All unknown tools and shell expressions are denied in enforce mode. This is a conservative prototype, **not general shell-policy enforcement**.

Audit-only records now say `execution_status: not_enforced`, not `not_executed`: they represent a *would-be* policy verdict, not the actual execution outcome. Enforcement records mean `approval_requested` or `not_observed`, not a claim that a human approved or that the tool executed. Hermes post-execution correlation is still future work.

Test runners execute arbitrary repository-controlled code and now require approval. Mode typos and audit-key initialization errors install a blocking fallback hook, but complete failure to import or load this plugin still causes Hermes to run without the hook; verify it is loaded before assuming enforcement. Startup key creation uses an atomic link and separate profiles resolve audit keys/journals in their current Hermes home.

Hermes may auto-approve native plugin approval requests when configured for YOLO or other approval-bypass modes; do not run Sentinel enforcement with those host settings. Peer plugins may modify tool arguments after the hook examines them. Audit-mode callback timeouts may still cause Hermes itself to block even though Sentinel returns no veto. The standalone SQLite ApprovalStore remains unused and is **not** an approval security boundary.

Smoke invocation after installing: `PYTHONPATH=. python demo/hook_smoke.py` from the plugin root.
