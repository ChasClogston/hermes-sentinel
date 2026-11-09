# Sentinel Governance

**Experimental, audit-first action governance for Nous Research Hermes Agent.**
Targets **macOS and Linux**; requires Python 3.11+ and Hermes 0.23.0+ (uses Hermes bundled `hermes_yaml`; no external PyYAML dependency).

Sentinel is an independent companion to Secret Guard. It does **not** copy Secret Guard code, ingest secret values, or require Secret Guard installed.

The plugin ID is `sentinel-governance`. Install it under that name and use `sentinel-governance report` for the audit summary. Existing installations can disable and remove the old plugin before installing this version. Both versions use the same profile-local audit journal. The legacy `sentinel` command and `HERMES_SENTINEL_MODE` setting remain available for existing scripts. If both mode settings are present, `SENTINEL_GOVERNANCE_MODE` takes precedence.

## What it actually does

- Registers a Hermes `pre_tool_call` hook.
- Classifies a **small, intentionally conservative** set of terminal action proposals.
- Evaluates deterministic YAML policies with hard-deny precedence.
- Uses Hermes's native `approve` gate in enforcement mode; Sentinel does **not** run its own authenticated approval UI.
- Appends strict-schema JSONL records with HMAC-correlated destination identifiers, **never raw commands, raw URLs, or tool arguments**.
- Defaults to **audit** mode: returns no blocking or approval directive even when its computed verdict is blocked.

**Not a firewall or security sandbox.** In-process hooks do not stop actions outside Hermes, opaque tool formats, redirects, DNS changes, subprocess egress, or all dangerous shell commands. Command parsing is a deliberately restricted heuristic, not a complete shell AST. A malformed or unsupported operation is a policy `unknown`.

## Demonstrated compatibility

- On macOS, Hermes 0.23.0: 52 automated tests passed (macOS development), plugin catalog validation passed (15 checks), plugin doctor passed (1 registered hook).
- Tested real Hermes pre-tool hook dispatch in isolated audit and enforcement profiles using synthetic proposals, **without executing network commands**.
- Audited proposals produced expected `allowed`, `pending`, and `blocked` journal records.
- Verified disabling/removing the plugin leaves zero active Sentinel hooks in a new process.
- The Ubuntu CI lifecycle job checks actual Hermes plugin installation, synthetic audit dispatch and report output, disable, and removal in a disposable home.
- A disposable macOS profile on v0.5.2 exercised model-driven approval and denial. Each proposal prompted separately after an allow-once decision.

## Quick start (isolated test profile only)

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
hermes plugins validate . --install-deps
```

Copy this plugin directory to an isolated `$HERMES_HOME/plugins/sentinel-governance`; **do not use your default production home for initial tests**.

```bash
export HERMES_HOME="$HOME/sentinel-governance-test-profile"
mkdir -p "$HERMES_HOME/plugins"
cp -R /path/to/sentinel-governance "$HERMES_HOME/plugins/sentinel-governance"
export SENTINEL_GOVERNANCE_MODE=audit
hermes plugins enable sentinel-governance --no-allow-tool-override
hermes plugins doctor --ci sentinel-governance
```

Test enforcement only in this disposable profile:

```bash
export SENTINEL_GOVERNANCE_MODE=enforce
```

**Enforcement is deliberately restrictive:** recognized test commands require Hermes approval and the prompt displays their allowlisted command label, obvious credential file transfers are blocked, a recognized external transfer requests Hermes native approval, and all other unrecognized operations are blocked. This default policy is unsuitable for ordinary daily use.

### Remove

```bash
hermes plugins disable sentinel-governance
hermes plugins remove sentinel-governance
```

A running gateway may require a restart to unload hooks. Audit files under `$HERMES_HOME/sentinel/` are not deleted by the remove command. Delete only the disposable test profile after verification.

## Test and demonstration

```bash
python3 -m unittest discover -s tests -v
PYTHONPATH=. python3 demo/hook_smoke.py
```

The smoke test uses **synthetic proposed tool calls only**. It does not run `curl`, `pytest`, or any arbitrary shell command. It verifies audit-only behavior, enforcement decisions, and that the canary never appears in Sentinel's journal.

## Audit schema

An append-only-by-convention `sentinel/audit.jsonl` contains: event and action IDs, UTC timestamp, tool class, operation, HMAC-SHA256 target identifier, policy ID, verdict, and execution status. The audit key is locally generated and stored at `sentinel/audit.key`; files use mode `0600`. Raw destinations and commands are not persisted by Sentinel.

This journal is **not a complete execution log**. A verdict of `allowed` does not prove execution happened; `pending` does not prove the operator approved. Sentinel relies on Hermes-native approval prompts; it does not have a separate authorization database.

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

Hermes may auto-approve native plugin approval requests when configured for YOLO or other approval-bypass modes; do not run Sentinel enforcement with those host settings. Peer plugins may modify tool arguments after the hook examines them. Audit-mode callback timeouts may still cause Hermes itself to block even though Sentinel returns no veto. No standalone Sentinel approval store ships with this release.

Smoke invocation after installing: `PYTHONPATH=. python demo/hook_smoke.py` from the plugin root.

The recognized curl form must include `-q` immediately after `curl`, disabling implicit `.curlrc` configuration. This does not control environment proxy variables or prevent out-of-band network traffic.

## v0.5.1 second-review corrections and prompt fatigue

- Uploads require a **regular, visible, single-component file within the selected workdir**. Hidden files, absolute/parent paths, symlinks, unresolvable files and sensitive directories are denied. A filename is not proof that its **contents** are safe; this is not a DLP engine. Path checks are vulnerable to same-user time-of-check/time-of-use file replacement because Hermes executes after the hook.
- The native Hermes approval message identifies the source filename, destination hostname, a cautiously sanitized URL path, and a display-only workspace basename. Raw commands, raw URL queries, full private source paths and secret values remain excluded from Sentinel journals. Unsafe destination paths are denied rather than copied into prompts.
- Read-only network requests are labeled `network_request`; test runners are labeled `approve-local-tests` and require approval. These commands may still execute arbitrary code in a repository.
- In default audit mode, recoverable initialization errors install a nonblocking hook and warn without printing error arguments. Enforcement mode and invalid mode fail closed when hook registration is possible.
- Per-event keys prevent approval reuse, but Hermes can still store useless `session`/`always` grants in its allowlist; for Sentinel prompts those options behave as effectively single-use. Do not use auto-approval/YOLO configurations when testing enforcement.
- **Approval fatigue is not solved by broad exemptions.** v0.5.1 remains audit-first and intentionally blocks unclassified tools under enforcement. The separate follow-on project is narrowly scoped, time-limited grant reuse with a hardened trust boundary; it is not represented as implemented here.
- A terminal user should use `SENTINEL_GOVERNANCE_MODE=audit` for daily observation. Enforce mode is a strictly scoped research/demo control, not a drop-in general Hermes permission system or OS network sandbox.

## v0.5.2 — Audit classification and report

A default-deny policy decision for an action Sentinel cannot classify is still `blocked` **under enforcement**, but in **audit-only** records its displayed verdict is now `unclassified` with `classification: unclassified`, `policy_verdict: blocked`, and `execution_status: not_enforced`. Recognized hard-deny matches remain `blocked`, allowing incident review without drowning in ordinary unknown actions.

The CLI `sentinel-governance report --days 7` (or `python -m sentinel.cli report --days 7`) reads the active Hermes profile's `sentinel/audit.jsonl` and prints only aggregate counts. `--journal /path/to/synthetic.jsonl` is provided for testing. It counts **proposed tool calls**, not confirmed execution, and it separates policy matches, approval candidates, observations, and interception decisions. Existing v0.5.1 default-deny rows are recognized as unclassified using the policy ID. No individual target, command, or session identifier appears in the report.

`sentinel-governance report` does not read another profile by default, make external requests, or prove that a high-risk operation actually executed. If the current profile has no journal, the report shows zeros. Keep audit mode on for unobtrusive observability; enforcement is still narrow and may block many routine actions. The report helps quantify that prospective friction **before** choosing to enable enforcement.

**YAML compatibility:** Policies now use Hermes's `hermes_yaml.safe_load` implementation rather than importing PyYAML. The cross-platform GitHub test matrix fetches the Hermes YAML compatibility module from a pinned Hermes source commit for CI only; plugin installations do not fetch this source themselves.

**Catalog admission caveat:** Hermes 0.23.0 currently emits a rule-9 warning for the direct `import hermes_yaml` in this plugin. That module is a bundled Hermes YAML compatibility utility and avoids the external PyYAML dependency, but the loader is not formally listed as a public plugin API. We disclose the warning rather than conceal the import; catalog maintainers should confirm whether this use is acceptable.
