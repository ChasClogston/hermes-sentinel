# Sentinel Governance

**Experimental, audit-first action governance for Nous Research Hermes Agent.**
Targets **macOS and Linux**; requires Python 3.11+ and Hermes 0.23.0+ (uses Hermes bundled `hermes_yaml`; no external PyYAML dependency).

Sentinel is an independent companion to Secret Guard. It does **not** copy Secret Guard code or require Secret Guard installed. Replay snapshots contain raw history, which may itself contain sensitive values; see the temporary-storage disclosure below.

The plugin ID is `sentinel-governance`. Install it under that name and use `sentinel-governance report` for the audit summary. Existing installations can disable and remove the old plugin before installing this version. Both versions use the same profile-local audit journal. The legacy `sentinel` command and `HERMES_SENTINEL_MODE` setting remain available for existing scripts. If both environment variables are present, `SENTINEL_GOVERNANCE_MODE` takes precedence over the legacy variable. Profile settings are authoritative; the selected environment value can only tighten them, as described below.

## What it actually does

- Registers a Hermes `pre_tool_call` hook.
- Classifies a **small, intentionally conservative** set of terminal action proposals.
- Evaluates deterministic YAML policies with hard-deny precedence.
- Uses Hermes's native `approve` gate in enforcement mode; Sentinel does **not** run its own authenticated approval UI.
- Appends strict-schema JSONL records with HMAC-correlated destination identifiers, **never raw commands, raw URLs, or tool arguments**.
- Defaults to **audit** mode: returns no blocking or approval directive even when its computed verdict is blocked.

**Not a firewall or security sandbox.** In-process hooks do not stop actions outside Hermes, opaque tool formats, redirects, DNS changes, subprocess egress, or all dangerous shell commands. Command parsing is a deliberately restricted heuristic, not a complete shell AST. A malformed or unsupported operation is a policy `unknown`.

## Demonstrated compatibility

- The v0.6.0 baseline had 59 automated tests plus catalog validation (15 checks) and plugin doctor (1 hook) on Hermes 0.23.0. The merged v0.6.1 release adds regressions: 92 unit tests and real pinned-Hermes history fixtures passed on MBP; CI separately verifies macOS and Linux lifecycle behavior.
- Tested real Hermes pre-tool hook dispatch in isolated audit and enforcement profiles using synthetic proposals, **without executing network commands**.
- Audited proposals produced expected `allowed`, `pending`, and `blocked` journal records.
- Verified disabling/removing the plugin leaves zero active Sentinel hooks in a new process.
- The macOS and Ubuntu CI lifecycle jobs check actual Hermes plugin installation, synthetic audit dispatch, replay, permitted alternatives, disable, and removal in disposable homes.
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

## Profile settings (v0.7.0)

In the selected Hermes profile's `config.yaml`, configure the plugin without relying on a shell environment:

```yaml
plugins:
  enabled: [sentinel-governance]
  entries:
    sentinel-governance:
      settings:
        mode: audit
        policy_path: sentinel/policy.yaml
```

Omit `policy_path` to use the bundled default. Omit `mode` for audit. The public Hermes `ctx.get_config` API also supports its legacy `config` subtree fallback. Sentinel reads mode and policy **per active profile, on each hook call**, with no shared mutable mode. A multiplexed profile switch therefore changes settings, policy, journal and audit key together. A malformed mode fails closed. A refused/unparsable policy or journal failure observes only in audit and blocks in enforce.

Mode is `enforce` if either the setting or selected environment value is enforce. Otherwise it is audit. Settings enforce plus environment audit remains enforce. An invalid value in either selected source blocks; case and surrounding whitespace are normalized. `SENTINEL_GOVERNANCE_MODE` takes precedence over the legacy `HERMES_SENTINEL_MODE` environment variable, whose value is then ignored. Registration logs the effective mode, mode source (`default`, `settings`, `environment`, or `settings+environment`) and policy source (`bundled` or `profile`). `sentinel-governance report` prints those same sources without policy contents or private paths. These are current configuration values, not a claim that an already-running process was restarted or that past events used those settings.

A custom policy must be inside the active Hermes home. Relative paths are rooted there; an absolute path inside that home is also accepted. Sentinel rejects traversal, symlinks (including intermediate directories), non-regular files, multiply-linked files, files not owned by the current user or root, and files writable by group or others. The home and intermediate policy directories must not be group/other writable either. Verification and reading use the same opened file descriptor. Use an owner-controlled file, for example mode 0600. Keep it under the profile, outside the installed plugin: an update replaces the plugin without overwriting the policy. No fallback to bundled rules occurs when a configured policy is invalid.

### Exact tool rules and whole-tool trust

```yaml
version: 1
rules:
  - id: allow-read-tools
    effect: allow
    operations: [unknown]
    tools: [read_file, search_files, secret_request]
  - id: approve-writes
    effect: require_approval
    operations: [unknown]
    tools: [write_file, patch]
```

`tools` is an optional, nonempty list of exact, case-sensitive names (letters, digits, `_ . : -`, at most 160 characters). It narrows every rule to those tools; it has no wildcard or basename matching. An absent matcher retains prior matching behavior. Hard denies override all other rules; equal-priority approval beats allow. Invalid destinations remain blocked.

An `allow` for `unknown` requires a `tools` list and refuses `terminal` or `execute_code` (including case variants). Other named tools are an explicit operator trust decision: **the whole tool is allowed, and Sentinel does not inspect its arguments**. Allowing `write_file` permits writes to any path Hermes permits. A named MCP/plugin tool can do anything its server or implementation permits, including executing code under a different name. Sentinel's matcher does not attest to a tool's implementation or capabilities. Other Hermes and plugin checks still apply. Journal names remain the private `terminal`/`other` classes; raw names and arguments are not added.

Replay uses this exact matcher. Without `--policy`, it loads the selected profile's configured policy; `--policy P` deliberately selects a separate analysis policy. With `--all-profiles`, all histories are estimated against that one selected policy, not each historical profile's policy. Counts are estimates, not execution or approval evidence.

The v0.7.0 test fixture uses cleared mode environment variables and real Hermes dispatch with synthetic final effects. It checks settings-only enforce, named tools without approvals, unknown-tool denial, approval-required writes, policy survival across plugin-directory replacement, and real SessionDB replay parity. No live credential store is touched. Optional policy self-test CLI and proving-ground contracts are deferred.

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

An append-only-by-convention `sentinel/audit.jsonl` contains: event and action IDs, UTC timestamp, tool class, operation, HMAC-SHA256 target identifier, policy ID, verdict, and execution status. The audit key is locally generated and stored at `sentinel/audit.key`; files use mode `0600`. Raw destinations and commands are excluded from this audit journal; replay has a separate temporary-storage disclosure below.

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

The runtime hook inspects proposed tool arguments in memory and reads its policy YAML and locally generated audit key. It writes a local HMAC key and sanitized JSONL journal under the active Hermes home. The hook initiates no network requests or subprocesses and reads no external credential stores. The user-invoked replay CLI makes a protected temporary raw copy of each selected history database and any WAL/rollback journal, then reads that copy through the public read-only SessionDB interface. The snapshot directory is owner-only (0700), files are 0600, and Hermes initialization uses an isolated home with the inherited environment cleared. Only aggregate integer counts return to the CLI; worker diagnostics are suppressed and replay adds no audit journal entries. The parent records Ctrl-C (SIGINT), termination (SIGTERM), or terminal/SSH closure (SIGHUP) as shutdown requests and exits with signal status after worker shutdown and snapshot cleanup. It polls for requests at short intervals. These signals cannot raise into parent cleanup. Critical deletion and worker shutdown also mask ordinary signals, restoring the prior mask afterward. The ownership marker is removed only after the contents, so a deletion error retains a marked recoverable directory. Normal completion and worker timeout use the same cleanup. If only the parent is killed with SIGKILL, the surviving worker checks its parent identity while copying/scanning, stops and removes its scratch directory. Killing both processes or power loss can still leave owner-only files. A later valid replay sweeps marked, owner-only, unleased directories older than 60 seconds; fresh, active, unmarked, unsafe or inaccessible directories are left alone. Cleanup is best effort under filesystem errors; deletion is not secure erasure. Snapshots use the user-owned private system temporary root on macOS when outside HOME and selected Hermes profiles, otherwise /tmp. Linux consistently uses /tmp. Both TMPDIR and XDG_RUNTIME_DIR are ignored for snapshot placement and startup sweeping. Leftovers in different roots used by older XDG-based builds are not discovered automatically. If no safe root is outside HOME and the selected profiles, replay is unavailable. Copying includes the complete database, so time and temporary disk usage grow with total history size, even for a short date window. The two-second worker budget includes copying and scanning; startup stale cleanup and the process-stop/cleanup interval add overhead. Replay must be invoked from the main thread so scoped signal handlers can be installed and restored. Hermes and other tools have their own logging behavior.

## v0.5 security review remediation

An independent adversarial review identified weaknesses in v0.4.0. Version 0.5 narrows command recognition to a restricted, exact curl grammar, uses a fresh `rule_key` per approval request to prevent session/always grants carrying over, and displays only an operation, hostname and source classification in approval messages. With the bundled default policy, all unknown tools and shell expressions are denied in enforce mode. This is a conservative prototype, **not general shell-policy enforcement**.

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


## Refusals and permitted alternatives

A policy block now instructs the agent to continue with an alternative that complies with the policy and its existing authorization. It asks the user when completing the task requires an exception or additional authorization. Each proposed alternative goes through the usual policy evaluation. Explicit allow rules continue automatically, approval rules request approval, and deny rules block. The default policy still requires approval for test runners and denies unrecognized operations.

The integration check exercises actual Hermes tool dispatch with an isolated test policy. It blocks one proposal, executes an explicitly allowed local fixture without requesting approval, then verifies that an approval-required proposal still requests approval. This checks the permission path. Model compliance with the wording can vary.

## Counts only history replay

Run these commands from a Hermes runtime with the plugin available on its Python path.

```bash
sentinel-governance replay --days 14
sentinel-governance replay --policy /path/to/proposed-policy.yaml --days 7
sentinel-governance replay --all-profiles --days 14
# Within an installed plugin directory
python -m sentinel.cli replay --days 14
```

Replay estimates enforce-mode decisions using the current classifier and selected policy. It reads the current profile by default. The explicit `--all-profiles` flag also includes other profiles, which can contain other projects' history. The CLI outputs only counts by operation and verdict, including unclassified and skipped calls. It runs separately from live model sessions.

A scan classifies at most 2,000 in-window calls, scans at most 20,000 messages, and selects at most 200 sessions, with a two-second worker deadline. Out-of-window calls do not spend the call budget; plain messages still spend the message/time budgets. Sessions are selected with the current profile first, then the other selected profiles. Each database is copied, scanned and released before the next database, with current profile first. Within a database, pages are visited round-robin across selected sessions, newest first within each session. There is no round-robin fairness across profiles. Counts from earlier databases are emitted immediately and retained if a later copy times out. All profiles share the same call/message/session/time budgets. A cap marks the sample incomplete only when another item exists; timeouts and skipped databases also mark it incomplete.

Hidden, child, subagent, archived, and rotated physical sessions are included once each. Each is read without ancestor expansion, avoiding duplicate rotation counts. Retained compaction history uses Hermes's display deduplication. Rewound rows (inactive and not compacted) are explicitly excluded, as is malformed data that Hermes's API discards before returning messages. Observable calls with a recognizable tool name and malformed/empty arguments are evaluated conservatively as unclassified, rather than silently omitted. Nested and flat function records, dictionary arguments, and large arguments are supported. Counts describe retained tool proposals, not unique executions across explicit conversation branches.

Missing or symlinked database files are filtered before starting the reader; no original profile is created. Database and existing WAL/rollback-journal files are opened as regular files without following their final symlink. File identities, sizes and modification/change times are checked before and after copying all components; detected concurrent changes cause one retry in a fresh attempt directory if time remains, then that database is skipped if the source remains unstable. This is a best-effort stable capture, not a transactional backup of a continuously changing source. SQLite opens only the private copy, so any SQLite sidecar creation or Hermes profile scaffolding stays there.

Historical source paths are evaluated against the current filesystem. Stored argument workdirs are honored; a missing workdir falls back to the replay invocation directory, not a reconstructed historical directory. Files that moved or disappeared can affect classification. These estimates describe proposed actions under today's policy and filesystem context. They do not establish historical execution or approval outcomes. Replay preserves the existing journal schema and runtime policy defaults.


## Historical v0.6.1 review fixes

Equal-priority matching rules prefer `require_approval` over `allow`, independent of rule names. Hard denies continue to override all allows and approvals. Policies that allow the `unknown` operation are now rejected: the classifier groups arbitrary commands and other tools into that category, so it cannot safely represent a narrow tool exemption. Use recognized operations; a separate tool matcher is outside this patch.

A genuine policy block retains permitted-alternative guidance. Evaluation failures and startup health-check failures instead say to stop and tell the user that Sentinel needs attention. They do not suggest alternatives while the failure blocks every tool. The replay `--days` argument accepts integers from 1 through 3650 and reports range errors directly.

The cross-platform lifecycle jobs run synthetic fixtures against pinned Hermes, including rotation/children/hidden/subagents, compaction, named rewind exclusion, stored argument variants, window/message budgets, an open WAL source, unchanged original profile trees, and temporary-snapshot cleanup. No real history or credentials are used.


### v0.6.1 re-review remediation

Shutdown and orphan-worker cleanup, lease-protected stale cleanup, incremental copy/scan with partial-result retention, one bounded source-change retry, and distinct failed-database counting have regression coverage in both lifecycle jobs. Startup sweeping requires our versioned ownership marker, mode 0700 directory, mode 0600 single-link regular marker, matching user ownership, age over 60 seconds and an exclusive nonblocking lease. It never follows a marker/directory symlink or deletes an active leased replay. Older unmarked snapshots from pre-remediation builds are deliberately not swept automatically.

See [release notes](docs/RELEASE_NOTES.md) for the incompatible unknown-allow policy behavior and remaining limitations. The snapshot design remains user-approved; no tool matcher or APFS-specific clone optimization is added in this patch.
