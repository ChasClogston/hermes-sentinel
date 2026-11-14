# v0.7.0 candidate

Separate follow-up to merged v0.6.1 / PR #7. Not production-enabled and not catalog-repinned.

## PR #8 independent-review corrections

- Refuse unclassified terminal/execute_code approvals as well as allows, including blanket unknown approvals with no tools list. Other whole-tool approval prompts explicitly grant one invocation of any operation the tool permits, without pretending arguments were shown.
- Apply mandatory pre-rule protections to read_file/write_file/patch: protect governance files from writes, credential-shaped paths from reads/writes, and check every patch/move target. Known file tools require canonical absolute host paths; ambiguous/relative/aliased/special/multiply-linked targets and unrecognized patch formats are refused. This tightens the original whole-tool contract; it does not inspect other arguments or attest to other named tools.
- Latch enforce per profile/process at registration or first resolution until process restart, surviving settings loss, requested downgrade and hook re-registration. Invalid mode remains blocking. Log and HMAC-sign requested mode changes, including refused downgrades.
- Journal policy-load failure once per profile/process when the journal/key are usable. Report shows current policy health with sanitized reason codes and separately counts authenticated configuration events without inflating proposal totals. CLI configuration mode cannot establish a running process's latch.
- Local signatures are record HMACs, not a chain or protection from same-privilege/key holders. File checks do not close inspection/execution races or opaque-tool/server bypasses. Finding 5's broader capability policy is deferred; only terminal/execute_code are refused by the unknown allow/approval loader.
- Actual Hermes dispatch fixtures use synthetic effects and approvals, including Sentinel-only credential reads, self-modifying write attempts, lost/invalid settings, ordinary permitted file alternatives, audit failure visibility and real replay parity. See README for the complete boundary and compatibility notes.


- Read `mode` and `policy_path` from public Hermes plugin settings on each active-profile call. Environment may tighten audit to enforce but cannot loosen settings enforce; invalid selected mode values fail closed. Startup logs and the read-only report show mode and source without private paths.
- Honor a profile-local custom policy without editing the installed plugin. Refuse symlinks, escaping/traversing paths, special or multiply-linked files, unsafe ownership and group/other-writable files/directories. Opened descriptors bind validation to reads. Invalid policy observes in audit and blocks in enforce; never silently use bundled rules instead.
- Add optional exact `tools` matching. Unknown allow/approval now requires a nonempty named-tool list excluding terminal/execute_code. Hard-deny and approval priority and invalid-destination protection remain. Journal tool classes stay unchanged.
- A named allow grants the whole tool subject to the known-file-tool protections; other arguments and server capabilities are not inspected. A tool may write anywhere the host permits or perform any operation its implementation supports. This is operator trust, not capability isolation. Other host/plugin gates remain.
- Replay defaults to the selected profile policy and uses the same tool matcher as live calls. An explicit `--policy` selects the analysis policy; all-profile replay uses one selected policy for all histories.
- Add settings-only real-Hermes enforcement, named-tool and real history parity fixtures, plus mode/unsafe-file/concurrent-profile regressions. The fixture replaces a disposable plugin directory and verifies the external profile policy survives. Existing replay snapshot protections and accepted limitations are unchanged.

See the README for configuration and trust disclosures. The `hermes_yaml` catalog warning remains unresolved pending maintainer guidance. Catalog PR #155058 remains draft and its pin stays on v0.6.0; no re-pin is part of this change. Optional self-test CLI/proving-ground contract and broader classifier backlog are deferred.

---

# v0.6.1 (merged PR #7)

Merged after Claude cleared exact head defc0d0. Catalog repinning remains on hold.

## Policy compatibility

Policies containing `effect: allow` for the `unknown` operation no longer load. This category includes arbitrary unclassified commands and other tools, so an unknown allow is not a safe tool-specific exemption. Correct the policy to use recognized operations. In enforce mode, evaluation failure blocks every proposed tool call with the stop-and-report failure message until the policy is corrected. Audit mode logs a sanitized failure and issues no veto. Replay exits with an unavailable message for an invalid policy. No new tool matcher is included.

## Temporary history snapshots

Replay copies raw database/WAL/rollback-journal files into a 0700 private directory, with 0600 files. Raw history may contain sensitive values. On macOS, prefer the user-owned private system temporary root outside HOME and selected profiles, otherwise use `/tmp`. Linux consistently uses `/tmp`. Both TMPDIR and XDG_RUNTIME_DIR are ignored for snapshot placement and startup sweeping. Replay is unavailable when no safe root is outside HOME and the selected profiles.

Normal completion, worker timeout, Ctrl-C, SIGTERM and SIGHUP run parent cleanup. A surviving worker detects parent death during copying/scanning and cleans up its own scratch directory. SIGKILL of both processes, power loss or filesystem errors can leave private files. A later valid replay removes only marked owner-only directories older than 60 seconds when no process holds a lease. Fresh, active, unsafe, inaccessible and unmarked directories are left alone, including legacy unmarked snapshots from earlier builds. Deletion is not secure erasure. Replay requires the main thread; prior signal handlers are restored afterward.

Each selected database is copied, scanned and released in order, current profile first. Sessions are paged round-robin within that database. Earlier counts remain available after a later copy timeout. Copy time and storage grow with the full database size, including history outside the requested window. One source-change retry is attempted only when time remains; a persistently changing source is skipped honestly.

All profiles share the two-second worker startup/copy/scan budget, 2,000 in-window calls, 20,000 messages and 200 sessions. Startup stale cleanup and process-stop/cleanup add overhead. There is no cross-profile round-robin fairness. Compaction deduplication and explicitly named rewind/upstream-malformed-data exclusions remain.

The `hermes_yaml` rule-9 catalog warning remains disclosed and awaits maintainer guidance. Audit callback timeouts can still make Hermes itself block. Production enforcement is not enabled by this release preparation.


## Focused cleanup follow-up

Ordinary parent signals are recorded as shutdown requests, observed by short polling, and converted to signal exit status only after cleanup. Worker termination/join and destructive deletion mask SIGINT/SIGTERM/SIGHUP with the prior mask restored afterward. This also protects cleanup that began for normal completion or the time budget. Directory contents are removed relative to a verified directory descriptor; the ownership marker is deleted last. If a content deletion fails, the marker stays for eligible later recovery. SIGKILL, power loss and filesystem errors retain the limitations above.

Focused regressions inject all three ordinary signals at deletion and worker-termination boundaries, force marker-first filesystem enumeration, and inject a content deletion error. Both lifecycle jobs run these tests plus the stable Linux temp-root and preserved macOS system-root checks. Test subprocesses inherit the caller-selected Sentinel package path, so the documented unit-test command works from a bare checkout with the Hermes dependencies available.

Snapshots left in a different root by older XDG-based builds are not discovered automatically; known legacy locations require ownership-checked inspection/cleanup. Linux `/tmp` capacity and backing filesystem remain system-configured; this change does not promise unlimited or disk-backed temporary space. The rare worker-startup SIGINT traceback containing standard-library paths is accepted as is. Unmarked directories remain deliberately unswept.

A copy that exhausts the replay time budget marks the sample limited; it does not increment failed/skipped-database accounting.
