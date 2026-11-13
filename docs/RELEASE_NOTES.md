# v0.6.1 candidate

This candidate remains subject to independent review before merge or catalog repinning.

## Policy compatibility

Policies containing `effect: allow` for the `unknown` operation no longer load. This category includes arbitrary unclassified commands and other tools, so an unknown allow is not a safe tool-specific exemption. Correct the policy to use recognized operations. In enforce mode, evaluation failure blocks every proposed tool call with the stop-and-report failure message until the policy is corrected. Audit mode logs a sanitized failure and issues no veto. Replay exits with an unavailable message for an invalid policy. No new tool matcher is included.

## Temporary history snapshots

Replay copies raw database/WAL/rollback-journal files into a 0700 private directory, with 0600 files. Raw history may contain sensitive values. On macOS, prefer the user-owned private OS temporary root; on Linux, prefer a user-owned private XDG runtime directory. The root must be outside HOME and selected profiles; otherwise use `/tmp`. Caller-controlled TMPDIR is ignored. Replay is unavailable when no safe root is outside HOME and the selected profiles.

Normal completion, worker timeout, Ctrl-C, SIGTERM and SIGHUP run parent cleanup. A surviving worker detects parent death during copying/scanning and cleans up its own scratch directory. SIGKILL of both processes, power loss or filesystem errors can leave private files. A later valid replay removes only marked owner-only directories older than 60 seconds when no process holds a lease. Fresh, active, unsafe, inaccessible and unmarked directories are left alone, including legacy unmarked snapshots from earlier builds. Deletion is not secure erasure. Replay requires the main thread; prior signal handlers are restored afterward.

Each selected database is copied, scanned and released in order, current profile first. Sessions are paged round-robin within that database. Earlier counts remain available after a later copy timeout. Copy time and storage grow with the full database size, including history outside the requested window. One source-change retry is attempted only when time remains; a persistently changing source is skipped honestly.

All profiles share the two-second worker startup/copy/scan budget, 2,000 in-window calls, 20,000 messages and 200 sessions. Startup stale cleanup and process-stop/cleanup add overhead. There is no cross-profile round-robin fairness. Compaction deduplication and explicitly named rewind/upstream-malformed-data exclusions remain.

The `hermes_yaml` rule-9 catalog warning remains disclosed and awaits maintainer guidance. Audit callback timeouts can still make Hermes itself block. Production enforcement is not enabled by this release preparation.
