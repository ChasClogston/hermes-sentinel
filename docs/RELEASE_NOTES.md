# v0.6.1 candidate

This candidate remains subject to independent review before merge or catalog repinning.

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

Snapshots left in a different root by older XDG-based builds are not discovered automatically; known legacy locations require ownership-checked inspection/cleanup. Linux `/tmp` capacity and backing filesystem remain system-configured; this change does not promise unlimited or disk-backed temporary space. The rare worker-startup SIGINT traceback containing standard-library paths and the existing timeout/skip accounting are outside these two fixes.

A copy that exhausts the replay time budget marks the sample limited; it does not increment failed/skipped-database accounting.
