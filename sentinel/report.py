"""Private, aggregate-only summary of Sentinel's append-only JSONL decisions.

Never prints tool arguments, hostnames, URLs, profile IDs or per-event records.
Counts describe proposed tool calls and Sentinel policy, not confirmed execution.
"""
from __future__ import annotations
import json
import os
import stat
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

_MAX_DAYS = 365
_MAX_LINE = 16384


def summarize(path: str | Path, days: int = 7, now: datetime | None = None) -> dict:
    if type(days) is not int or not 1 <= days <= _MAX_DAYS:
        raise ValueError('report days must be 1..365')
    now = now or datetime.now(timezone.utc)
    threshold = now - timedelta(days=days)
    counts = Counter()
    errors = 0
    source = Path(path)
    if not source.exists():
        return {'days': days, 'total': 0, 'counts': counts, 'invalid_rows': 0}
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(source, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError('report refuses unsafe journal file')
        with os.fdopen(fd, 'r', encoding='utf-8', errors='replace', closefd=False) as stream:
            for line in stream:
                if len(line) > _MAX_LINE:
                    errors += 1
                    continue
                try:
                    row = json.loads(line)
                    ts = datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
                    if ts.tzinfo is None:
                        raise ValueError('naive timestamp')
                    if not threshold <= ts <= now + timedelta(minutes=5):
                        continue
                    if row.get('event_type') is not None:
                        from .audit import read_key, verify_control_event
                        try:
                            key = read_key(source.parent / 'audit.key')
                            if not verify_control_event(row, key):
                                raise ValueError('invalid control signature')
                        except (OSError, ValueError):
                            errors += 1
                            continue
                        counts[row['event_type']] += 1
                        continue
                    mode = row['enforcement_mode']
                    status = row['execution_status']
                    classification = row.get('classification')
                    if classification not in ('matched', 'unclassified'):
                        classification = ('unclassified' if row.get('policy_id')=='default-deny'
                                          else 'matched')
                    verdict = row.get('policy_verdict', row.get('verdict'))
                    if classification == 'unclassified':
                        counts['unclassified'] += 1
                    elif verdict == 'blocked':
                        counts['hard_deny_matches'] += 1
                    elif verdict == 'pending':
                        counts['approval_candidates'] += 1
                    elif verdict == 'allowed':
                        counts['policy_allows'] += 1
                    else:
                        raise ValueError('invalid verdict')
                    if mode == 'audit':
                        counts['audit_only'] += 1
                    elif mode == 'enforce':
                        counts['enforce_mode'] += 1
                        if status == 'blocked_by_sentinel':
                            counts['actual_sentinel_blocks'] += 1
                        elif status == 'approval_requested':
                            counts['approval_requests'] += 1
                    else:
                        raise ValueError('invalid mode')
                    counts['total'] += 1
                except (ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError):
                    errors += 1
    finally:
        os.close(fd)
    return {'days': days, 'total': counts['total'], 'counts': counts, 'invalid_rows': errors}


def display_report(result: dict, use_color: bool = False) -> str:
    c = result['counts']
    rows = (
        ('Observed proposals', result['total']),
        ('Unclassified', c['unclassified']),
        ('Hard-deny policy matches', c['hard_deny_matches']),
        ('Approval candidates', c['approval_candidates']),
        ('Policy allows', c['policy_allows']),
        ('Audit-only observations', c['audit_only']),
        ('Enforcement requests', c['approval_requests']),
        ('Sentinel Governance block decisions', c['actual_sentinel_blocks']),
        ('Invalid/ignored rows', result['invalid_rows']),
        ('Signed mode-change events', c['mode_change']),
        ('Signed policy-load failures', c['policy_load_failure']),
    )
    # All labels are constants and all values are validated aggregate integers.
    lines = ['+--------------------------------------------------+',
             f'| {"SENTINEL GOVERNANCE // AUDIT REPORT":<48} |',
             '+--------------------------------------------------+',
             f'| Window: last {result["days"]:>3} days                             |']
    for name, value in rows:
        lines.append(f'| {name:<35} {value:>10} |')
    lines += ['+--------------------------------------------------+',
              'Proposed actions only; no post-execution verification.',
              'Unclassified means default-deny under enforcement,',
              'not an observed block during audit-only operation.']
    if use_color:
        lines[1] = '\x1b[92m'+lines[1]+'\x1b[0m'
    return '\n'.join(lines)
