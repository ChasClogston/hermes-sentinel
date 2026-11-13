"""Sentinel policy demo and private aggregate report CLI."""
from __future__ import annotations
import argparse
import os
import sys
from pathlib import Path

def _journal_default() -> Path:
    try:
        from hermes_constants import get_hermes_home
        root = get_hermes_home()
    except ImportError:
        root = Path(os.environ.get('HERMES_HOME',str(Path.home()/'.hermes')))
    return root/'sentinel'/'audit.jsonl'

def _replay_days(value):
    try:
        days = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError('--days must be an integer from 1 to 3650') from None
    if not 1 <= days <= 3650:
        raise argparse.ArgumentTypeError('--days must be an integer from 1 to 3650')
    return days


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == 'replay':
        parser = argparse.ArgumentParser(prog='sentinel-governance replay',
                                         description='Counts-only estimates from read-only Hermes history')
        parser.add_argument('--policy', type=Path,
                            default=None, help='Explicit analysis policy; default is the active profile policy')
        parser.add_argument('--days', type=_replay_days, default=14)
        parser.add_argument('--all-profiles', action='store_true',
                            help='Include other profiles, which may contain other projects\' history')
        args = parser.parse_args(argv[1:])
        from .config import load_policy
        from .replay import discover_databases, display_replay, summarize_replay
        from .settings import current_home, resolve_settings
        try:
            policy = (load_policy(str(args.policy)) if args.policy is not None else
                      resolve_settings(current_home()).load_policy())
            result = summarize_replay(discover_databases(args.all_profiles),
                                      policy, days=args.days)
            print(display_replay(result, days=args.days))
            return 0
        except Exception:
            print('Sentinel Governance replay unavailable. Check the policy and Hermes installation.',
                  file=sys.stderr)
            return 2
    if argv and argv[0]=='report':
        p=argparse.ArgumentParser(prog='sentinel-governance report', description='Sanitized audit aggregates only')
        p.add_argument('--days', type=int,default=7)
        p.add_argument('--journal',type=Path, default=None,
                       help='Alternative synthetic/test journal path')
        args=p.parse_args(argv[1:])
        from .report import summarize,display_report
        try:
            summary=summarize(args.journal or _journal_default(),args.days)
            from .settings import current_home, resolve_settings
            try:
                binding = resolve_settings(current_home())
                print(f'Effective mode: {binding.mode}\nMode source: {binding.mode_source}\nPolicy source: {binding.policy_source}')
            except Exception:
                print('Effective mode: invalid (fail closed)\nMode source: invalid\nPolicy source: unavailable')
            print(display_report(summary,use_color=sys.stdout.isatty() and 'NO_COLOR' not in os.environ))
            return 0
        except (ValueError,OSError) as e:
            # Never print exception messages (can contain a private path).
            print(f'Sentinel Governance report unavailable ({type(e).__name__})',file=sys.stderr)
            return 2

    from .config import load_policy
    from .engine import Action,evaluate
    p=argparse.ArgumentParser(prog='sentinel-governance')
    p.add_argument('--policy',default=str(Path(__file__).parent.parent/'policies'/'default.yaml'))
    p.add_argument('--operation',required=True)
    p.add_argument('--tool',default='terminal')
    p.add_argument('--destination')
    p.add_argument('--source-class',default='unknown')
    args=p.parse_args(argv)
    decision=evaluate(Action(args.tool,args.operation,args.destination,args.source_class),load_policy(args.policy),os.urandom(32))
    use_color=sys.stdout.isatty() and 'NO_COLOR' not in os.environ
    colors={'allowed':'\x1b[92m','pending':'\x1b[93m','blocked':'\x1b[91m'}
    prefix=colors[decision.verdict] if use_color else ''
    suffix='\x1b[0m' if use_color else ''
    print(f'+----------------------------------------+\n| SENTINEL GOVERNANCE // POLICY DECISION |\n+----------------------------------------+\n| {prefix}{decision.verdict.upper():<38}{suffix} |\n| Rule: {decision.rule_id[:31]:<32} |\n+----------------------------------------+')
    return 0 if decision.verdict=='allowed' else 2

if __name__=='__main__':
    raise SystemExit(main())

