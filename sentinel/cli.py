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

def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0]=='report':
        p=argparse.ArgumentParser(prog='sentinel report', description='Sanitized audit aggregates only')
        p.add_argument('--days', type=int,default=7)
        p.add_argument('--journal',type=Path, default=None,
                       help='Alternative synthetic/test journal path')
        args=p.parse_args(argv[1:])
        from .report import summarize,display_report
        try:
            summary=summarize(args.journal or _journal_default(),args.days)
            print(display_report(summary,use_color=sys.stdout.isatty() and 'NO_COLOR' not in os.environ))
            return 0
        except (ValueError,OSError) as e:
            # Never print exception messages (can contain a private path).
            print(f'Sentinel report unavailable ({type(e).__name__})',file=sys.stderr)
            return 2

    from .config import load_policy
    from .engine import Action,evaluate
    p=argparse.ArgumentParser(prog='sentinel')
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
    print(f'+----------------------------------------+\n| HERMES SENTINEL // POLICY DECISION     |\n+----------------------------------------+\n| {prefix}{decision.verdict.upper():<38}{suffix} |\n| Rule: {decision.rule_id[:31]:<32} |\n+----------------------------------------+')
    return 0 if decision.verdict=='allowed' else 2

if __name__=='__main__':
    raise SystemExit(main())
