"""Safe demo CLI. Never prints raw arguments or destinations."""
import argparse
import os
from pathlib import Path
from .config import load_policy
from .engine import Action, evaluate

def main():
    p=argparse.ArgumentParser(prog="sentinel")
    p.add_argument("--policy", default=str(Path(__file__).parent.parent / "policies" / "default.yaml"))
    p.add_argument("--operation",required=True)
    p.add_argument("--tool",default="terminal")
    p.add_argument("--destination")
    p.add_argument("--source-class",default="unknown")
    args=p.parse_args()
    key=os.urandom(32)
    decision=evaluate(Action(args.tool,args.operation,args.destination,args.source_class),load_policy(args.policy),key)
    colors={"allowed":"\033[92m","pending":"\033[93m","blocked":"\033[91m"}
    use_color=os.isatty(1) and "NO_COLOR" not in os.environ
    prefix=colors[decision.verdict] if use_color else ""
    suffix="\033[0m" if use_color else ""
    print(f"+----------------------------------------+\n| HERMES SENTINEL // POLICY DECISION     |\n+----------------------------------------+\n| {prefix}{decision.verdict.upper():<38}{suffix} |\n| Rule: {decision.rule_id[:31]:<32} |\n+----------------------------------------+")
    return 0 if decision.verdict=="allowed" else 2
if __name__=="__main__":
    raise SystemExit(main())
