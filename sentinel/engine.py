"""Pure policy engine. Raw tool arguments must never enter audit or UI code."""
from __future__ import annotations
import hashlib
import hmac
import ipaddress
import re
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

@dataclass(frozen=True)
class Action:
    tool: str
    operation: str
    destination: str | None = None
    source_class: str = "unknown"
    tool_name: str | None = None
    file_restriction: str | None = None

@dataclass(frozen=True)
class Decision:
    verdict: str
    rule_id: str
    reason: str
    target_digest: str
    operation: str
    tool: str

def canonical_destination(raw: str | None) -> tuple[str, str]:
    if not raw:
        return "none", "none"
    try:
        p = urlsplit(raw)
        if p.scheme.lower() not in ("http", "https") or not p.hostname or p.username or p.password:
            return "unknown", "unknown"
        host = p.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = p.port if p.port is not None else (443 if p.scheme.lower() == "https" else 80)
        if not 1 <= port <= 65535:
            return "unknown", "unknown"
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            category = "local_or_private" if not ip.is_global else "external_untrusted"
        except ValueError:
            # Ambiguous numeric IP notation must not be treated as public DNS.
            if all(re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", x) for x in host.split(".")):
                return "unknown", "unknown"
            category = "local_or_private" if host == "localhost" or host.endswith(".localhost") else "external_untrusted"
        display_host = f"[{host}]" if ":" in host else host
        return f"{p.scheme.lower()}://{display_host}:{port}", category
    except (ValueError, UnicodeError):
        return "unknown", "unknown"

def action_digest(action: Action) -> str:
    # Digest covers full exact action. Do not log this digest as a substitute for raw argument safety.
    data = json.dumps(action.__dict__, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()

def target_hmac(target: str, key: bytes) -> str:
    return hmac.new(key, target.encode(), hashlib.sha256).hexdigest()

def evaluate(action: Action, policy: dict, audit_key: bytes) -> Decision:
    target, category = canonical_destination(action.destination)
    if action.file_restriction:
        return Decision('blocked', action.file_restriction, 'file_protection', target_hmac(target, audit_key),
                        action.operation, action.tool)
    rules = policy.get("rules", [])
    matches = []
    for rule in rules:
        if 'tools' in rule and (action.tool_name or action.tool) not in rule['tools']:
            continue
        if action.operation not in rule.get("operations", []):
            continue
        if "destination_classes" in rule and category not in rule["destination_classes"]:
            continue
        if "source_classes" in rule and action.source_class not in rule["source_classes"]:
            continue
        matches.append(rule)
    # Hard denies override any approval/allow. Otherwise priority is deterministic.
    denies = [r for r in matches if r["effect"] == "deny"]
    if denies:
        rule = sorted(denies, key=lambda r: (-r.get("priority", 0), r["id"]))[0]
    elif matches:
        rule = sorted(matches, key=lambda r: (-r.get("priority", 0),
                      r["effect"] != "require_approval", r["id"]))[0]
    else:
        rule = {"id": "default-deny", "effect": "deny"}
    verdict = {"deny": "blocked", "allow": "allowed", "require_approval": "pending"}[rule["effect"]]
    # Unknown network destination cannot be allowed by broad rules.
    if action.destination and category == "unknown":
        verdict, rule = "blocked", {"id": "invalid-destination"}
    return Decision(verdict, rule["id"], "policy_decision", target_hmac(target, audit_key), action.operation, action.tool)
