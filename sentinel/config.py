import yaml

def load_policy(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    if not isinstance(policy, dict) or policy.get("version") != 1 or not isinstance(policy.get("rules"), list):
        raise ValueError("invalid policy format")
    ids=set()
    for rule in policy["rules"]:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"),str) or rule["id"] in ids or rule.get("effect") not in {"deny","allow","require_approval"} or not isinstance(rule.get("operations"),list):
            raise ValueError("invalid policy rule")
        ids.add(rule["id"])
    return policy
