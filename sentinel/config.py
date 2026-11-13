"""Strict Sentinel policy schema validation; reject ambiguous/unknown keys."""
from __future__ import annotations
import hermes_yaml as yaml
import re

_TOP = {'version', 'defaults', 'rules'}
_DEFAULTS = {'unknown_action', 'unknown_destination'}
_RULE = {'id','priority','effect','operations','destination_classes','source_classes','tools'}
_OPERATIONS = {'network_upload','network_request','test_execution','unknown'}
_DESTINATIONS = {'external_untrusted','local_or_private','none','unknown'}
_SOURCES = {'credential_file','private_key','workspace_file','none','unknown'}


def _string_list(value, valid):
    return (isinstance(value,list) and bool(value)
            and all(isinstance(x,str) and x in valid for x in value))


def load_policy(path: str) -> dict:
    with open(path, encoding='utf-8') as f:
        policy=yaml.safe_load(f)
    return validate_policy(policy)


def validate_policy(policy) -> dict:
    if not isinstance(policy,dict) or set(policy)-_TOP or type(policy.get('version')) is not int or policy['version'] != 1:
        raise ValueError('invalid Sentinel policy root')
    defaults=policy.get('defaults',{})
    if not isinstance(defaults,dict) or set(defaults)-_DEFAULTS:
        raise ValueError('invalid Sentinel policy defaults')
    if any(v!='deny' for v in defaults.values()):
        raise ValueError('Sentinel v0.5 supports only deny defaults')
    rules=policy.get('rules')
    if not isinstance(rules,list):
        raise ValueError('invalid Sentinel policy rules')
    seen=set()
    for rule in rules:
        if not isinstance(rule,dict) or set(rule)-_RULE:
            raise ValueError('invalid Sentinel policy rule fields')
        name=rule.get('id')
        if not isinstance(name,str) or not name or len(name)>70 or not name.replace('-','').replace('_','').isalnum() or name in seen:
            raise ValueError('invalid Sentinel policy rule id')
        seen.add(name)
        if rule.get('effect') not in ('deny','allow','require_approval'):
            raise ValueError('invalid Sentinel policy effect')
        if type(rule.get('priority',0)) is not int:
            raise ValueError('invalid Sentinel policy priority')
        if not _string_list(rule.get('operations'), _OPERATIONS):
            raise ValueError('invalid Sentinel policy operations')
        tools = rule.get('tools')
        if 'tools' in rule and not (isinstance(tools, list) and tools and all(
                isinstance(tool, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,160}', tool)
                for tool in tools)):
            raise ValueError('invalid Sentinel tools matcher')
        if rule['effect'] == 'allow' and 'unknown' in rule['operations']:
            if not tools or any(tool.lower() in {'terminal', 'execute_code'} for tool in tools):
                raise ValueError('Sentinel unknown allow requires named non-execution tools')
        for key,allowed in (('destination_classes',_DESTINATIONS),('source_classes',_SOURCES)):
            if key in rule and not _string_list(rule[key],allowed):
                raise ValueError('invalid Sentinel policy classification')
    return policy
