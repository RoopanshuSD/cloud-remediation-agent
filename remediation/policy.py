"""Deterministic policy gate. Every write action is evaluated here before it runs.

The gate is code, not a prompt: the model can propose anything, but a denied action never reaches the
cloud. Rules are loaded from policy/rules.yaml.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .tools import WORLD, is_public_statement

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "policy" / "rules.yaml"


@dataclass
class Decision:
    verdict: str  # "allow" | "deny" | "needs_approval"
    rule: str = ""
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"


class PolicyEngine:
    def __init__(self, rules: dict):
        self.rules = rules

    @classmethod
    def load(cls, path: str | Path = DEFAULT_RULES) -> "PolicyEngine":
        with open(path, encoding="utf-8") as f:
            return cls(yaml.safe_load(f))

    def evaluate(self, tool: str, args: dict, writes_so_far: int) -> Decision:
        r = self.rules
        if tool in r.get("deny_tools", []):
            return Decision("deny", "deny_tools", f"{tool} is never allowed automatically")
        if tool in r.get("require_approval", []):
            return Decision("needs_approval", "require_approval", f"{tool} requires a human approver")
        if writes_so_far >= r.get("max_writes_per_incident", 10**9):
            return Decision("deny", "max_writes_per_incident",
                            f"blast-radius limit: {writes_so_far} writes already made in this incident")
        if r.get("deny_world_ingress") and tool == "authorize_ingress" and args.get("cidr") == WORLD:
            return Decision("deny", "deny_world_ingress", "opening ingress to 0.0.0.0/0 is never automated")
        if r.get("deny_public_bucket_policy") and tool == "put_bucket_policy":
            stmts = (args.get("policy") or {}).get("Statement", [])
            if any(is_public_statement(s) for s in (stmts if isinstance(stmts, list) else [stmts])):
                return Decision("deny", "deny_public_bucket_policy", "policy would make the bucket public")
        if r.get("deny_iam_wildcards") and tool == "put_user_policy":
            for s in (args.get("policy") or {}).get("Statement", []):
                acts = s.get("Action")
                acts = acts if isinstance(acts, list) else [acts]
                if s.get("Effect") == "Allow" and any(a in ("*", "iam:*") for a in acts):
                    return Decision("deny", "deny_iam_wildcards", "policy grants wildcard IAM actions")
        return Decision("allow")
