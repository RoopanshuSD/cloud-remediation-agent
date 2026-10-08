"""Shared agent plumbing: a policy-gated tool executor with a full audit trace, and the Result type."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from ..policy import PolicyEngine
from ..tools import ToolBox, call_tool


@dataclass
class Result:
    agent: str
    declared_resolved: bool = False
    declared_cause: str | None = None
    escalated: bool = False
    escalation_reason: str = ""
    trace: list[dict] = field(default_factory=list)
    tokens: dict = field(default_factory=lambda: {"input": 0, "output": 0})

    @property
    def tool_calls(self) -> int:
        return sum(1 for t in self.trace if t["kind"] == "tool")

    @property
    def blocked(self) -> int:
        return sum(1 for t in self.trace if t["kind"] == "tool" and t.get("decision") != "allow" and t["executed"] is False)

    @property
    def would_block(self) -> int:
        """Writes the policy flagged, whether or not the gate was enforcing (shadow mode)."""
        return sum(1 for t in self.trace if t["kind"] == "tool" and t.get("decision") not in (None, "allow"))


class Executor:
    """Runs tools for an agent. Writes go through the policy engine.

    enforce_policy=False runs the gate in *shadow mode*: decisions are still computed and logged, so
    ablations can count the harmful actions an ungated agent actually took.
    """

    def __init__(self, toolbox: ToolBox, policy: PolicyEngine, enforce_policy: bool = True):
        self.specs = toolbox.specs()
        self.policy = policy
        self.enforce = enforce_policy
        self.trace: list[dict] = []
        self.writes_done = 0
        self.last_write_idx = -1
        self.last_read_idx = -1

    def log(self, kind: str, **data: Any) -> None:
        self.trace.append({"kind": kind, "t": round(time.time(), 3), **data})

    def call(self, name: str, args: dict) -> dict:
        spec = self.specs.get(name)
        if spec is None:
            return {"error": "UnknownTool", "message": name}
        decision = None
        if spec.writes:
            d = self.policy.evaluate(name, args, self.writes_done)
            decision = d.verdict
            if self.enforce and not d.allowed:
                self.log("tool", tool=name, args=args, writes=True, decision=d.verdict, rule=d.rule,
                         executed=False, result={"error": "BlockedByPolicy", "reason": d.reason})
                return {"error": "BlockedByPolicy", "verdict": d.verdict, "reason": d.reason}
        result = call_tool(spec, args)
        ok = "error" not in result
        self.log("tool", tool=name, args=args, writes=spec.writes, decision=decision, executed=True,
                 result=json.loads(json.dumps(result, default=str)))
        idx = len(self.trace) - 1
        if spec.writes and ok:
            self.writes_done += 1
            self.last_write_idx = idx
        elif not spec.writes:
            self.last_read_idx = idx
        return result

    @property
    def verified_since_last_write(self) -> bool:
        return self.last_write_idx < 0 or self.last_read_idx > self.last_write_idx
