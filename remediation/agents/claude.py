"""LLM agent: Claude drives the tools through a manual tool-use loop; the controller enforces the stages in code.

Two guarantees do not depend on the prompt:
  * policy: every write tool call goes through Executor -> PolicyEngine (deny / needs_approval are returned
    to the model as tool errors);
  * verify (when enabled): `declare_resolution` is rejected unless a read-only probe ran after the last
    successful write, so the agent cannot close a ticket on an unverified change.

Requires ANTHROPIC_API_KEY (or an `ant auth login` profile). Not needed for the rule-based agent or the bench.
"""
from __future__ import annotations

import json
import os

from ..causes import CAUSES
from .base import Executor, Result

MODEL = os.environ.get("REMEDIATION_MODEL", "claude-opus-5-5")

SYSTEM = """You are an on-call cloud remediation agent. You receive an incident ticket that describes symptoms only.
Work in stages: (1) detect: identify affected resources; (2) diagnose: use read-only probes to gather
evidence and rank root-cause hypotheses; (3) remediate: make the smallest change that fixes the root cause.
Every write is checked by a policy engine; if it is blocked, choose another approach or escalate;
(4) verify: re-run probes that test the *reported symptom*, not just your change.
Do not modify resources unrelated to the incident. When the symptom is verified fixed, call
declare_resolution. If you cannot fix it safely, call escalate."""

CONTROL_TOOLS = [
    {"name": "declare_resolution",
     "description": "Close the incident. Only call after verifying the reported symptom is gone.",
     "input_schema": {"type": "object", "additionalProperties": False, "required": ["root_cause", "summary"],
                      "properties": {"root_cause": {"type": "string", "enum": list(CAUSES)},
                                     "summary": {"type": "string"}}}},
    {"name": "escalate",
     "description": "Hand the incident to a human with your findings.",
     "input_schema": {"type": "object", "additionalProperties": False, "required": ["reason"],
                      "properties": {"reason": {"type": "string"}}}},
]


class ClaudeAgent:
    def __init__(self, verify: bool = True, max_steps: int = 30, effort: str = "high", client=None):
        self.verify = verify
        self.max_steps = max_steps
        self.effort = effort
        self.name = "claude" + ("+verify" if verify else "")
        self._client = client

    @property
    def client(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic()
        return self._client

    def _tools(self, ex: Executor) -> list[dict]:
        tools = [{"name": s.name, "description": s.description, "input_schema": s.input_schema()}
                 for s in ex.specs.values()]
        return tools + CONTROL_TOOLS

    def _create(self, tools, messages):
        return self.client.beta.messages.create(
            model=MODEL, max_tokens=16000, system=SYSTEM, tools=tools, messages=messages,
            output_config={"effort": self.effort},
            betas=["server-side-fallback-2026-07-01"], extra_body={"fallbacks": "default"},
        )

    def run(self, ticket: str, ex: Executor, task=None) -> Result:
        res = Result(self.name, trace=ex.trace)
        tools = self._tools(ex)
        messages = [{"role": "user", "content": f"Incident ticket:\n\n{ticket}"}]
        for step in range(self.max_steps):
            resp = self._create(tools, messages)
            res.tokens["input"] += resp.usage.input_tokens
            res.tokens["output"] += resp.usage.output_tokens
            if resp.stop_reason == "refusal":
                res.escalated, res.escalation_reason = True, "model refusal"
                return res
            messages.append({"role": "assistant", "content": resp.content})
            uses = [b for b in resp.content if b.type == "tool_use"]
            if not uses:
                ex.log("stage", stage="end", stop_reason=resp.stop_reason)
                return res
            results, done = [], False
            for u in uses:
                args = u.input if isinstance(u.input, dict) else json.loads(u.input)
                if u.name == "declare_resolution":
                    if self.verify and not ex.verified_since_last_write:
                        out = {"error": "VerificationRequired",
                               "message": "Run a read-only probe of the reported symptom after your last change."}
                    else:
                        res.declared_resolved, res.declared_cause = True, args.get("root_cause")
                        ex.log("stage", stage="declare", **args)
                        out, done = {"ok": True}, True
                elif u.name == "escalate":
                    res.escalated, res.escalation_reason = True, args.get("reason", "")
                    ex.log("stage", stage="escalate", **args)
                    out, done = {"ok": True}, True
                else:
                    out = ex.call(u.name, args)
                results.append({"type": "tool_result", "tool_use_id": u.id,
                                "content": json.dumps(out, default=str), "is_error": "error" in out})
            messages.append({"role": "user", "content": results})
            if done:
                return res
        res.escalated, res.escalation_reason = True, "step budget exhausted"
        return res
