"""Plumbing test for the Claude agent loop with a scripted fake client (no API key, no network).

Checks that tool calls reach the executor, that the verify gate rejects an unverified resolution,
and that a verified resolution is accepted.
"""
from types import SimpleNamespace as NS

from bench.loader import load_tasks
from remediation.agents.base import Executor
from remediation.agents.claude import ClaudeAgent
from remediation.cloud import cloud_session
from remediation.policy import PolicyEngine
from remediation.tools import ToolBox


def _resp(*uses):
    blocks = [NS(type="tool_use", id=f"tu{i}", name=n, input=a) for i, (n, a) in enumerate(uses)]
    return NS(content=blocks, stop_reason="tool_use", usage=NS(input_tokens=10, output_tokens=5))


class FakeClient:
    def __init__(self, script):
        self.script, self.seen = list(script), []
        self.beta = NS(messages=NS(create=self.create))

    def create(self, **kw):
        self.seen.append(kw["messages"][-1])
        return self.script.pop(0)


def test_verify_gate_rejects_then_accepts():
    task = next(t for t in load_tasks() if t.name == "versioning-suspended")
    script = [
        _resp(("set_bucket_versioning", {"bucket": "finance-reports", "status": "Enabled"})),
        _resp(("declare_resolution", {"root_cause": "versioning_suspended", "summary": "enabled"})),  # unverified
        _resp(("get_bucket_config", {"bucket": "finance-reports"})),
        _resp(("declare_resolution", {"root_cause": "versioning_suspended", "summary": "verified"})),
    ]
    client = FakeClient(script)
    with cloud_session() as cloud:
        task.setup.setup(cloud)
        ex = Executor(ToolBox(cloud), PolicyEngine.load())
        res = ClaudeAgent(verify=True, client=client).run(task.instruction, ex, task)
        assert all(task.verifier.verify(ToolBox(cloud)).values())
    rejected = client.seen[2]["content"][0]
    assert "VerificationRequired" in rejected["content"] and rejected["is_error"]
    assert res.declared_resolved and res.declared_cause == "versioning_suspended"
    assert res.tokens == {"input": 40, "output": 20}
