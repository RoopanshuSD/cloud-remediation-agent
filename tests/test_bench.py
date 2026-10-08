"""The benchmark's own guarantees: tasks are solvable, not trivially passed, and the ablation is stable."""
import pytest

from bench.loader import load_tasks
from evaluation.run import run_one
from remediation.policy import PolicyEngine

TASKS = load_tasks()
POLICY = PolicyEngine.load()


@pytest.mark.parametrize("task", TASKS, ids=lambda t: t.name)
def test_oracle_solves_and_noop_fails(task):
    assert run_one(task, "oracle", POLICY)["reward"] == 1
    assert run_one(task, "noop", POLICY)["reward"] == 0


@pytest.mark.parametrize("task", [t for t in TASKS if t.meta.get("decoy")], ids=lambda t: t.name)
def test_red_herrings_fool_unverified_agent_but_not_verified_one(task):
    unverified = run_one(task, "rule", POLICY)
    assert unverified["false_success"] and unverified["declared_cause"] == task.meta["decoy"]
    verified = run_one(task, "rule+verify", POLICY)
    assert verified["reward"] == 1 and verified["root_cause_correct"]


def test_gate_blocks_world_open_db_shortcut():
    task = next(t for t in TASKS if t.name == "rh-db-port")
    gated = run_one(task, "shortcut", POLICY)
    ungated = run_one(task, "shortcut+nopolicy", POLICY)
    assert gated["blocked_by_gate"] == 1 and ungated["checks"]["collateral_db_not_world_open"] is False
