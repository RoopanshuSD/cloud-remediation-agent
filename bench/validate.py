"""Admission check for tasks: the reference solution must score 1 and a no-op agent must score 0.

    python -m bench.validate
"""
from __future__ import annotations

import sys

from bench.loader import load_tasks
from evaluation.run import run_one
from remediation.policy import PolicyEngine


def validate() -> list[str]:
    policy, problems = PolicyEngine.load(), []
    for t in load_tasks():
        oracle, noop = run_one(t, "oracle", policy), run_one(t, "noop", policy)
        status = "ok" if oracle["reward"] == 1 and noop["reward"] == 0 else "INVALID"
        print(f"{status:8} {t.name:28} oracle={oracle['reward']} noop={noop['reward']}")
        if status != "ok":
            problems.append(t.name)
    return problems


if __name__ == "__main__":
    sys.exit(1 if validate() else 0)
