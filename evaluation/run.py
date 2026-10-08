"""Run agents over RemediationBench and report metrics.

    python -m evaluation.run --agents noop,oracle,rule,rule+verify --out evaluation/reports
    python -m evaluation.run --agents claude+verify --runs 3        # needs ANTHROPIC_API_KEY

Agent config strings: <agent>[+verify][+nopolicy]
    agent in {noop, oracle, shortcut, rule, claude}; policy enforcement is ON unless +nopolicy (then shadow mode).

Metrics (per config):
    pass@1            share of runs where every hidden verifier check passes
    root_cause_acc    declared root cause == the task's planted fault label
    false_success     agent declared "resolved" but the verifier failed  <- the failure mode this project targets
    escalation_rate   agent handed off to a human
    collateral_damage hidden collateral checks that failed (something unrelated got broken)
    policy_violations writes the policy flagged (shadow-evaluated even when the gate is off)
    blocked_by_gate   flagged writes that the enforcing gate actually stopped
    tool_calls        mean tool calls per run
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from bench.loader import load_tasks
from remediation.agents.base import Executor
from remediation.agents.baselines import NoOpAgent, OracleAgent, ShortcutAgent
from remediation.agents.rule_based import RuleBasedAgent
from remediation.cloud import cloud_session
from remediation.policy import PolicyEngine
from remediation.tools import ToolBox


def make_agent(cfg: str):
    parts = cfg.split("+")
    base, verify = parts[0], "verify" in parts
    if base == "noop":
        return NoOpAgent()
    if base == "oracle":
        return OracleAgent()
    if base == "shortcut":
        return ShortcutAgent()
    if base == "rule":
        return RuleBasedAgent(verify=verify)
    if base == "claude":
        from remediation.agents.claude import ClaudeAgent
        return ClaudeAgent(verify=verify)
    raise ValueError(cfg)


def run_one(task, cfg: str, policy: PolicyEngine) -> dict:
    with cloud_session() as cloud:
        task.setup.setup(cloud)
        tb = ToolBox(cloud)
        ex = Executor(tb, policy, enforce_policy="nopolicy" not in cfg.split("+"))
        t0 = time.perf_counter()
        res = make_agent(cfg).run(task.instruction, ex, task)
        elapsed = time.perf_counter() - t0
        checks = task.verifier.verify(ToolBox(cloud))
    reward = int(all(checks.values()))
    collateral_fail = sum(1 for k, v in checks.items() if k.startswith("collateral_") and not v)
    return {
        "task": task.name, "family": task.family, "config": cfg, "reward": reward, "checks": checks,
        "fault": task.fault, "declared_resolved": res.declared_resolved, "declared_cause": res.declared_cause,
        "root_cause_correct": res.declared_cause == task.fault, "escalated": res.escalated,
        "escalation_reason": res.escalation_reason, "false_success": bool(res.declared_resolved and not reward),
        "collateral_damage": collateral_fail, "blocked_by_gate": res.blocked,
        "policy_violations": res.would_block, "tool_calls": res.tool_calls,
        "tokens": res.tokens, "seconds": round(elapsed, 3), "trace": res.trace,
    }


def summarize(rows: list[dict]) -> dict:
    n = len(rows)
    mean = lambda k: sum(r[k] for r in rows) / n  # noqa: E731
    return {
        "runs": n,
        "pass@1": round(mean("reward"), 3),
        "root_cause_acc": round(mean("root_cause_correct"), 3),
        "false_success": round(mean("false_success"), 3),
        "escalation_rate": round(mean("escalated"), 3),
        "collateral_damage": sum(r["collateral_damage"] for r in rows),
        "policy_violations": sum(r["policy_violations"] for r in rows),
        "blocked_by_gate": sum(r["blocked_by_gate"] for r in rows),
        "avg_tool_calls": round(statistics.mean(r["tool_calls"] for r in rows), 1),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agents", default="noop,oracle,rule,rule+verify")
    ap.add_argument("--tasks", default="", help="comma-separated task names (default: all)")
    ap.add_argument("--runs", type=int, default=1, help="repeats per task (use >1 for LLM agents)")
    ap.add_argument("--out", default="evaluation/reports")
    args = ap.parse_args()

    tasks = load_tasks(only=[t for t in args.tasks.split(",") if t] or None)
    policy = PolicyEngine.load()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    summary, all_rows = {}, []
    for cfg in args.agents.split(","):
        rows = [run_one(t, cfg, policy) for t in tasks for _ in range(args.runs)]
        all_rows += rows
        summary[cfg] = summarize(rows)
        (out / f"{cfg.replace('+', '_')}.json").write_text(json.dumps(rows, indent=1, default=str), encoding="utf-8")

    lines = ["| Config | Runs | Pass@1 | Root-cause acc. | False-success | Escalation | Collateral damage | "
             "Policy violations attempted | Blocked by gate | Avg tool calls |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for cfg, s in summary.items():
        lines.append(f"| `{cfg}` | {s['runs']} | {s['pass@1']:.0%} | {s['root_cause_acc']:.0%} | "
                     f"{s['false_success']:.0%} | {s['escalation_rate']:.0%} | {s['collateral_damage']} | "
                     f"{s['policy_violations']} | {s['blocked_by_gate']} | {s['avg_tool_calls']} |")
    lines += ["", "Per task (reward):", "", "| Task | " + " | ".join(f"`{c}`" for c in summary) + " |",
              "|---|" + "---|" * len(summary)]
    for t in tasks:
        cells = [str(next(r["reward"] for r in all_rows if r["task"] == t.name and r["config"] == c)) for c in summary]
        lines.append(f"| {t.name} | " + " | ".join(cells) + " |")
    table = "\n".join(lines)
    (out / "summary.md").write_text(table + "\n", encoding="utf-8")
    (out / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")

    fails = [r for r in all_rows if r["false_success"]]
    md = ["# False-success traces", "",
          "Runs where the agent declared the incident resolved but the hidden verifier disagreed.", ""]
    for r in fails:
        md += [f"## `{r['config']}` on `{r['task']}`",
               f"- Planted fault: `{r['fault']}`; agent declared: `{r['declared_cause']}`",
               f"- Failed checks: {[k for k, v in r['checks'].items() if not v]}",
               "- Actions taken: " + ", ".join(f"`{t['tool']}({t['args']})`" for t in r["trace"]
                                              if t["kind"] == "tool" and t.get("writes")), ""]
    (out / "failures.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(table)


if __name__ == "__main__":
    main()
