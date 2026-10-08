"""A deterministic, rule-based planner wrapped in the 5-stage controller.

It is deliberately weak. Hypotheses are ordered by a *static prior* (how often a cause is behind a symptom
class), not by evidence. That isolates the effect of the controller's stages. With `verify=False` it acts on
the first applicable hypothesis and declares success. With `verify=True` it re-checks the reported *symptom*
after each remediation and moves on to the next hypothesis when the symptom persists.

  detect    -> classify the ticket into a symptom family and extract named resources
  diagnose  -> generate applicable hypotheses (prior-ordered), each with remediation actions
  policy    -> every write goes through the Executor's policy gate
  remediate -> apply the hypothesis' actions
  verify    -> re-run the symptom probe; on failure loop back to the next hypothesis
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from ..tools import WORLD, is_public_statement
from .base import Executor, Result

# Static prior: for each symptom family, the order in which causes are tried.
PRIORS = {
    "exposure": ["public_bucket_policy", "open_ssh_ingress"],
    "connectivity": ["open_ssh_ingress", "sg_wrong_port"],
    "data_loss": ["lifecycle_expiring_live_data", "versioning_suspended"],
    "access_denied": ["missing_encryption", "bucket_policy_explicit_deny"],
    "privilege": ["wildcard_iam_policy"],
}

FAMILY_KEYWORDS = [
    ("access_denied", r"accessdenied|access denied|permission denied|403"),
    ("connectivity", r"time[sd]? out|timeout|cannot connect|can't connect|unreachable|connection refused"),
    ("privilege", r"admin|over-?privileged|least privilege|wildcard"),
    ("exposure", r"public|internet|exposed|leak|world-readable|scan"),
    ("data_loss", r"disappear|deleted|missing objects|overwrit|recover|lost"),
]


@dataclass
class Hypothesis:
    cause: str
    resource: str
    actions: list[tuple[str, dict]]
    check: Callable[[Callable], bool]
    notes: str = ""


@dataclass
class Incident:
    family: str
    buckets: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    port: int | None = None
    principal: str | None = None
    action: str | None = None


class RuleBasedAgent:
    def __init__(self, verify: bool = True, max_hypotheses: int = 3):
        self.verify = verify
        self.max_hypotheses = max_hypotheses
        self.name = "rule" + ("+verify" if verify else "")

    # ---------------------------------------------------------------- detect
    def detect(self, ticket: str, call) -> Incident:
        low = ticket.lower()
        family = next((f for f, pat in FAMILY_KEYWORDS if re.search(pat, low)), "exposure")
        known_buckets = [b["bucket"] for b in call("list_buckets", {})["buckets"]]
        known_groups = [g["group"] for g in call("describe_security_groups", {})["security_groups"]]
        port = re.search(r"port (\d+)", low)
        principal = re.search(r"(arn:aws:iam::\d+:(?:role|user)/[\w+=,.@-]+)", ticket)
        action = re.search(r"\b(s3:\w+)", ticket)
        return Incident(
            family=family,
            buckets=[b for b in known_buckets if b in ticket],
            groups=sorted([g for g in known_groups if re.search(rf"\b{re.escape(g)}\b", ticket)],
                          key=ticket.index),
            users=re.findall(r"user[: ]+`?([\w-]+)`?", ticket),
            port=int(port.group(1)) if port else None,
            principal=principal.group(1) if principal else None,
            action=action.group(1) if action else None,
        )

    # ---------------------------------------------------------------- diagnose
    def hypotheses(self, inc: Incident, call) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        for cause in PRIORS.get(inc.family, []):
            out.extend(getattr(self, f"_h_{cause}")(inc, call))
        return out[: self.max_hypotheses]

    def _symptom_check(self, inc: Incident, fallback: Callable[[Callable], bool]) -> Callable[[Callable], bool]:
        """Verify against the reported symptom when the ticket describes one; otherwise check the fix itself."""
        if inc.family == "connectivity" and len(inc.groups) >= 2 and inc.port:
            src, dst = inc.groups[0], inc.groups[1]
            return lambda call: call("check_connectivity", {"source_group": src, "target_group": dst,
                                                            "port": inc.port}).get("reachable", False)
        if inc.family == "access_denied" and inc.principal and inc.buckets:
            return lambda call: call("simulate_s3_access", {"principal_arn": inc.principal,
                                                            "action": inc.action or "s3:PutObject",
                                                            "bucket": inc.buckets[0]}).get("allowed", False)
        return fallback

    def _h_public_bucket_policy(self, inc, call):
        out = []
        for b in inc.buckets:
            pol = call("get_bucket_policy", {"bucket": b})["policy"]
            if not pol or not call("check_public_access", {"bucket": b})["public"]:
                continue
            keep = [s for s in pol["Statement"] if not is_public_statement(s)]
            act = ("put_bucket_policy", {"bucket": b, "policy": {**pol, "Statement": keep}}) if keep \
                else ("delete_bucket_policy", {"bucket": b})
            out.append(Hypothesis("public_bucket_policy", b, [act],
                                  lambda call, b=b: not call("check_public_access", {"bucket": b})["public"]))
        return out

    def _h_open_ssh_ingress(self, inc, call):
        out = []
        for g in call("describe_security_groups", {})["security_groups"]:
            if any(r["port"] == 22 and r.get("cidr") == WORLD for r in g["ingress"]):
                name = g["group"]

                def fixed(call, name=name):
                    sgs = call("describe_security_groups", {})["security_groups"]
                    return not any(r["port"] == 22 and r.get("cidr") == WORLD
                                   for s in sgs if s["group"] == name for r in s["ingress"])
                out.append(Hypothesis("open_ssh_ingress", name,
                                      [("revoke_ingress", {"group": name, "port": 22, "cidr": WORLD})],
                                      self._symptom_check(inc, fixed)))
        return out

    def _h_sg_wrong_port(self, inc, call):
        if len(inc.groups) < 2 or not inc.port:
            return []
        src, dst = inc.groups[0], inc.groups[1]
        for g in call("describe_security_groups", {})["security_groups"]:
            if g["group"] != dst:
                continue
            wrong = [r for r in g["ingress"] if r.get("source_group") == src and r["port"] != inc.port]
            if wrong:
                actions = [("authorize_ingress", {"group": dst, "port": inc.port, "source_group": src})]
                actions += [("revoke_ingress", {"group": dst, "port": r["port"], "source_group": src}) for r in wrong]
                return [Hypothesis("sg_wrong_port", dst, actions, self._symptom_check(inc, lambda call: False))]
        return []

    def _h_lifecycle_expiring_live_data(self, inc, call):
        out = []
        for b in inc.buckets:
            rules = call("get_bucket_config", {"bucket": b})["lifecycle_rules"]
            if any(r.get("Status") == "Enabled" and "Expiration" in r for r in rules):
                out.append(Hypothesis("lifecycle_expiring_live_data", b, [("delete_bucket_lifecycle", {"bucket": b})],
                                      lambda call, b=b: not call("get_bucket_config", {"bucket": b})["lifecycle_rules"]))
        return out

    def _h_versioning_suspended(self, inc, call):
        out = []
        for b in inc.buckets:
            if call("get_bucket_config", {"bucket": b})["versioning"] != "Enabled":
                out.append(Hypothesis("versioning_suspended", b,
                                      [("set_bucket_versioning", {"bucket": b, "status": "Enabled"})],
                                      lambda call, b=b: call("get_bucket_config", {"bucket": b})["versioning"] == "Enabled"))
        return out

    def _h_missing_encryption(self, inc, call):
        out = []
        for b in inc.buckets:
            if call("get_bucket_config", {"bucket": b})["default_encryption"] is None:
                out.append(Hypothesis("missing_encryption", b, [("enable_default_encryption", {"bucket": b})],
                                      self._symptom_check(inc, lambda call: True)))
        return out

    def _h_bucket_policy_explicit_deny(self, inc, call):
        out = []
        for b in inc.buckets:
            pol = call("get_bucket_policy", {"bucket": b})["policy"]
            if not pol:
                continue
            keep = [s for s in pol["Statement"]
                    if not (s.get("Effect") == "Deny" and not s.get("Condition")
                            and inc.principal and inc.principal in str(s.get("Principal")))]
            if len(keep) < len(pol["Statement"]):
                out.append(Hypothesis("bucket_policy_explicit_deny", b,
                                      [("put_bucket_policy", {"bucket": b, "policy": {**pol, "Statement": keep}})],
                                      self._symptom_check(inc, lambda call: True)))
        return out

    def _h_wildcard_iam_policy(self, inc, call):
        out = []
        for u in inc.users:
            for name, doc in call("get_user_policies", {"user": u})["policies"].items():
                stmts = doc.get("Statement", [])
                if not any(s.get("Action") in ("*", ["*"]) for s in stmts):
                    continue
                # Least-privilege replacement: keep resource scope, swap '*' for the S3 actions the ticket needs.
                needed = sorted(set(re.findall(r"\b(s3:\w+)", inc.__dict__.get("_ticket", "")))) or ["s3:GetObject"]
                res = [f"arn:aws:s3:::{b}/*" for b in inc.buckets] or ["*"]
                new = {"Version": "2012-10-17",
                       "Statement": [{"Sid": "LeastPrivilege", "Effect": "Allow", "Action": needed, "Resource": res}]}
                out.append(Hypothesis("wildcard_iam_policy", u, [("put_user_policy",
                                      {"user": u, "policy_name": name, "policy": new})],
                                      lambda call, u=u, n=name: all(
                                          s.get("Action") not in ("*", ["*"])
                                          for s in call("get_user_policies", {"user": u})["policies"][n]["Statement"])))
        return out

    # ---------------------------------------------------------------- controller
    def run(self, ticket: str, ex: Executor, task=None) -> Result:
        call = ex.call
        inc = self.detect(ticket, call)
        inc.__dict__["_ticket"] = ticket
        ex.log("stage", stage="detect", family=inc.family, buckets=inc.buckets, groups=inc.groups, port=inc.port)
        hyps = self.hypotheses(inc, call)
        ex.log("stage", stage="diagnose", hypotheses=[(h.cause, h.resource) for h in hyps])
        if not hyps:
            return Result(self.name, escalated=True, escalation_reason="no applicable hypothesis", trace=ex.trace)
        for h in hyps:
            ex.log("stage", stage="remediate", cause=h.cause, resource=h.resource)
            results = [call(tool, args) for tool, args in h.actions]
            if any(r.get("error") == "BlockedByPolicy" for r in results):
                ex.log("stage", stage="policy", outcome="blocked", cause=h.cause)
                continue
            if not self.verify:
                return Result(self.name, declared_resolved=True, declared_cause=h.cause, trace=ex.trace)
            ok = h.check(call)
            ex.log("stage", stage="verify", cause=h.cause, passed=ok)
            if ok:
                return Result(self.name, declared_resolved=True, declared_cause=h.cause, trace=ex.trace)
        return Result(self.name, escalated=True, escalation_reason="symptom persists after all hypotheses",
                      declared_cause=None, trace=ex.trace)
