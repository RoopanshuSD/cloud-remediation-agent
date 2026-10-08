import pytest

from remediation.policy import PolicyEngine

P = PolicyEngine.load()
PUBLIC = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]}
PUBLIC_AWS_STAR = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:*", "Resource": "*"}]}
PRIVATE = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
                          "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}


@pytest.mark.parametrize("tool,args,verdict", [
    ("delete_bucket", {"bucket": "x"}, "deny"),
    ("delete_user_policy", {"user": "u", "policy_name": "p"}, "needs_approval"),
    ("authorize_ingress", {"group": "db-sg", "port": 5432, "cidr": "0.0.0.0/0"}, "deny"),
    ("authorize_ingress", {"group": "db-sg", "port": 5432, "source_group": "app-sg"}, "allow"),
    ("put_bucket_policy", {"bucket": "x", "policy": PUBLIC}, "deny"),
    ("put_bucket_policy", {"bucket": "x", "policy": PUBLIC_AWS_STAR}, "deny"),
    ("put_bucket_policy", {"bucket": "x", "policy": PRIVATE}, "allow"),
    ("put_user_policy", {"user": "u", "policy_name": "p",
                         "policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}, "deny"),
    ("put_user_policy", {"user": "u", "policy_name": "p",
                         "policy": {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}},
     "allow"),
])
def test_rules(tool, args, verdict):
    assert P.evaluate(tool, args, writes_so_far=0).verdict == verdict


def test_blast_radius_limit():
    limit = P.rules["max_writes_per_incident"]
    assert P.evaluate("set_bucket_versioning", {"bucket": "b", "status": "Enabled"}, limit - 1).allowed
    d = P.evaluate("set_bucket_versioning", {"bucket": "b", "status": "Enabled"}, limit)
    assert d.verdict == "deny" and d.rule == "max_writes_per_incident"
