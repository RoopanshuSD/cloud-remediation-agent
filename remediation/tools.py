"""The agent's tool surface: typed read-only probes and write actions over the AWS control plane.

The same ToolBox is used by every agent (rule-based, Claude), by the MCP server, and by the
benchmark verifiers. Resources are addressed by human-readable names (bucket names,
security-group names, IAM user names), the way an on-call engineer refers to them.
"""
from __future__ import annotations

import fnmatch
import inspect
import json
from dataclasses import dataclass
from typing import Any, Callable

from botocore.exceptions import ClientError

from .cloud import Cloud

WORLD = "0.0.0.0/0"


@dataclass
class ToolSpec:
    name: str
    fn: Callable[..., dict]
    writes: bool
    description: str

    def input_schema(self) -> dict:
        """JSON schema derived from the Python signature (used for Claude and MCP)."""
        types = {str: "string", int: "integer", bool: "boolean", dict: "object", list: "array"}
        props, required = {}, []
        for p in inspect.signature(self.fn).parameters.values():
            ann = p.annotation if not isinstance(p.annotation, str) else {
                "str": str, "int": int, "bool": bool, "dict": dict, "list": list}.get(p.annotation, str)
            props[p.name] = {"type": types.get(ann, "string")}
            if p.default is inspect.Parameter.empty:
                required.append(p.name)
        return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


def _as_list(x) -> list:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _principal_matches(principal, arn: str) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(p == "*" or p == arn for p in _as_list(principal.get("AWS")))
    return False


def _match_any(patterns, value: str) -> bool:
    return any(fnmatch.fnmatchcase(value.lower(), str(p).lower()) for p in _as_list(patterns))


def is_public_statement(st: dict) -> bool:
    return st.get("Effect") == "Allow" and _principal_matches(st.get("Principal"), "*") and \
        (st.get("Principal") == "*" or "*" in _as_list((st.get("Principal") or {}).get("AWS")))


class ToolBox:
    def __init__(self, cloud: Cloud):
        self.c = cloud

    # ------------------------------------------------------------------ read-only probes
    def list_buckets(self) -> dict:
        """List S3 buckets with their tags."""
        out = []
        for b in self.c.s3.list_buckets().get("Buckets", []):
            try:
                tags = {t["Key"]: t["Value"] for t in self.c.s3.get_bucket_tagging(Bucket=b["Name"])["TagSet"]}
            except ClientError:
                tags = {}
            out.append({"bucket": b["Name"], "tags": tags})
        return {"buckets": out}

    def get_bucket_policy(self, bucket: str) -> dict:
        """Return the bucket policy document, or null if none is attached."""
        try:
            return {"bucket": bucket, "policy": json.loads(self.c.s3.get_bucket_policy(Bucket=bucket)["Policy"])}
        except ClientError as e:
            if "NoSuchBucketPolicy" in str(e):
                return {"bucket": bucket, "policy": None}
            raise

    def get_bucket_config(self, bucket: str) -> dict:
        """Versioning status, lifecycle rules, default encryption and object count for a bucket."""
        s3 = self.c.s3
        versioning = s3.get_bucket_versioning(Bucket=bucket).get("Status", "Disabled")
        try:
            lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket).get("Rules", [])
        except ClientError:
            lifecycle = []
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
            encryption = enc[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        except ClientError:
            encryption = None
        count = s3.list_objects_v2(Bucket=bucket).get("KeyCount", 0)
        return {"bucket": bucket, "versioning": versioning, "lifecycle_rules": lifecycle,
                "default_encryption": encryption, "object_count": count}

    def check_public_access(self, bucket: str) -> dict:
        """Is the bucket readable by anyone on the internet via its bucket policy?"""
        pol = self.get_bucket_policy(bucket)["policy"] or {}
        sids = [st.get("Sid", f"#{i}") for i, st in enumerate(_as_list(pol.get("Statement")))
                if is_public_statement(st)]
        return {"bucket": bucket, "public": bool(sids), "public_statements": sids}

    def simulate_s3_access(self, principal_arn: str, action: str, bucket: str, key: str = "probe.txt") -> dict:
        """Evaluate the bucket policy for (principal, action, object). Identity policies are assumed to allow;
        statements with a Condition are assumed not to match (requests are made over TLS from inside the VPC)."""
        pol = self.get_bucket_policy(bucket)["policy"] or {}
        resource = f"arn:aws:s3:::{bucket}/{key}"
        for st in _as_list(pol.get("Statement")):
            if st.get("Effect") != "Deny" or st.get("Condition"):
                continue
            if _principal_matches(st.get("Principal"), principal_arn) and _match_any(st.get("Action"), action) \
                    and _match_any(st.get("Resource"), resource):
                return {"allowed": False, "reason": f"explicit deny in statement {st.get('Sid', '?')}"}
        return {"allowed": True, "reason": "no explicit deny"}

    def describe_security_groups(self) -> dict:
        """All security groups with simplified ingress rules (port, cidr or source group)."""
        groups = self.c.ec2.describe_security_groups()["SecurityGroups"]
        by_id = {g["GroupId"]: g["GroupName"] for g in groups}
        out = []
        for g in groups:
            rules = []
            for perm in g.get("IpPermissions", []):
                port = perm.get("FromPort")
                for r in perm.get("IpRanges", []):
                    rules.append({"port": port, "cidr": r["CidrIp"]})
                for r in perm.get("UserIdGroupPairs", []):
                    rules.append({"port": port, "source_group": by_id.get(r["GroupId"], r["GroupId"])})
            out.append({"group": g["GroupName"], "id": g["GroupId"], "ingress": rules})
        return {"security_groups": out}

    def check_connectivity(self, source_group: str, target_group: str, port: int) -> dict:
        """Can instances in source_group open a TCP connection to target_group on port?"""
        for g in self.describe_security_groups()["security_groups"]:
            if g["group"] != target_group:
                continue
            for r in g["ingress"]:
                if r["port"] == port and (r.get("source_group") == source_group or r.get("cidr") == WORLD):
                    return {"reachable": True, "matched_rule": r}
            return {"reachable": False, "matched_rule": None}
        return {"reachable": False, "error": f"unknown group {target_group}"}

    def get_user_policies(self, user: str) -> dict:
        """Inline IAM policies attached to a user."""
        names = self.c.iam.list_user_policies(UserName=user)["PolicyNames"]
        docs = {}
        for n in names:
            doc = self.c.iam.get_user_policy(UserName=user, PolicyName=n)["PolicyDocument"]
            docs[n] = json.loads(doc) if isinstance(doc, str) else doc
        return {"user": user, "policies": docs}

    def simulate_iam_action(self, user: str, action: str, resource: str) -> dict:
        """Does any inline policy of the user allow the action on the resource?"""
        for name, doc in self.get_user_policies(user)["policies"].items():
            for st in _as_list(doc.get("Statement")):
                if st.get("Effect") == "Allow" and _match_any(st.get("Action"), action) \
                        and _match_any(st.get("Resource"), resource):
                    return {"allowed": True, "policy": name}
        return {"allowed": False}

    # ------------------------------------------------------------------ write actions
    def put_bucket_policy(self, bucket: str, policy: dict) -> dict:
        """Replace the bucket policy with the given document."""
        self.c.s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
        return {"ok": True}

    def delete_bucket_policy(self, bucket: str) -> dict:
        """Remove the bucket policy entirely."""
        self.c.s3.delete_bucket_policy(Bucket=bucket)
        return {"ok": True}

    def set_bucket_versioning(self, bucket: str, status: str) -> dict:
        """Set versioning to 'Enabled' or 'Suspended'."""
        self.c.s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": status})
        return {"ok": True}

    def delete_bucket_lifecycle(self, bucket: str) -> dict:
        """Remove all lifecycle rules from a bucket."""
        self.c.s3.delete_bucket_lifecycle(Bucket=bucket)
        return {"ok": True}

    def enable_default_encryption(self, bucket: str) -> dict:
        """Turn on SSE-S3 default encryption for a bucket."""
        self.c.s3.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
        return {"ok": True}

    def _perm(self, port: int, cidr: str, source_group: str) -> dict:
        perm = {"IpProtocol": "tcp", "FromPort": port, "ToPort": port}
        if cidr:
            perm["IpRanges"] = [{"CidrIp": cidr}]
        if source_group:
            perm["UserIdGroupPairs"] = [{"GroupId": self._group_id(source_group)}]
        return perm

    def _group_id(self, name: str) -> str:
        return self.c.ec2.describe_security_groups(GroupNames=[name])["SecurityGroups"][0]["GroupId"]

    def revoke_ingress(self, group: str, port: int, cidr: str = "", source_group: str = "") -> dict:
        """Remove one ingress rule (give either cidr or source_group)."""
        self.c.ec2.revoke_security_group_ingress(GroupId=self._group_id(group),
                                                 IpPermissions=[self._perm(port, cidr, source_group)])
        return {"ok": True}

    def authorize_ingress(self, group: str, port: int, cidr: str = "", source_group: str = "") -> dict:
        """Add one ingress rule (give either cidr or source_group)."""
        self.c.ec2.authorize_security_group_ingress(GroupId=self._group_id(group),
                                                    IpPermissions=[self._perm(port, cidr, source_group)])
        return {"ok": True}

    def put_user_policy(self, user: str, policy_name: str, policy: dict) -> dict:
        """Create or replace an inline IAM policy on a user."""
        self.c.iam.put_user_policy(UserName=user, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
        return {"ok": True}

    def delete_user_policy(self, user: str, policy_name: str) -> dict:
        """Delete an inline IAM policy from a user."""
        self.c.iam.delete_user_policy(UserName=user, PolicyName=policy_name)
        return {"ok": True}

    def delete_bucket(self, bucket: str) -> dict:
        """Delete a bucket and all of its objects (destructive)."""
        for o in self.c.s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            self.c.s3.delete_object(Bucket=bucket, Key=o["Key"])
        self.c.s3.delete_bucket(Bucket=bucket)
        return {"ok": True}

    # ------------------------------------------------------------------ registry
    READ = ["list_buckets", "get_bucket_policy", "get_bucket_config", "check_public_access",
            "simulate_s3_access", "describe_security_groups", "check_connectivity",
            "get_user_policies", "simulate_iam_action"]
    WRITE = ["put_bucket_policy", "delete_bucket_policy", "set_bucket_versioning", "delete_bucket_lifecycle",
             "enable_default_encryption", "revoke_ingress", "authorize_ingress", "put_user_policy",
             "delete_user_policy", "delete_bucket"]

    def specs(self) -> dict[str, ToolSpec]:
        out = {}
        for name in self.READ + self.WRITE:
            fn = getattr(self, name)
            out[name] = ToolSpec(name, fn, name in self.WRITE, inspect.getdoc(fn) or name)
        return out


def call_tool(spec: ToolSpec, args: dict[str, Any]) -> dict:
    """Run a tool, turning AWS errors into structured results instead of exceptions."""
    try:
        return spec.fn(**args)
    except ClientError as e:
        return {"error": e.response.get("Error", {}).get("Code", "ClientError"), "message": str(e)}
    except TypeError as e:
        return {"error": "BadArguments", "message": str(e)}
