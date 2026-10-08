"""Closed vocabulary of root causes.

Agents must declare one of these labels, which makes root-cause accuracy deterministic:
the declared label is compared with the fault label a task plants. No LLM judge is involved.
"""
CAUSES = {
    "public_bucket_policy": "S3 bucket policy grants access to Principal '*'",
    "open_ssh_ingress": "Security group allows SSH (22) from 0.0.0.0/0",
    "sg_wrong_port": "Security group rule exists but on the wrong port",
    "lifecycle_expiring_live_data": "S3 lifecycle rule expires live objects",
    "versioning_suspended": "S3 versioning suspended, so overwritten objects are unrecoverable",
    "wildcard_iam_policy": "IAM policy grants '*' actions",
    "bucket_policy_explicit_deny": "S3 bucket policy has an explicit Deny for the caller",
    "missing_encryption": "S3 bucket has no default encryption",
    "unknown": "Could not determine the root cause",
}
