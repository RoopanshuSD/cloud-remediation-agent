ROLE = "arn:aws:iam::123456789012:role/app-role"


def verify(tb):
    pol = tb.get_bucket_policy("uploads")["policy"] or {"Statement": []}
    sids = {s.get("Sid") for s in pol["Statement"]}
    return {
        "fixed_put_allowed": tb.simulate_s3_access(ROLE, "s3:PutObject", "uploads")["allowed"],
        "collateral_tls_statement_kept": "DenyInsecureTransport" in sids,
        "collateral_read_grant_kept": "AppRead" in sids,
        "collateral_not_public": not tb.check_public_access("uploads")["public"],
    }
