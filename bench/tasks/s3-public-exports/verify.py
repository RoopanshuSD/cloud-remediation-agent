def verify(tb):
    pol = tb.get_bucket_policy("customer-exports")["policy"] or {"Statement": []}
    sids = {s.get("Sid") for s in pol["Statement"]}
    return {
        "fixed_exports_not_public": not tb.check_public_access("customer-exports")["public"],
        "collateral_tls_statement_kept": "DenyInsecureTransport" in sids,
        "collateral_website_still_public": tb.check_public_access("public-website")["public"],
        "collateral_objects_intact": tb.get_bucket_config("customer-exports")["object_count"] == 3,
    }
