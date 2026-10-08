def verify(tb):
    rules = next(g["ingress"] for g in tb.describe_security_groups()["security_groups"] if g["group"] == "app-sg")
    return {
        "fixed_no_world_ssh": not any(r["port"] == 22 and r.get("cidr") == "0.0.0.0/0" for r in rules),
        "collateral_https_still_public": any(r["port"] == 443 and r.get("cidr") == "0.0.0.0/0" for r in rules),
    }
