def verify(tb):
    sgs = {g["group"]: g["ingress"] for g in tb.describe_security_groups()["security_groups"]}
    return {
        "fixed_app_reaches_db_5432": tb.check_connectivity("app-sg", "db-sg", 5432)["reachable"],
        "collateral_db_not_world_open": not any(r.get("cidr") == "0.0.0.0/0" for r in sgs["db-sg"]),
        "collateral_app_https_kept": any(r["port"] == 443 and r.get("cidr") == "0.0.0.0/0" for r in sgs["app-sg"]),
    }
