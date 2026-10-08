def verify(tb):
    prod = tb.get_bucket_config("prod-data")
    logs = tb.get_bucket_config("logs-archive")
    return {
        "fixed_no_expiring_rule": not any(r.get("Status") == "Enabled" and "Expiration" in r
                                          for r in prod["lifecycle_rules"]),
        "collateral_objects_intact": prod["object_count"] == 5,
        "collateral_archive_rule_kept": any(r.get("ID") == "expire-old-logs" for r in logs["lifecycle_rules"]),
    }
