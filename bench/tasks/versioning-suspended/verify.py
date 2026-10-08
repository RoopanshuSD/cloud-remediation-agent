def verify(tb):
    cfg = tb.get_bucket_config("finance-reports")
    return {
        "fixed_versioning_enabled": cfg["versioning"] == "Enabled",
        "collateral_objects_intact": cfg["object_count"] == 3,
    }
