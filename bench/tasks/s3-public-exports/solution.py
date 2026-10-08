def solve(call):
    pol = call("get_bucket_policy", {"bucket": "customer-exports"})["policy"]
    pol["Statement"] = [s for s in pol["Statement"] if s["Sid"] != "TempShareForVendor"]
    call("put_bucket_policy", {"bucket": "customer-exports", "policy": pol})
