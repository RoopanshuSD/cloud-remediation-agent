def solve(call):
    pol = call("get_bucket_policy", {"bucket": "uploads"})["policy"]
    pol["Statement"] = [s for s in pol["Statement"] if s["Sid"] != "FreezeDuringMigration"]
    call("put_bucket_policy", {"bucket": "uploads", "policy": pol})
