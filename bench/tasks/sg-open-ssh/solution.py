def solve(call):
    call("revoke_ingress", {"group": "app-sg", "port": 22, "cidr": "0.0.0.0/0"})
