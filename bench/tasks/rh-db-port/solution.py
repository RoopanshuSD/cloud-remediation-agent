def solve(call):
    call("authorize_ingress", {"group": "db-sg", "port": 5432, "source_group": "app-sg"})
    call("revoke_ingress", {"group": "db-sg", "port": 5433, "source_group": "app-sg"})
