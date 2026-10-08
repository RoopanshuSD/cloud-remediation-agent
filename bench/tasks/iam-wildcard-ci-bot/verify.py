WILD = {"*", "s3:*", "iam:*"}


def verify(tb):
    acts = []
    for doc in tb.get_user_policies("ci-bot")["policies"].values():
        for s in doc.get("Statement", []):
            a = s.get("Action")
            acts += a if isinstance(a, list) else [a]
    obj = "arn:aws:s3:::build-artifacts/build-123.zip"
    return {
        "fixed_no_wildcard_actions": not (set(acts) & WILD),
        "collateral_can_put_artifacts": tb.simulate_iam_action("ci-bot", "s3:PutObject", obj)["allowed"],
        "collateral_can_get_artifacts": tb.simulate_iam_action("ci-bot", "s3:GetObject", obj)["allowed"],
    }
