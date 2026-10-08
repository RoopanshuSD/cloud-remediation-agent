import asyncio
import json

from remediation.cloud import cloud_session
from remediation.mcp_server import build_server


def test_mcp_lists_tools_and_gates_writes():
    with cloud_session() as cloud:
        cloud.s3.create_bucket(Bucket="audit-logs")
        server = build_server(cloud)
        tools = {t.name: t for t in asyncio.run(server.list_tools())}
        assert {"get_bucket_policy", "check_connectivity", "put_bucket_policy"} <= set(tools)
        assert tools["delete_bucket"].description.startswith("[WRITE, policy-gated]")
        out = asyncio.run(server.call_tool("delete_bucket", {"bucket": "audit-logs"}))
        text = json.dumps(out, default=str)
        assert "BlockedByPolicy" in text
        assert [b["Name"] for b in cloud.s3.list_buckets()["Buckets"]] == ["audit-logs"]
