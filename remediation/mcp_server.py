"""Expose the remediation tools over the Model Context Protocol, so any MCP client can drive them.

Writes still go through the policy gate. The server holds one Executor per process, so the blast-radius
limit applies per server session.

    python -m remediation.mcp_server                       # SSE on http://127.0.0.1:8000/sse (moto backend)
    LOCALSTACK_ENDPOINT=http://localhost:4566 python -m remediation.mcp_server
"""
from __future__ import annotations

import functools
import inspect
import json

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer
except ImportError:  # 1.x
    from mcp.server.fastmcp import FastMCP as MCPServer
from mcp.types import ToolAnnotations

from .agents.base import Executor
from .cloud import Cloud
from .policy import PolicyEngine
from .tools import ToolBox


def build_server(cloud: Cloud, policy: PolicyEngine | None = None) -> MCPServer:
    ex = Executor(ToolBox(cloud), policy or PolicyEngine.load(), enforce_policy=True)
    mcp = MCPServer("cloud-remediation")
    for spec in ex.specs.values():
        def make(spec=spec):
            @functools.wraps(spec.fn)
            def tool(**kwargs) -> str:
                return json.dumps(ex.call(spec.name, kwargs), default=str)
            tool.__signature__ = inspect.signature(spec.fn).replace(return_annotation=str)
            return tool
        prefix = "[WRITE, policy-gated] " if spec.writes else "[read-only] "
        hints = ToolAnnotations(readOnlyHint=not spec.writes, destructiveHint=spec.name.startswith("delete_"))
        mcp.add_tool(make(), name=spec.name, description=prefix + spec.description, annotations=hints)
    mcp._remediation_executor = ex  # exposed for tests / audit export
    return mcp


def main() -> None:
    import os
    from contextlib import ExitStack

    with ExitStack() as stack:
        if os.environ.get("LOCALSTACK_ENDPOINT"):
            cloud = Cloud(os.environ["LOCALSTACK_ENDPOINT"])
        else:
            from moto import mock_aws
            stack.enter_context(mock_aws())
            cloud = Cloud()
        build_server(cloud).run(transport="sse")


if __name__ == "__main__":
    main()
