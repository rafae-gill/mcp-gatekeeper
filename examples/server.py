"""A tiny MCP server behind the gatekeeper.

    python examples/issue_key.py          # mint a key, prints it once
    python examples/server.py             # serve on :8080

    curl -s localhost:8080/health                                   # -> 200
    curl -s -X POST localhost:8080/mcp \
         -H 'content-type: application/json' \
         -H 'accept: application/json, text/event-stream' \
         -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
              "params":{"name":"whoami","arguments":{}}}'           # -> 401

    ... and again with  -H "x-api-key: sk_..."                      # -> works
    ... or with         -H "authorization: Bearer sk_..."           # -> works

Works with the MCP Python SDK 1.x (`FastMCP`) and 2.x (`MCPServer`).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:                                    # mcp >= 2
    from mcp.server.mcpserver import MCPServer as Server
except ImportError:                     # mcp 1.x
    from mcp.server.fastmcp import FastMCP as Server

from mcp_gatekeeper import (Gatekeeper, JsonFileStore, PrintAudit,
                            assert_grantable)

STORE_PATH = os.path.join(os.path.dirname(__file__), "demo-store.json")
SERVER_NAME = "warehouse"

# The registry a dashboard would grant from. Keeping it next to the server is
# what lets the startup check below be honest.
GRANTABLE = ["health_check", "whoami", "run_query"]

mcp = Server("DemoWarehouse")


@mcp.tool()
def health_check() -> str:
    """Liveness. Exempt from the time window below so monitoring survives."""
    return "healthy"


@mcp.tool()
def whoami() -> str:
    """Cheap tool to prove a key works."""
    return "you reached the demo warehouse server"


@mcp.tool()
def run_query(sql: str) -> str:
    """Pretend to query something."""
    return "would run: %s" % sql[:200]


@mcp.tool()
def drop_everything() -> str:
    """Deliberately NOT in GRANTABLE, to demonstrate the startup check."""
    return "nope"


def http_app():
    """Stateless + plain-JSON responses, so a single curl can call a tool.

    The SDK's arguments for this moved between 1.x and 2.x.
    """
    try:
        return mcp.streamable_http_app(stateless_http=True, json_response=True)
    except TypeError:                   # mcp 1.x: these are server settings
        mcp.settings.stateless_http = True
        mcp.settings.json_response = True
        return mcp.streamable_http_app()


if __name__ == "__main__":
    import asyncio

    import uvicorn

    served = [t.name for t in asyncio.run(mcp.list_tools())]

    # The check that would have saved us weeks. A tool the server serves but the
    # registry cannot grant is invisible to admins (they hold "*") and broken
    # for everyone else. Comment out `drop_everything` above to see it pass.
    try:
        assert_grantable(served, GRANTABLE)
        print("tool registry: OK (%d tools)" % len(served))
    except Exception as e:
        print("\n!! tool registry drift\n%s\n" % e)
        print("   This is a demo, so we continue. In production, fail the boot.\n")

    if not os.path.exists(STORE_PATH):
        print("No key store yet — run:  python examples/issue_key.py")
        raise SystemExit(1)

    app = Gatekeeper(
        http_app(),
        server_name=SERVER_NAME,
        store=JsonFileStore(STORE_PATH),
        audit=PrintAudit(),
        window_exempt=("health_check",),
    )
    # Bound to localhost: SDK 2.x rejects unexpected Host headers by default
    # (DNS-rebinding protection). Serving under a real hostname means passing
    # `host=` / `transport_security=` to streamable_http_app.
    print("serving on http://localhost:8080  (GET /health is open; all else needs a key)")
    uvicorn.run(app, host="127.0.0.1", port=8080)
