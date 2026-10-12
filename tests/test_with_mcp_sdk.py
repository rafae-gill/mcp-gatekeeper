"""The gate in front of a REAL MCP server, not a stand-in.

The unit tests prove the gate's own logic. These prove it still fits the
official Python SDK — the thing most likely to break this library is the SDK
changing underneath it. CI runs them against both the newest SDK and 1.x.

Skipped when `mcp` is not installed:  pip install -e ".[dev]"
"""
import json

import pytest

pytest.importorskip("mcp")
from starlette.testclient import TestClient  # noqa: E402  (installed with mcp)

from mcp_gatekeeper import (Gatekeeper, ListAudit, MemoryStore,  # noqa: E402
                            assert_grantable, mint_key)

try:                                    # mcp >= 2
    from mcp.server.mcpserver import MCPServer as Server
except ImportError:                     # mcp 1.x
    from mcp.server.fastmcp import FastMCP as Server

GRANTABLE = ["whoami", "drop_table"]
PERMS = {"warehouse": {"access": "user", "tools": ["whoami"]}}
PROTOCOL = "2025-06-18"


def build():
    srv = Server("it")

    @srv.tool()
    def whoami() -> str:
        return "it-works"

    @srv.tool()
    def drop_table() -> str:
        return "dropped"

    try:
        app = srv.streamable_http_app(stateless_http=True, json_response=True)
    except TypeError:                   # mcp 1.x: these are server settings
        srv.settings.stateless_http = True
        srv.settings.json_response = True
        app = srv.streamable_http_app()

    store = MemoryStore()
    secret, _ = mint_key(store, name="Reader", email="r@example.com", permissions=PERMS)
    audit = ListAudit()
    gate = Gatekeeper(app, server_name="warehouse", store=store, audit=audit)
    return srv, gate, secret, audit


def headers(secret=None):
    h = {"content-type": "application/json",
         "accept": "application/json, text/event-stream",
         "mcp-protocol-version": PROTOCOL}
    if secret:
        h["x-api-key"] = secret
    return h


def rpc(method, params=None, _id=1):
    return {"jsonrpc": "2.0", "id": _id, "method": method, "params": params or {}}


@pytest.fixture
def server():
    srv, gate, secret, audit = build()
    # 127.0.0.1 with a port: SDK 2.x rejects unexpected Host headers by default.
    with TestClient(gate, base_url="http://127.0.0.1:8080") as client:
        yield srv, client, secret, audit


def test_handshake_works_with_a_key(server):
    _, client, secret, _ = server
    r = client.post("/mcp", headers=headers(secret), json=rpc("initialize", {
        "protocolVersion": PROTOCOL, "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"}}))
    assert r.status_code == 200
    assert "serverInfo" in r.json()["result"]


def test_no_key_never_reaches_the_server(server):
    _, client, _, audit = server
    r = client.post("/mcp", headers=headers(),
                    json=rpc("tools/call", {"name": "whoami", "arguments": {}}))
    assert r.status_code == 401
    assert audit.actions() == []


def test_granted_tool_runs_for_real(server):
    _, client, secret, audit = server
    r = client.post("/mcp", headers=headers(secret),
                    json=rpc("tools/call", {"name": "whoami", "arguments": {}}))
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["isError"] is False
    assert result["content"][0]["text"] == "it-works"
    assert audit.actions() == ["whoami"]


def test_ungranted_tool_is_refused_before_the_server(server):
    _, client, secret, audit = server
    r = client.post("/mcp", headers=headers(secret),
                    json=rpc("tools/call", {"name": "drop_table", "arguments": {}}))
    result = r.json()["result"]
    assert result["isError"] is True
    assert "ACCESS DENIED" in result["content"][0]["text"]
    assert audit.actions() == ["denied:tool"]


def test_batch_is_refused(server):
    _, client, secret, _ = server
    r = client.post("/mcp", headers=headers(secret), content=json.dumps(
        [rpc("tools/call", {"name": "drop_table", "arguments": {}})]))
    assert r.status_code == 400


def test_registry_check_against_real_tools_list(server):
    import asyncio
    srv, *_ = server
    served = [t.name for t in asyncio.run(srv.list_tools())]
    assert sorted(served) == sorted(GRANTABLE)
    assert_grantable(served, GRANTABLE)
