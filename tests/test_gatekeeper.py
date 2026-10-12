"""Tests, each one pinning a bug that actually happened.

Run:  python -m pytest -q      (or just: python tests/test_gatekeeper.py)
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from mcp_gatekeeper import (Gatekeeper, InviteError, ListAudit, MemoryStore,
                            ServerPolicy, assert_grantable, claim_invite,
                            create_invite, granted_servers, mint_key,
                            peek_invite, reconcile, revoke_invite,
                            validate_key)
from mcp_gatekeeper.reconcile import ToolRegistryDrift

READER = {"warehouse": {"access": "user",
                        "tools": ["run_query", "health_check"]},
          "ledger": {"access": "none", "tools": []}}


def make_store():
    store = MemoryStore()
    secret, _ = mint_key(store, name="Reader", email="r@example.com",
                         permissions=READER)
    return store, secret


# ---------------------------------------------------------------- transport --

class Collector:
    def __init__(self):
        self.status = None
        self.body = b""

    async def __call__(self, message):
        if message["type"] == "http.response.start":
            self.status = message["status"]
        elif message["type"] == "http.response.body":
            self.body += message.get("body", b"")


async def call(gate, *, key=None, path="/mcp", method="POST", body=None,
               chunks=None, headers=None):
    headers = list(headers or [])
    if key is not None:
        headers.append([b"x-api-key", key.encode()])
    scope = {"type": "http", "path": path, "method": method, "headers": headers}
    raw = json.dumps(body).encode() if body is not None else b""
    parts = chunks if chunks is not None else ([raw] if raw else [])

    queue = list(parts)

    async def receive():
        if queue:
            part = queue.pop(0)
            return {"type": "http.request", "body": part, "more_body": bool(queue)}
        return {"type": "http.request", "body": b"", "more_body": False}

    out = Collector()
    await gate(scope, receive, out)
    return out


def tool_call(name, _id=7):
    return {"jsonrpc": "2.0", "id": _id, "method": "tools/call",
            "params": {"name": name}}


class EchoApp:
    """Stands in for the MCP app. Records the body it was handed."""

    def __init__(self):
        self.seen = None

    async def __call__(self, scope, receive, send):
        buf = b""
        while True:
            msg = await receive()
            buf += msg.get("body", b"") or b""
            if not msg.get("more_body"):
                break
        self.seen = buf
        await send({"type": "http.response.start", "status": 200,
                    "headers": [[b"content-type", b"application/json"]]})
        await send({"type": "http.response.body", "body": b'{"ok":true}'})


# --------------------------------------------------------------------- auth --

def test_missing_header_is_rejected():
    """THE BYPASS. An earlier version passed through when no key was supplied,
    for the MCP handshake. Omitting the header was total auth bypass."""
    store, _ = make_store()
    out = asyncio.run(call(Gatekeeper(EchoApp(), server_name="warehouse", store=store),
                           key=None, body=tool_call("run_query")))
    assert out.status == 401


def test_bad_key_is_rejected():
    store, _ = make_store()
    out = asyncio.run(call(Gatekeeper(EchoApp(), server_name="warehouse", store=store),
                           key="sk_nonsense", body=tool_call("run_query")))
    assert out.status == 401


def test_health_is_open_but_only_for_get():
    store, _ = make_store()
    gate = Gatekeeper(EchoApp(), server_name="warehouse", store=store)
    assert asyncio.run(call(gate, key=None, path="/health", method="GET")).status == 200
    assert asyncio.run(call(gate, key=None, path="/health", method="POST")).status == 401


def test_key_without_this_server_is_rejected():
    store, secret = make_store()
    out = asyncio.run(call(Gatekeeper(EchoApp(), server_name="ledger", store=store),
                           key=secret, body=tool_call("post_entry")))
    assert out.status == 401


def test_revoked_key_is_rejected():
    store, secret = make_store()
    rec = store.find_key_by_hash(list(store.keys.values())[0].key_hash)
    store.set_key_active(rec.key_id, False)
    assert validate_key(store, secret, "warehouse") is None


# -------------------------------------------------------------- tool grants --

def test_granted_tool_passes_through():
    store, secret = make_store()
    app = EchoApp()
    out = asyncio.run(call(Gatekeeper(app, server_name="warehouse", store=store),
                           key=secret, body=tool_call("run_query")))
    assert out.status == 200
    assert json.loads(app.seen)["params"]["name"] == "run_query"


def test_ungranted_tool_is_refused_as_jsonrpc_result():
    """Refusals come back as a JSON-RPC result with isError, not an HTTP error,
    so the agent reads a message instead of retrying a transport failure."""
    store, secret = make_store()
    out = asyncio.run(call(Gatekeeper(EchoApp(), server_name="warehouse", store=store),
                           key=secret, body=tool_call("drop_table")))
    assert out.status == 200
    payload = json.loads(out.body)
    assert payload["result"]["isError"] is True
    assert "drop_table" in payload["result"]["content"][0]["text"]


def test_tool_check_failing_denies_rather_than_passes():
    """The check once lived inside a bare `except: pass`, so a raise meant the
    request proceeded ungated AND unlogged."""
    store, secret = make_store()

    class Boom(ServerPolicy):
        def grants(self, tool_name):
            raise RuntimeError("policy backend exploded")

    rec = list(store.keys.values())[0]
    gate = Gatekeeper(EchoApp(), server_name="warehouse", store=store)
    original = ServerPolicy.from_dict

    def patched(d):
        p = original(d)
        if p is None:
            return None
        b = Boom(**{k: getattr(p, k) for k in
                    ("access", "tools", "hours_from", "hours_to", "minutes_from",
                     "minutes_to", "hours_tz", "allowed_weekdays", "extra")})
        return b

    ServerPolicy.from_dict = staticmethod(patched)
    try:
        out = asyncio.run(call(gate, key=secret, body=tool_call("run_query")))
    finally:
        ServerPolicy.from_dict = staticmethod(original)

    assert json.loads(out.body)["result"]["isError"] is True


def test_initialize_is_not_window_or_tool_checked():
    """Blocking the handshake would make the client fail to connect rather than
    report a clear refusal."""
    store, secret = make_store()
    app = EchoApp()
    out = asyncio.run(call(Gatekeeper(app, server_name="warehouse", store=store),
                           key=secret,
                           body={"jsonrpc": "2.0", "id": 1, "method": "initialize"}))
    assert out.status == 200 and app.seen is not None


# -------------------------------------------------------------- body replay --

def test_chunked_body_is_not_truncated():
    """A single `await receive()` silently truncated chunked requests."""
    store, secret = make_store()
    app = EchoApp()
    raw = json.dumps(tool_call("run_query")).encode()
    half = len(raw) // 2
    out = asyncio.run(call(Gatekeeper(app, server_name="warehouse", store=store),
                           key=secret, chunks=[raw[:half], raw[half:]]))
    assert out.status == 200
    assert app.seen == raw


# ------------------------------------------------------------- time windows --

def test_window_wraps_past_midnight():
    p = ServerPolicy(tools=["*"], hours_from=22, hours_to=6)
    at = lambda h: datetime(2026, 1, 5, h, 0, tzinfo=timezone.utc)
    assert p.window_error(at(23)) is None
    assert p.window_error(at(3)) is None
    assert p.window_error(at(12)) is not None


def test_window_minute_precision():
    p = ServerPolicy(tools=["*"], hours_from=11, minutes_from=30, hours_to=12)
    at = lambda h, m: datetime(2026, 1, 5, h, m, tzinfo=timezone.utc)
    assert p.window_error(at(11, 29)) is not None
    assert p.window_error(at(11, 30)) is None


def test_equal_bounds_disable_the_check():
    assert ServerPolicy(tools=["*"], hours_from=0, hours_to=0).window_error() is None


def test_bad_timezone_fails_open():
    """Scheduling fails OPEN while auth fails CLOSED. A typo in a tz must not
    lock a key out with an error nobody can interpret."""
    p = ServerPolicy(tools=["*"], hours_from=9, hours_to=17, hours_tz="Mars/Olympus")
    assert p.window_error() is None


def test_weekday_restriction():
    p = ServerPolicy(tools=["*"], allowed_weekdays=[0, 1, 2, 3, 4])
    sunday = datetime(2026, 1, 4, 12, 0, tzinfo=timezone.utc)
    monday = datetime(2026, 1, 5, 12, 0, tzinfo=timezone.utc)
    assert p.window_error(sunday) is not None
    assert p.window_error(monday) is None


# ----------------------------------------------------------------- invites ---

def test_claim_mints_once_and_is_identity_bound():
    store = MemoryStore()
    url, rec = create_invite(store, name="Sam", email="sam@example.com",
                             permissions=READER, base_url="https://keys.example.com")
    token = url.rsplit("/", 1)[-1]

    assert peek_invite(store, token)["status"] == "pending"

    with pytest.raises(InviteError):
        claim_invite(store, token, "someone.else@example.com")

    secret = claim_invite(store, token, "sam@example.com")
    assert validate_key(store, secret, "warehouse") is not None

    with pytest.raises(InviteError):
        claim_invite(store, token, "sam@example.com")
    assert peek_invite(store, token)["status"] == "claimed"


def test_secret_is_never_stored():
    store = MemoryStore()
    url, _ = create_invite(store, name="Sam", email="sam@example.com",
                           permissions=READER, base_url="https://keys.example.com")
    secret = claim_invite(store, url.rsplit("/", 1)[-1], "sam@example.com")
    blob = json.dumps([k.__dict__ for k in store.keys.values()], default=str)
    assert secret not in blob


def test_expired_invite_is_refused():
    store = MemoryStore()
    url, rec = create_invite(store, name="Sam", email="sam@example.com",
                             permissions=READER, base_url="https://keys.example.com")
    rec.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    store.put_invite(rec)
    with pytest.raises(InviteError):
        claim_invite(store, url.rsplit("/", 1)[-1], "sam@example.com")


def test_http_base_url_is_refused():
    store = MemoryStore()
    with pytest.raises(InviteError):
        create_invite(store, name="Sam", email="sam@example.com",
                      permissions=READER, base_url="http://keys.example.com")


def test_all_none_permissions_are_refused():
    store = MemoryStore()
    with pytest.raises(InviteError):
        create_invite(store, name="Sam", email="sam@example.com",
                      permissions={"warehouse": {"access": "none"}},
                      base_url="https://keys.example.com")


def test_granted_servers_ignores_none_blocks():
    assert granted_servers(READER) == ["warehouse"]


# --------------------------------------------------------------- reconcile ---

def test_reconcile_flags_only_the_dangerous_direction():
    r = reconcile(served=["a", "b", "c"], grantable=["a", "b", "z"])
    assert r.served_not_grantable == ["c"]
    assert r.grantable_not_served == ["z"]
    assert r.ok is False

    assert reconcile(served=["a"], grantable=["a", "z"]).ok is True


def test_assert_grantable_raises_on_drift():
    with pytest.raises(ToolRegistryDrift):
        assert_grantable(["a", "write_result"], ["a"])
    assert_grantable(["a"], ["a", "spare"])


# ------------------------------------------------------------- audit trail ---

def test_denials_are_audited():
    store, secret = make_store()
    audit = ListAudit()
    gate = Gatekeeper(EchoApp(), server_name="warehouse", store=store, audit=audit)
    asyncio.run(call(gate, key=secret, body=tool_call("run_query")))
    asyncio.run(call(gate, key=secret, body=tool_call("drop_table")))
    assert audit.actions() == ["run_query", "denied:tool"]


# ------------------------------------------------------ bearer header -------

def test_bearer_token_is_accepted():
    """Some MCP clients can only send `Authorization: Bearer`."""
    store, secret = make_store()
    out = asyncio.run(call(Gatekeeper(EchoApp(), server_name="warehouse", store=store),
                           headers=[[b"authorization", b"Bearer " + secret.encode()]],
                           body=tool_call("run_query")))
    assert out.status == 200 and b"ok" in out.body


def test_x_api_key_wins_over_bearer():
    store, secret = make_store()
    out = asyncio.run(call(Gatekeeper(EchoApp(), server_name="warehouse", store=store),
                           key="sk_wrong",
                           headers=[[b"authorization", b"Bearer " + secret.encode()]],
                           body=tool_call("run_query")))
    assert out.status == 401


def test_non_bearer_authorization_is_rejected():
    store, secret = make_store()
    out = asyncio.run(call(Gatekeeper(EchoApp(), server_name="warehouse", store=store),
                           headers=[[b"authorization", b"Basic " + secret.encode()]],
                           body=tool_call("run_query")))
    assert out.status == 401


# ------------------------------------------- bodies the gate cannot inspect --

def test_batch_body_is_refused_not_passed_through():
    """A JSON-RPC batch is a list. An object-only check would wave a
    `tools/call` inside it straight through to the server."""
    store, secret = make_store()
    app = EchoApp()
    out = asyncio.run(call(Gatekeeper(app, server_name="warehouse", store=store),
                           key=secret, body=[tool_call("drop_table")]))
    assert out.status == 400
    assert app.seen is None


def test_unparseable_body_is_refused_not_passed_through():
    store, secret = make_store()
    app = EchoApp()
    out = asyncio.run(call(Gatekeeper(app, server_name="warehouse", store=store),
                           key=secret, chunks=[b'{"method":"tools/call",']))
    assert out.status == 400
    assert app.seen is None


def test_oversized_body_is_refused():
    store, secret = make_store()
    app = EchoApp()
    gate = Gatekeeper(app, server_name="warehouse", store=store, max_body_bytes=64)
    out = asyncio.run(call(gate, key=secret, chunks=[b"x" * 40, b"x" * 40]))
    assert out.status == 413
    assert app.seen is None


def test_malformed_params_are_refused_not_crashed():
    store, secret = make_store()
    body = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": "run_query"}
    out = asyncio.run(call(Gatekeeper(EchoApp(), server_name="warehouse", store=store),
                           key=secret, body=body))
    assert json.loads(out.body)["result"]["isError"] is True


# ---------------------------------------------------------- window exempt ---

def test_window_exempt_tool_skips_window_but_not_allowlist(monkeypatch):
    """Health checks survive out of hours; the allowlist still applies."""
    monkeypatch.setattr(ServerPolicy, "window_error",
                        lambda self, now=None: "RESTRICTED: closed")
    store, secret = make_store()
    gate = Gatekeeper(EchoApp(), server_name="warehouse", store=store,
                      window_exempt=("health_check", "not_granted"))

    ok = asyncio.run(call(gate, key=secret, body=tool_call("health_check")))
    assert json.loads(ok.body) == {"ok": True}

    closed = asyncio.run(call(gate, key=secret, body=tool_call("run_query")))
    assert "RESTRICTED" in json.loads(closed.body)["result"]["content"][0]["text"]

    denied = asyncio.run(call(gate, key=secret, body=tool_call("not_granted")))
    assert "ACCESS DENIED" in json.loads(denied.body)["result"]["content"][0]["text"]


# ------------------------------------------------------ claim-link hygiene ---

@pytest.mark.parametrize("url", ["http://keys.example.com",
                                 "http://localhost.evil.com",
                                 "http://evil.com/localhost",
                                 "ftp://localhost", "keys.example.com"])
def test_insecure_claim_base_urls_are_refused(url):
    with pytest.raises(InviteError):
        create_invite(MemoryStore(), name="Sam", email="sam@example.com",
                      permissions=READER, base_url=url)


@pytest.mark.parametrize("url", ["https://keys.example.com",
                                 "http://localhost:8080", "http://127.0.0.1",
                                 "http://[::1]:8080"])
def test_secure_or_local_claim_base_urls_are_allowed(url):
    create_invite(MemoryStore(), name="Sam", email="sam@example.com",
                  permissions=READER, base_url=url)


def test_admin_can_revoke_by_invite_id():
    """The admin never holds the token — only its hash was kept."""
    store = MemoryStore()
    url, rec = create_invite(store, name="Sam", email="sam@example.com",
                             permissions=READER, base_url="https://keys.example.com")
    revoke_invite(store, rec.invite_id, by_token=False)
    with pytest.raises(InviteError):
        claim_invite(store, url.rsplit("/", 1)[-1], "sam@example.com")


# ------------------------------------------------- blocking stores and audit --

def test_slow_store_does_not_serialize_requests():
    """Store calls run on worker threads. Called inline, a 200 ms database
    round-trip would make five concurrent requests take a full second."""
    import time
    store, secret = make_store()
    real = store.find_key_by_hash

    def slow(h):
        time.sleep(0.2)
        return real(h)

    store.find_key_by_hash = slow
    gate = Gatekeeper(EchoApp(), server_name="warehouse", store=store)

    async def five():
        return await asyncio.gather(*[call(gate, key=secret, body=tool_call("run_query"))
                                      for _ in range(5)])

    t0 = time.perf_counter()
    outs = asyncio.run(five())
    assert all(o.status == 200 for o in outs)
    assert time.perf_counter() - t0 < 0.6


def test_allowed_call_is_refused_if_it_cannot_be_audited():
    """Nothing runs without a line in the audit log."""
    class BrokenAudit:
        def record(self, *a, **kw):
            raise RuntimeError("audit db down")

    store, secret = make_store()
    app = EchoApp()
    out = asyncio.run(call(Gatekeeper(app, server_name="warehouse", store=store,
                                      audit=BrokenAudit()),
                           key=secret, body=tool_call("run_query")))
    assert json.loads(out.body)["result"]["isError"] is True
    assert app.seen is None


# ---------------------------------------------------------- usage limits ---

def limited(**limits):
    store = MemoryStore()
    perms = {"warehouse": {"tools": ["run_query"], **limits}}
    secret, _ = mint_key(store, name="Agent", email="agent@example.com", permissions=perms)
    return store, secret


def text_of(out):
    return json.loads(out.body)["result"]["content"][0]["text"]


def test_calls_per_minute_limit_refuses_then_recovers():
    from mcp_gatekeeper import Limiter
    store, secret = limited(max_calls_per_minute=3)
    audit = ListAudit()
    gate = Gatekeeper(EchoApp(), server_name="warehouse", store=store, audit=audit)
    t = [1000.0]
    gate.limiter = Limiter(clock=lambda: t[0])

    for _ in range(3):
        assert json.loads(asyncio.run(call(gate, key=secret, body=tool_call("run_query"))).body) == {"ok": True}
    refused = asyncio.run(call(gate, key=secret, body=tool_call("run_query")))
    assert text_of(refused).startswith("RATE LIMITED: this key may make 3 calls per minute")
    assert audit.actions()[-1] == "denied:rate"

    t[0] += 61
    assert json.loads(asyncio.run(call(gate, key=secret, body=tool_call("run_query"))).body) == {"ok": True}


def test_calls_per_day_limit():
    from mcp_gatekeeper import Limiter
    store, secret = limited(max_calls_per_day=2)
    gate = Gatekeeper(EchoApp(), server_name="warehouse", store=store)
    t = [0.0]
    gate.limiter = Limiter(clock=lambda: t[0])
    for _ in range(2):
        asyncio.run(call(gate, key=secret, body=tool_call("run_query")))
        t[0] += 3600
    out = asyncio.run(call(gate, key=secret, body=tool_call("run_query")))
    assert "2 calls per day" in text_of(out)


def test_refused_calls_do_not_use_up_quota():
    store, secret = limited(max_calls_per_minute=1)
    gate = Gatekeeper(EchoApp(), server_name="warehouse", store=store)
    for _ in range(3):
        asyncio.run(call(gate, key=secret, body=tool_call("not_granted")))
    ok = asyncio.run(call(gate, key=secret, body=tool_call("run_query")))
    assert json.loads(ok.body) == {"ok": True}


def test_concurrency_limit_and_slot_release():
    store, secret = limited(max_concurrent=1)

    async def scenario():
        gate_open = asyncio.Event()

        class SlowApp(EchoApp):
            async def __call__(self, scope, receive, send):
                await gate_open.wait()
                await super().__call__(scope, receive, send)

        gate = Gatekeeper(SlowApp(), server_name="warehouse", store=store)
        first = asyncio.create_task(call(gate, key=secret, body=tool_call("run_query")))
        for _ in range(200):                      # until the first call holds the slot
            if sum(gate.limiter._running.values()) == 1:
                break
            await asyncio.sleep(0.01)
        busy = await call(gate, key=secret, body=tool_call("run_query"))
        gate_open.set()
        await first
        again = await call(gate, key=secret, body=tool_call("run_query"))
        return busy, again

    busy, again = asyncio.run(scenario())
    assert text_of(busy).startswith("BUSY")
    assert json.loads(again.body) == {"ok": True}


def test_concurrency_slot_is_released_when_the_server_crashes():
    store, secret = limited(max_concurrent=1)

    class Crash(EchoApp):
        async def __call__(self, scope, receive, send):
            raise RuntimeError("tool blew up")

    gate = Gatekeeper(Crash(), server_name="warehouse", store=store)
    for _ in range(2):
        with pytest.raises(RuntimeError):
            asyncio.run(call(gate, key=secret, body=tool_call("run_query")))
    assert sum(gate.limiter._running.values()) == 0


def test_limits_are_read_live_from_the_key():
    """Tightening a limit is a store write, like changing tools."""
    store, secret = limited()
    gate = Gatekeeper(EchoApp(), server_name="warehouse", store=store)
    asyncio.run(call(gate, key=secret, body=tool_call("run_query")))
    rec = list(store.keys.values())[0]
    rec.permissions["warehouse"]["max_calls_per_minute"] = 1
    store.put_key(rec)
    asyncio.run(call(gate, key=secret, body=tool_call("run_query")))
    out = asyncio.run(call(gate, key=secret, body=tool_call("run_query")))
    assert "RATE LIMITED" in text_of(out)


# ------------------------------------------------- typos fail soft, not shut --

def test_unreadable_schedule_does_not_lock_the_key_out():
    """`"hours_from": "9am"` used to raise during key validation: a 401 on
    every request, from a field that is documented to fail OPEN."""
    store = MemoryStore()
    secret, _ = mint_key(store, name="T", email="t@example.com", permissions={
        "warehouse": {"tools": ["run_query"], "hours_from": "9am", "hours_to": 17,
                      "max_calls_per_minute": "lots"}})
    p = validate_key(store, secret, "warehouse")
    assert p is not None
    assert p.policy.max_calls_per_minute == 0


# ------------------------------------------------- live edits to keys.json --

def test_jsonfile_picks_up_hand_edits_and_ignores_broken_ones(tmp_path):
    import os
    from mcp_gatekeeper import JsonFileStore
    path = tmp_path / "keys.json"
    store = JsonFileStore(str(path))
    secret, rec = mint_key(store, name="Sam", email="s@example.com",
                           permissions={"warehouse": {"tools": ["run_query"]}})

    def edit(mutate, bump):
        data = json.loads(path.read_text())
        mutate(data)
        path.write_text(json.dumps(data))
        st = os.stat(path)
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + bump * 1_000_000_000))

    edit(lambda d: d["keys"][0]["permissions"]["warehouse"]["tools"].append("drop_table"), 1)
    assert validate_key(store, secret, "warehouse").grants("drop_table")

    path.write_text("{ half-saved")
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
    assert validate_key(store, secret, "warehouse").grants("drop_table")   # previous contents


def test_jsonfile_touch_does_not_overwrite_an_admin_edit(tmp_path):
    import os
    from mcp_gatekeeper import JsonFileStore
    path = tmp_path / "keys.json"
    store = JsonFileStore(str(path))
    secret, rec = mint_key(store, name="Sam", email="s@example.com",
                           permissions={"warehouse": {"tools": ["run_query"]}})
    data = json.loads(path.read_text())
    data["keys"][0]["active"] = False                       # admin revokes by hand
    path.write_text(json.dumps(data))
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))

    store.touch_key(rec.key_id)                             # a request lands
    assert json.loads(path.read_text())["keys"][0]["active"] is False
    assert validate_key(store, secret, "warehouse") is None


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
