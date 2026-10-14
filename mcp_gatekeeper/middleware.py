"""The ASGI gate in front of an MCP server.

Wrap any streamable-HTTP MCP app. Every request is authenticated; every
`tools/call` is additionally checked against the key's time window and tool
allowlist, then recorded.

The comments below explain the guarantees the gate gives; each one is pinned by
a test.
"""
from __future__ import annotations

import json
import logging

from .audit import AuditSink, NullAudit
from .limits import Limiter
from .policy import Principal, ServerPolicy
from .store import Store
from .keys import hash_secret

log = logging.getLogger("mcp_gatekeeper")


async def _offload(fn, *args):
    """Run a blocking store/audit call on a worker thread.

    Store and audit calls are plain sync functions. Called directly from this
    async middleware, a network round-trip to a real database would block the
    event loop and serialize every concurrent request behind it — the same
    trap as a blocking driver inside an `async def` tool, a common mistake
    that can cost most of your throughput.
    """
    try:
        import anyio.to_thread          # present wherever the MCP SDK is
    except ImportError:                 # pragma: no cover
        import asyncio
        return await asyncio.to_thread(fn, *args)
    return await anyio.to_thread.run_sync(fn, *args)

HEADER = b"x-api-key"
OPEN_PATHS = ("/health", "/healthz")
STATE_KEY = "gatekeeper_principal"


def current_principal(ctx) -> Principal | None:
    """Who is calling, from inside a tool. Pass the tool's MCP `Context`.

        @mcp.tool()
        def run_query(sql: str, ctx: Context) -> str:
            who = current_principal(ctx)
            tables = who.policy.extra.get("tables", [])   # this key's data scope
            ...

    Returns None if the request didn't come through a Gatekeeper — a tool
    that scopes data by caller should refuse in that case, not fall back to
    "everything".
    """
    request = getattr(getattr(ctx, "request_context", None), "request", None)
    state = (getattr(request, "scope", None) or {}).get("state") or {}
    return state.get(STATE_KEY)

# Matches the MCP Python SDK's own default. The body is buffered here before
# the SDK sees it, so without a cap of our own the SDK's limit never applies.
MAX_BODY_BYTES = 4 * 1024 * 1024


def extract_key(headers) -> str:
    """The caller's secret, from `x-api-key` or `Authorization: Bearer`.

    Bearer is accepted because some MCP clients can only send that header. If
    both are present `x-api-key` wins, so there is exactly one key per request.
    """
    h = dict(headers or [])
    key = h.get(HEADER, b"").decode("latin-1").strip()
    if key:
        return key
    auth = h.get(b"authorization", b"").decode("latin-1").strip()
    scheme, _, token = auth.partition(" ")
    if scheme.lower() == "bearer":
        return token.strip()
    return ""


def validate_key(store: Store, api_key: str, server_name: str) -> Principal | None:
    """Resolve a raw key to a Principal for one server, or None.

    The lookup is BY HASH. The plaintext exists only inside this request — there
    is no code path anywhere that reads a secret back out of storage.
    """
    if not api_key:
        return None

    rec = store.find_key_by_hash(hash_secret(api_key))
    if rec is None or not rec.active:
        return None

    policy = ServerPolicy.from_dict((rec.permissions or {}).get(server_name))
    if policy is None:
        return None

    store.touch_key(rec.key_id)
    return Principal(key_id=rec.key_id, name=rec.name, email=rec.email, policy=policy)


class Gatekeeper:
    """ASGI middleware. `Gatekeeper(app, server_name="warehouse", store=...)`."""

    def __init__(self, app, *, server_name: str, store: Store,
                 audit: AuditSink | None = None,
                 open_paths: tuple[str, ...] = OPEN_PATHS,
                 health_body: bytes = b'{"status":"healthy"}',
                 window_exempt: tuple[str, ...] = (),
                 max_body_bytes: int = MAX_BODY_BYTES):
        self.app = app
        self.server_name = server_name
        self.store = store
        self.audit = audit or NullAudit()
        self.open_paths = open_paths
        self.health_body = health_body
        # Tools that ignore the time window — typically a health-check tool,
        # so uptime monitoring survives out of hours. They are still subject
        # to the key's tool allowlist.
        self.window_exempt = frozenset(window_exempt)
        self.max_body_bytes = max_body_bytes
        self.limiter = Limiter()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")

        # The ONLY unauthenticated route, and it is GET-only. A POST to /health
        # must not be a way in.
        if path in self.open_paths and method == "GET":
            await self._json(send, 200, self.health_body)
            return

        api_key = extract_key(scope.get("headers"))

        principal = None
        if api_key:
            try:
                principal = await _offload(validate_key, self.store, api_key,
                                           self.server_name)
            except Exception as e:
                # Fail CLOSED. A datastore outage must not become open access to
                # a server that writes to production.
                log.error("auth lookup failed: %s", e)
                principal = None

        # Every request needs a valid key: a missing key and a bad key get the
        # same 401. Deliberately no exception for the MCP handshake.
        if principal is None:
            await self._json(send, 401,
                             b'{"error":"Unauthorized",'
                             b'"message":"Valid x-api-key or Bearer token required"}')
            return

        # Hand the caller to the tools. Whatever a client sent, this is set
        # here, after validation — so a tool reading it sees the real key.
        scope.setdefault("state", {})[STATE_KEY] = principal

        # Read the WHOLE body before inspecting and replaying it: a request can
        # arrive in several chunks, and all of it must be checked.
        chunks = []
        size = 0
        if method == "POST":
            while True:
                msg = await receive()
                part = msg.get("body", b"") or b""
                size += len(part)
                if size > self.max_body_bytes:
                    await self._json(send, 413, b'{"error":"Request body too large"}')
                    return
                chunks.append(part)
                if not msg.get("more_body"):
                    break
        raw_body = b"".join(chunks)

        sent = []

        async def replay(_s=sent):
            if not _s:
                _s.append(True)
                return {"type": "http.request", "body": raw_body, "more_body": False}
            return await receive()

        if raw_body:
            # Fail CLOSED on anything we cannot inspect. Passing an unreadable
            # body through would make the tool check depend on the server
            # rejecting it too — and a JSON-RPC batch (a list) is exactly the
            # shape that would carry a `tools/call` past an object-only check.
            try:
                req = json.loads(raw_body)
            except Exception:
                req = None
            if not isinstance(req, dict):
                await self._json(send, 400,
                                 b'{"jsonrpc":"2.0","id":null,"error":{"code":-32600,'
                                 b'"message":"Body must be a single JSON-RPC object '
                                 b'(batches are not supported)"}}')
                return

            if req.get("method") == "tools/call":
                denied, release = await self._check_call(req, principal, send)
                if denied:
                    return
                try:
                    await self.app(scope, replay, send)
                finally:
                    release()           # frees the concurrency slot
                return

        await self.app(scope, replay, send)

    async def _check_call(self, req: dict, principal: Principal, send):
        """(refused, release). If refused, a response was already sent;
        otherwise `release()` must be called when the call finishes."""
        req_id = req.get("id", 1)
        params = req.get("params")
        tool = params.get("name", "unknown") if isinstance(params, dict) else "unknown"
        if not isinstance(tool, str):
            tool = "unknown"

        # Window applies to TOOL CALLS only. Blocking `initialize` would make
        # the client fail to connect rather than report a clear refusal — the
        # user sees "cannot connect" instead of "outside your hours".
        window_error = (None if tool in self.window_exempt
                        else principal.policy.window_error())
        if window_error:
            await self._record(principal, "denied:window", window_error)
            await self._refuse(send, req_id, window_error)
            return True, None

        # If the check itself errors, the answer is "no": it fails closed.
        try:
            allowed = principal.grants(tool)
        except Exception as e:
            log.error("tool-access check failed: %s", e)
            allowed = False
        if not allowed:
            await self._record(principal, "denied:tool", tool)
            await self._refuse(
                send, req_id,
                "ACCESS DENIED: you do not have permission to use '%s'. "
                "Ask an admin to update your key." % tool)
            return True, None

        # Rate and concurrency limits. Checked after the allowlist, so a call
        # that was never allowed doesn't use up the key's quota.
        limit_error, release = self.limiter.acquire(
            principal.key_id, self.server_name, principal.policy)
        if limit_error:
            action = "denied:busy" if limit_error.startswith("BUSY") else "denied:rate"
            await self._record(principal, action, tool)
            await self._refuse(send, req_id, limit_error)
            return True, None

        # An allowed call that cannot be recorded is refused: nothing runs
        # without a line in the audit log.
        if not await self._record(principal, tool):
            release()
            await self._refuse(send, req_id,
                               "UNAVAILABLE: the audit log could not be written, "
                               "so '%s' was not run. Try again shortly." % tool)
            return True, None
        return False, release

    async def _record(self, principal: Principal, action: str, details: str = "") -> bool:
        try:
            await _offload(self.audit.record, principal, self.server_name, action, details)
            return True
        except Exception as e:
            log.error("audit write failed (%s %s): %s", principal.name, action, e)
            return False

    async def _json(self, send, status: int, body: bytes) -> None:
        await send({"type": "http.response.start", "status": status,
                    "headers": [[b"content-type", b"application/json"]]})
        await send({"type": "http.response.body", "body": body})

    async def _refuse(self, send, req_id, text: str) -> None:
        """Refuse as a JSON-RPC RESULT, not an HTTP error.

        The agent then sees a readable message it can act on — "ask an admin for
        access" — instead of a transport failure it will retry blindly, or
        surface to the user as a crash.
        """
        payload = json.dumps({
            "jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": True},
        }).encode()
        await self._json(send, 200, payload)
