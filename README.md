# mcp-gatekeeper

Per-person, per-tool, time-boxed, audited access to MCP servers.

![Demo: a key is issued through a claim link, then tool calls are allowed, refused and audited](docs/demo.gif)

MCP's spec points at OAuth 2.1. That answers *who is calling*. It does not answer
**which of the thirty tools on this server this person may invoke, at what hour, and what
gets recorded afterwards** — which is the question you actually have once a server can write
to a ledger or a warehouse.

Most MCP servers run over stdio on one laptop as one user with no auth at all. That is fine
until it isn't.

```python
from mcp.server.mcpserver import MCPServer      # mcp 1.x: mcp.server.fastmcp.FastMCP
from mcp_gatekeeper import Gatekeeper, JsonFileStore, PrintAudit

mcp = MCPServer("Warehouse")

@mcp.tool()
def run_query(sql: str) -> str:
    ...

app = Gatekeeper(
    mcp.streamable_http_app(),
    server_name="warehouse",
    store=JsonFileStore("keys.json"),
    audit=PrintAudit(),
)
uvicorn.run(app, host="0.0.0.0", port=8080)
```

Now `GET /health` is open, everything else needs a valid key (`x-api-key: sk_…` or
`Authorization: Bearer sk_…`), every `tools/call` is checked against that key's allowlist and
time window, and every call — allowed or refused — is recorded.

> **Status: alpha.** Small, readable, tested against the MCP Python SDK 1.x and 2.x.
> Maintained on a best-effort basis — it is a reference implementation to read and adapt,
> not a supported product.

## Try it

```bash
git clone https://github.com/rafae-gill/mcp-gatekeeper && cd mcp-gatekeeper
pip install -e ".[example]"

python examples/issue_key.py     # walks the invite -> claim flow, prints a key once
python examples/server.py        # serves on :8080

# in another terminal
python examples/call.py whoami                          # 401
python examples/call.py whoami --key sk_…               # runs
python examples/call.py drop_everything --key sk_…      # refused, and logged

# or the raw request:

curl -s localhost:8080/health                                      # 200
curl -s -X POST localhost:8080/mcp \
     -H 'content-type: application/json' \
     -H 'accept: application/json, text/event-stream' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}'
                                                                   # 401
# same again with  -H "x-api-key: sk_…"                            # works
# swap whoami for drop_everything                                  # refused, and logged
```

## How a request goes through

![The gate checks the key, the body, the time window and the tool allowlist, writes an audit line, and only then forwards the call](docs/architecture.svg)

## Three ideas worth stealing

### 1. Policy lives on the key, not in code

```jsonc
{
  "permissions": {
    "warehouse": {
      "access": "user",
      "tools": ["run_query", "health_check"],
      "hours_tz": "UTC",
      "hours_from": 10, "hours_to": 3,     // wraps past midnight
      "statement_timeout_s": 120,          // your server reads this from `extra`
      "max_concurrent": 4
    },
    "ledger": { "access": "none", "tools": [] }
  }
}
```

Changing someone's access is a write to the store. No redeploy. The people who grant access
stop being the people who deploy — which is the whole point, and the best decision in the
design.

Unrecognised fields ride along in `policy.extra` untouched, so your server can enforce knobs
the gatekeeper has never heard of.

### 2. Never email a key — email a claim link

The obvious bulk flow is: create N keys, collect N secrets, email them. That puts N live
credentials into an email pipeline, an agent transcript, and whatever log sits in between,
and none of it can be un-sent.

So the key isn't created up front. An invite stores the *specification* — who it's for and
what it may reach — plus a hashed, single-use, expiring token. The secret is generated when
the invitee claims it and persisted only as a SHA-256 hash.

![Claim-link flow: until the invitee claims it, a usable secret exists nowhere](docs/claim-flow.svg)

```python
url, invite = create_invite(store, name="Sam", email="sam@corp.com",
                            permissions=PERMS, base_url="https://keys.corp.com")
# ... email `url` ...
secret = claim_invite(store, token, verified_email_from_your_idp)   # once, ever
```

- **No secret at rest anywhere.** A leaked invite link is not a leaked key.
- **Identity-bound.** The claimant must be the invited address, so a forwarded link is
  useless to anyone else — which is what makes it safe to email at all.
- **No resend.** Only the token hash is kept, so the original link genuinely can't be
  reconstructed. Revoke and re-issue. That's the guarantee, not a limitation.

> The design bit its author: a bulk-issue script created the invites, then crashed before
> writing the links to disk. They were unrecoverable, exactly as intended, and the whole batch
> had to be revoked and redone.

### 3. Reconcile what you serve against what you can grant

If access is granted from a registry — a dashboard, a config file — then a tool added to the
server but missing from that registry **cannot be granted to anybody**. It keeps working for
anyone holding a `"*"` wildcard, which is usually the person who added it, and fails for
everyone else.

```python
served = [t.name for t in await mcp.list_tools()]
assert_grantable(served, REGISTRY["warehouse"])   # raises on a real gap
```

```
SERVED BUT NOT GRANTABLE (2) — nobody without a wildcard can call these:
    write_result, attach_file
```

Ours went unnoticed for weeks and was found when a colleague on a normal key ran the same
workflow and the writes silently did nothing. The check is asymmetric on purpose: a name in
the registry that isn't served is harmless, so only the dangerous direction fails a build.

## Design notes

**Auth fails closed. Scheduling fails open.** A datastore outage denies every request. But an
unreadable time window, or a typo in a timezone, logs a warning and *allows* — because the
failure mode of a misconfigured schedule should be "no schedule", not "no access". They're
different kinds of rule and deserve different defaults.

**Refusals are JSON-RPC results, not HTTP errors.** `isError: true` with a readable message,
so the agent reports "ask an admin for access" instead of retrying a transport failure.

**The handshake is never gated.** Window and tool checks apply to `tools/call` only. Blocking
`initialize` makes the client fail to connect rather than report a clear refusal.

**Health is open, but GET-only.** A POST to `/health` is not a way in. A health-check *tool*
can be exempted from the time window (`window_exempt=("health_check",)`) so monitoring
survives out of hours; it still needs to be on the key's allowlist.

**What it can't read, it refuses.** A body that isn't a single JSON-RPC object — malformed
JSON, or a batch — gets a 400 instead of being passed through unchecked. Otherwise the tool
check would only be as strict as whatever the server behind it happens to reject.

## Storage

Three backends ship:

| Store | For |
|---|---|
| `MemoryStore` | tests |
| `JsonFileStore` | trying it out, one small server |
| `PostgresStore` | production — `pip install "mcp-gatekeeper[postgres]"` |

```python
from mcp_gatekeeper.postgres import PostgresStore, PostgresAudit

store = PostgresStore("postgresql://gatekeeper@db/gatekeeper")   # creates gk_* tables
app = Gatekeeper(inner, server_name="warehouse", store=store, audit=PostgresAudit(store))
```

`PostgresAudit` makes the audit log a table, so "who was refused on the ledger this week" is a
query, not a log search:

```sql
SELECT at, actor, action, details FROM gk_audit
WHERE server = 'ledger' AND action LIKE 'denied:%' ORDER BY at DESC;
```

Store and audit calls run on worker threads, never on the event loop — a blocking database
call inside async code serializes every concurrent request, which is the mistake that cost the
original system most of its throughput. And an allowed call that can't be written to the audit
log is refused: nothing runs without a line in the log.

Writing your own (Firestore, DynamoDB, …) is eight methods, and
`tests/test_store_contract.py` is the checklist — add your backend to `BACKENDS` and it must
pass the same tests, including four threads racing to claim one invite.

```python
class Store(Protocol):
    def find_key_by_hash(self, key_hash) -> KeyRecord | None: ...
    def touch_key(self, key_id) -> None: ...
    def put_key(self, record) -> None: ...
    def set_key_active(self, key_id, active) -> bool: ...
    def find_invite_by_token_hash(self, token_hash) -> InviteRecord | None: ...
    def get_invite(self, invite_id) -> InviteRecord | None: ...
    def put_invite(self, record) -> None: ...
    def claim_invite_atomic(self, invite_id, key) -> None: ...
```

`claim_invite_atomic` must be a real transaction on a real backend — it's what stops two
clicks in the same second minting two keys.

## What this is not

- **Not an identity provider.** `claim_invite` takes a *verified* email. Verifying it is your
  IdP's job, and if that argument can be spoofed the whole design collapses into "anyone with
  the link gets the key".
- **Not novel security work.** Scoped tokens, hashed secrets and one-time claim links are
  textbook. The contribution is applying them to MCP, where almost nobody has, and reporting
  what broke.
- **Not a rate limiter.** `extra` carries your limits; enforcing them is the server's job.
- **Not multi-tenant.** No notion of organizations.

## Provenance

Extracted from a system that has run in production for months — five MCP servers, roughly two
dozen people, real production data. The comments marking bugs are not hypothetical;
each one cost something. The headline three:

- a `# pass through for the handshake` branch that made **omitting the header a total auth
  bypass**
- a single `await receive()` that silently **truncated chunked request bodies**
- a permission check inside a bare `except: pass`, so a raise meant the request proceeded
  **ungated and unlogged**

`tests/test_gatekeeper.py` pins all three, and the rest of the rules above.
`tests/test_with_mcp_sdk.py` runs the gate in front of a real SDK server, and CI runs the
whole suite weekly against the newest SDK and against 1.x — the SDK moving underneath is the
likeliest way for this to break.

```
69 passed, 11 skipped in 1.81s       # the skips are the Postgres runs; set GK_TEST_POSTGRES_DSN
```

## License

MIT © Muhammad Rafae Gill
