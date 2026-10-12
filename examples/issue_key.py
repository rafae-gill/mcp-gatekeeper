"""Issue a key the way you should: an invite, then a claim.

    python examples/issue_key.py

Walks the whole flow locally so you can see that the secret only ever exists at
the moment of claiming. In a real deployment the two halves live apart: an admin
creates the invite and emails the link; the recipient opens it, signs in with
your identity provider, and their browser is the only place the key appears.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mcp_gatekeeper import (JsonFileStore, claim_invite, create_invite,
                            peek_invite)

STORE_PATH = os.path.join(os.path.dirname(__file__), "demo-store.json")

PERMISSIONS = {
    "warehouse": {
        "access": "user",
        # Which tools this person may call.
        "tools": ["health_check", "whoami", "run_query"],
        # When. Office hours in a named zone; wraps past midnight if you want.
        "hours_from": 0, "hours_to": 0,          # 0/0 = always, for the demo
        "hours_tz": "UTC",
        # How often, and how much at once. Enforced by the gate.
        "max_calls_per_minute": 30,
        "max_calls_per_day": 2000,
        "max_concurrent": 4,
        # Which data. Anything else rides along to the tools, which enforce
        # it: the demo warehouse lets this key read these tables and no others.
        "tables": ["sales", "customers"],
    },
    "ledger": {"access": "none", "tools": []},
}

EMAIL = "demo@example.com"

store = JsonFileStore(STORE_PATH)

claim_url, invite = create_invite(
    store, name="Demo User", email=EMAIL,
    permissions=PERMISSIONS,
    base_url="https://keys.example.com",     # https enforced; this is a demo
    ttl_hours=48, created_by="setup-script")

print("1. invite created")
print("   status      :", peek_invite(store, claim_url.rsplit('/', 1)[-1])["status"])
print("   expires     :", invite.expires_at.isoformat(timespec="minutes"))
print("   claim link  :", claim_url)
print("   (at this point NO credential exists anywhere — only this link)")

token = claim_url.rsplit("/", 1)[-1]

try:
    claim_invite(store, token, "someone.else@example.com")
except Exception as e:
    print("\n2. a forwarded link is useless to anyone else")
    print("   ->", e)

secret = claim_invite(store, token, EMAIL)
print("\n3. claimed by the right person — the key exists now, shown once:\n")
print("   ", secret)
print("\n   Stored as a hash only. Nothing can read it back, including you.")

try:
    claim_invite(store, token, EMAIL)
except Exception as e:
    print("\n4. the link is single-use")
    print("   ->", e)

print("\nStore written to", STORE_PATH)
print("Now:  python examples/server.py")
