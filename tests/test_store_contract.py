"""Every Store must pass these. Write a new backend, add it to `BACKENDS`.

Postgres runs when GK_TEST_POSTGRES_DSN is set (CI sets it), e.g.

    GK_TEST_POSTGRES_DSN=postgresql://postgres:postgres@localhost:5432/postgres

Each test gets its own table prefix and drops its tables afterwards.
"""
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from mcp_gatekeeper import (InviteError, InviteRecord, JsonFileStore, KeyRecord,
                            MemoryStore, claim_invite, create_invite, hash_secret,
                            mint_key, revoke_invite, validate_key)

DSN = os.environ.get("GK_TEST_POSTGRES_DSN")
PERMS = {"warehouse": {"access": "user", "tools": ["run_query"],
                       "statement_timeout_s": 120}}


def _postgres():
    pytest.importorskip("psycopg")
    from mcp_gatekeeper.postgres import PostgresStore
    store = PostgresStore(DSN, table_prefix="t%s_" % uuid.uuid4().hex[:8],
                          touch_interval_s=0, max_size=4)
    return store, lambda: (store.drop_tables(), store.close())


BACKENDS = {
    "memory": lambda tmp: (MemoryStore(), None),
    "jsonfile": lambda tmp: (JsonFileStore(str(tmp / "store.json")), None),
    "postgres": lambda tmp: _postgres(),
}


@pytest.fixture(params=list(BACKENDS))
def store(request, tmp_path):
    if request.param == "postgres" and not DSN:
        pytest.skip("GK_TEST_POSTGRES_DSN not set")
    s, cleanup = BACKENDS[request.param](tmp_path)
    yield s
    if cleanup:
        cleanup()


def now():
    return datetime.now(timezone.utc)


def key(**kw):
    d = dict(key_id=uuid.uuid4().hex, key_hash=uuid.uuid4().hex, name="K",
             email="k@example.com", permissions=PERMS, created_at=now())
    d.update(kw)
    return KeyRecord(**d)


# ------------------------------------------------------------------- keys ---

def test_key_roundtrip_keeps_permissions_intact(store):
    k = key()
    store.put_key(k)
    got = store.find_key_by_hash(k.key_hash)
    assert got.key_id == k.key_id
    assert got.permissions == PERMS          # nested, with an `extra` knob


def test_unknown_and_inactive_keys_are_not_found(store):
    k = key()
    store.put_key(k)
    assert store.find_key_by_hash("nope") is None
    assert store.set_key_active(k.key_id, False) is True
    assert store.find_key_by_hash(k.key_hash) is None
    assert store.set_key_active("missing", False) is False


def test_put_key_is_an_upsert(store):
    k = key()
    store.put_key(k)
    k.name = "Renamed"
    store.put_key(k)
    assert store.find_key_by_hash(k.key_hash).name == "Renamed"


def test_touch_key_sets_last_used(store):
    k = key()
    store.put_key(k)
    store.touch_key(k.key_id)
    assert store.find_key_by_hash(k.key_hash).last_used is not None


# ---------------------------------------------------------------- invites ---

def test_invite_lookup_by_token_hash_and_by_id(store):
    inv = InviteRecord(invite_id=uuid.uuid4().hex, token_hash=hash_secret("t"),
                       name="Sam", email="sam@example.com", permissions=PERMS,
                       expires_at=now() + timedelta(hours=1), created_at=now())
    store.put_invite(inv)
    assert store.find_invite_by_token_hash(hash_secret("t")).invite_id == inv.invite_id
    assert store.get_invite(inv.invite_id).email == "sam@example.com"
    assert store.get_invite("missing") is None


def test_claim_is_atomic_and_single_use(store):
    inv = InviteRecord(invite_id=uuid.uuid4().hex, token_hash=hash_secret("t2"),
                       name="Sam", email="sam@example.com", permissions=PERMS,
                       expires_at=now() + timedelta(hours=1), created_at=now())
    store.put_invite(inv)
    k = key()
    store.claim_invite_atomic(inv.invite_id, k)
    assert store.get_invite(inv.invite_id).status == "claimed"
    assert store.get_invite(inv.invite_id).key_id == k.key_id
    assert store.find_key_by_hash(k.key_hash) is not None
    with pytest.raises(InviteError):
        store.claim_invite_atomic(inv.invite_id, key())


def test_concurrent_claims_mint_exactly_one_key(store):
    """Two clicks in the same instant. The backend's locking is all that
    stands between this and two live keys."""
    inv = InviteRecord(invite_id=uuid.uuid4().hex, token_hash=hash_secret("t3"),
                       name="Sam", email="sam@example.com", permissions=PERMS,
                       expires_at=now() + timedelta(hours=1), created_at=now())
    store.put_invite(inv)
    keys = [key() for _ in range(4)]
    wins, losses = [], []
    barrier = threading.Barrier(len(keys))

    def attempt(k):
        barrier.wait()
        try:
            store.claim_invite_atomic(inv.invite_id, k)
            wins.append(k)
        except InviteError:
            losses.append(k)

    threads = [threading.Thread(target=attempt, args=(k,)) for k in keys]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(wins) == 1 and len(losses) == 3
    assert [k for k in keys if store.find_key_by_hash(k.key_hash)] == wins


# -------------------------------------------------------------- end to end --

def test_full_invite_flow_on_this_backend(store):
    url, rec = create_invite(store, name="Sam", email="sam@example.com",
                             permissions=PERMS, base_url="https://keys.example.com")
    secret = claim_invite(store, url.rsplit("/", 1)[-1], "sam@example.com")
    p = validate_key(store, secret, "warehouse")
    assert p is not None and p.grants("run_query")
    assert p.policy.extra == {"statement_timeout_s": 120}

    url2, rec2 = create_invite(store, name="Ann", email="ann@example.com",
                               permissions=PERMS, base_url="https://keys.example.com")
    revoke_invite(store, rec2.invite_id, by_token=False)
    with pytest.raises(InviteError):
        claim_invite(store, url2.rsplit("/", 1)[-1], "ann@example.com")


def test_mint_key_then_revoke(store):
    secret, rec = mint_key(store, name="Bot", email="bot@example.com", permissions=PERMS)
    assert validate_key(store, secret, "warehouse") is not None
    store.set_key_active(rec.key_id, False)
    assert validate_key(store, secret, "warehouse") is None


# --------------------------------------------------------- backend specific --

def test_jsonfile_survives_a_restart(tmp_path):
    path = str(tmp_path / "s.json")
    secret, _ = mint_key(JsonFileStore(path), name="A", email="a@example.com",
                         permissions=PERMS)
    assert validate_key(JsonFileStore(path), secret, "warehouse") is not None


@pytest.mark.skipif(not DSN, reason="GK_TEST_POSTGRES_DSN not set")
def test_postgres_audit_is_queryable():
    store, cleanup = _postgres()
    try:
        from mcp_gatekeeper.postgres import PostgresAudit
        from mcp_gatekeeper import Principal
        audit = PostgresAudit(store)
        p = Principal(key_id="k1", name="Sam")
        audit.record(p, "ledger", "post_entry")
        audit.record(p, "ledger", "denied:tool", "drop_table")
        with store.pool.connection() as conn:
            rows = conn.execute(
                "SELECT actor, action, details FROM %s WHERE server = 'ledger' "
                "AND action LIKE 'denied:%%' ORDER BY id" % store.audit_table).fetchall()
        assert rows == [("Sam", "denied:tool", "drop_table")]
    finally:
        cleanup()


@pytest.mark.skipif(not DSN, reason="GK_TEST_POSTGRES_DSN not set")
def test_postgres_rejects_unsafe_table_prefix():
    from mcp_gatekeeper.postgres import PostgresStore
    with pytest.raises(ValueError):
        PostgresStore(DSN, table_prefix="x; DROP TABLE users; --")
