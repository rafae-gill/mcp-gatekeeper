"""Postgres storage, and an audit sink that writes to the same database.

    pip install "mcp-gatekeeper[postgres]"

    from mcp_gatekeeper.postgres import PostgresStore, PostgresAudit

    store = PostgresStore("postgresql://gatekeeper@db/gatekeeper")
    app = Gatekeeper(inner, server_name="warehouse", store=store,
                     audit=PostgresAudit(store))

Tables are created on first use (`create_tables=False` to manage them
yourself; `SCHEMA` below is the DDL). Three tables, prefixed `gk_` by default:
keys, invites, and an append-only audit log.

Two things a real backend has to get right that the in-memory one gets for
free:

  * `claim_invite_atomic` locks the invite row (`SELECT ... FOR UPDATE`) inside
    the same transaction that mints the key. Without it, two clicks in the same
    second both see "pending" and both mint a key.
  * `touch_key` runs on every authenticated request. Writing `last_used` every
    time turns read traffic into write traffic, so it only writes when the
    stored value is older than `touch_interval_s`.
"""
from __future__ import annotations

import re

try:
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb
    from psycopg_pool import ConnectionPool
except ImportError as e:                                    # pragma: no cover
    raise ImportError(
        "PostgresStore needs psycopg 3 and psycopg_pool: "
        "pip install \"mcp-gatekeeper[postgres]\"") from e

from .store import InviteError, InviteRecord, KeyRecord

# Table names are interpolated, never parameterised, so the prefix is held to
# a strict pattern instead of being trusted.
_PREFIX = re.compile(r"^[a-z_][a-z0-9_]{0,30}$")

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS {p}keys (
        key_id             text PRIMARY KEY,
        key_hash           text NOT NULL UNIQUE,
        name               text NOT NULL DEFAULT '',
        email              text NOT NULL DEFAULT '',
        permissions        jsonb NOT NULL DEFAULT '{{}}'::jsonb,
        active             boolean NOT NULL DEFAULT true,
        key_prefix         text NOT NULL DEFAULT '',
        created_at         timestamptz,
        last_used          timestamptz,
        created_by         text NOT NULL DEFAULT '',
        claimed_via_invite text NOT NULL DEFAULT ''
    )""",
    """CREATE TABLE IF NOT EXISTS {p}invites (
        invite_id   text PRIMARY KEY,
        token_hash  text NOT NULL UNIQUE,
        name        text NOT NULL DEFAULT '',
        email       text NOT NULL DEFAULT '',
        permissions jsonb NOT NULL DEFAULT '{{}}'::jsonb,
        status      text NOT NULL DEFAULT 'pending',
        expires_at  timestamptz,
        created_at  timestamptz,
        created_by  text NOT NULL DEFAULT '',
        claimed_at  timestamptz,
        key_id      text NOT NULL DEFAULT ''
    )""",
    """CREATE TABLE IF NOT EXISTS {p}audit (
        id           bigserial PRIMARY KEY,
        at           timestamptz NOT NULL DEFAULT now(),
        actor        text NOT NULL,
        actor_key_id text NOT NULL DEFAULT '',
        server       text NOT NULL,
        action       text NOT NULL,
        details      text NOT NULL DEFAULT ''
    )""",
    "CREATE INDEX IF NOT EXISTS {p}audit_actor_at ON {p}audit (actor, at)",
)

_KEY_COLS = ("key_id", "key_hash", "name", "email", "permissions", "active",
             "key_prefix", "created_at", "last_used", "created_by",
             "claimed_via_invite")
_INVITE_COLS = ("invite_id", "token_hash", "name", "email", "permissions",
                "status", "expires_at", "created_at", "created_by",
                "claimed_at", "key_id")


def _upsert(table: str, cols: tuple[str, ...], pk: str) -> str:
    return "INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s" % (
        table, ", ".join(cols), ", ".join(["%s"] * len(cols)), pk,
        ", ".join("%s = EXCLUDED.%s" % (c, c) for c in cols if c != pk))


class PostgresStore:
    """`Store` on Postgres. Pass a connection string, or your own psycopg pool."""

    def __init__(self, conninfo: str | None = None, *,
                 pool: ConnectionPool | None = None,
                 table_prefix: str = "gk_",
                 create_tables: bool = True,
                 min_size: int = 1, max_size: int = 10,
                 touch_interval_s: int = 60):
        if (conninfo is None) == (pool is None):
            raise ValueError("Pass exactly one of conninfo or pool.")
        if not _PREFIX.match(table_prefix):
            raise ValueError("table_prefix must match %s" % _PREFIX.pattern)

        self.prefix = table_prefix
        self.touch_interval_s = int(touch_interval_s)
        self._owns_pool = pool is None
        self.pool = pool or ConnectionPool(conninfo, min_size=min_size,
                                           max_size=max_size, open=True)
        self._keys = table_prefix + "keys"
        self._invites = table_prefix + "invites"
        self.audit_table = table_prefix + "audit"
        if create_tables:
            self.create_tables()

    # -- housekeeping -------------------------------------------------------

    def create_tables(self) -> None:
        with self.pool.connection() as conn:
            for stmt in SCHEMA:
                conn.execute(stmt.format(p=self.prefix))

    def drop_tables(self) -> None:
        """For tests. Irreversible."""
        with self.pool.connection() as conn:
            for t in (self.audit_table, self._invites, self._keys):
                conn.execute("DROP TABLE IF EXISTS %s" % t)

    def close(self) -> None:
        if self._owns_pool:
            self.pool.close()

    def _one(self, sql: str, params: tuple) -> dict | None:
        with self.pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                return cur.fetchone()

    # -- keys ---------------------------------------------------------------

    def find_key_by_hash(self, key_hash: str) -> KeyRecord | None:
        row = self._one("SELECT * FROM %s WHERE key_hash = %%s AND active LIMIT 1"
                        % self._keys, (key_hash,))
        return KeyRecord(**row) if row else None

    def touch_key(self, key_id: str) -> None:
        with self.pool.connection() as conn:
            conn.execute(
                "UPDATE %s SET last_used = now() WHERE key_id = %%s AND "
                "(last_used IS NULL OR last_used < now() - make_interval(secs => %%s))"
                % self._keys, (key_id, self.touch_interval_s))

    def put_key(self, record: KeyRecord) -> None:
        values = tuple(Jsonb(record.permissions or {}) if c == "permissions"
                       else getattr(record, c) for c in _KEY_COLS)
        with self.pool.connection() as conn:
            conn.execute(_upsert(self._keys, _KEY_COLS, "key_id"), values)

    def set_key_active(self, key_id: str, active: bool) -> bool:
        row = self._one("UPDATE %s SET active = %%s WHERE key_id = %%s RETURNING key_id"
                        % self._keys, (bool(active), key_id))
        return row is not None

    # -- invites ------------------------------------------------------------

    def find_invite_by_token_hash(self, token_hash: str) -> InviteRecord | None:
        row = self._one("SELECT * FROM %s WHERE token_hash = %%s" % self._invites,
                        (token_hash,))
        return InviteRecord(**row) if row else None

    def get_invite(self, invite_id: str) -> InviteRecord | None:
        row = self._one("SELECT * FROM %s WHERE invite_id = %%s" % self._invites,
                        (invite_id,))
        return InviteRecord(**row) if row else None

    def put_invite(self, record: InviteRecord) -> None:
        values = tuple(Jsonb(record.permissions or {}) if c == "permissions"
                       else getattr(record, c) for c in _INVITE_COLS)
        with self.pool.connection() as conn:
            conn.execute(_upsert(self._invites, _INVITE_COLS, "invite_id"), values)

    def claim_invite_atomic(self, invite_id: str, key: KeyRecord) -> None:
        """Check, mint and mark claimed in ONE transaction, with the invite row
        locked, so a double click cannot mint two keys."""
        with self.pool.connection() as conn, conn.transaction():
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT status FROM %s WHERE invite_id = %%s FOR UPDATE"
                            % self._invites, (invite_id,))
                row = cur.fetchone()
                if row is None or row["status"] != "pending":
                    raise InviteError("This invite is no longer available.", status=409)
                values = tuple(Jsonb(key.permissions or {}) if c == "permissions"
                               else getattr(key, c) for c in _KEY_COLS)
                cur.execute(_upsert(self._keys, _KEY_COLS, "key_id"), values)
                cur.execute("UPDATE %s SET status = 'claimed', claimed_at = now(), "
                            "key_id = %%s WHERE invite_id = %%s" % self._invites,
                            (key.key_id, invite_id))


class PostgresAudit:
    """Append-only audit log in the store's database.

    Queryable afterwards, which is the point — "who called create_invoice last
    Tuesday" should be a SELECT, not a log search:

        SELECT at, actor, action, details FROM gk_audit
        WHERE server = 'ledger' AND action LIKE 'denied:%' ORDER BY at DESC;
    """

    def __init__(self, store: PostgresStore):
        self.pool = store.pool
        self.table = store.audit_table

    def record(self, principal, server, action, details="") -> None:
        with self.pool.connection() as conn:
            conn.execute(
                "INSERT INTO %s (actor, actor_key_id, server, action, details) "
                "VALUES (%%s, %%s, %%s, %%s, %%s)" % self.table,
                (getattr(principal, "name", "unknown"),
                 getattr(principal, "key_id", ""), server, action, details or ""))
