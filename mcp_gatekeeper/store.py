"""Where keys and invites live.

Deliberately an interface. The original of this code was welded to one cloud
datastore, which made it unusable anywhere else — the single biggest barrier to
reuse. Everything the gatekeeper needs is eight methods.

Two implementations ship here: `MemoryStore` for tests and `JsonFileStore` for
small real deployments. A Firestore/Postgres/Dynamo adapter is the same eight
methods.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Protocol

log = logging.getLogger("mcp_gatekeeper")


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class KeyRecord:
    """A key as stored. Note what is NOT here: the secret.

    Only `key_hash` is persisted. There is no code path that returns a secret
    from storage, because there is nothing to return — which is what makes
    "we cannot recover your key" a property of the system rather than a policy.
    """

    key_id: str
    key_hash: str
    name: str
    email: str = ""
    permissions: dict = field(default_factory=dict)   # {server: policy dict}
    active: bool = True
    key_prefix: str = ""
    created_at: datetime | None = None
    last_used: datetime | None = None
    created_by: str = ""
    claimed_via_invite: str = ""


@dataclass
class InviteRecord:
    """A key that does not exist yet.

    Holds the SPECIFICATION of a key plus a hashed single-use token. Until it is
    claimed there is no credential anywhere — so a leaked invite is not a leaked
    key.
    """

    invite_id: str
    token_hash: str
    name: str
    email: str
    permissions: dict = field(default_factory=dict)
    status: str = "pending"          # pending | claimed | revoked | expired
    expires_at: datetime | None = None
    created_at: datetime | None = None
    created_by: str = ""
    claimed_at: datetime | None = None
    key_id: str = ""


class Store(Protocol):
    def find_key_by_hash(self, key_hash: str) -> KeyRecord | None: ...
    def touch_key(self, key_id: str) -> None: ...
    def put_key(self, record: KeyRecord) -> None: ...
    def set_key_active(self, key_id: str, active: bool) -> bool: ...
    def find_invite_by_token_hash(self, token_hash: str) -> InviteRecord | None: ...
    def get_invite(self, invite_id: str) -> InviteRecord | None: ...
    def put_invite(self, record: InviteRecord) -> None: ...
    def claim_invite_atomic(self, invite_id: str, key: KeyRecord) -> None: ...


class MemoryStore:
    """In-process store. Threadsafe enough for tests and single-process use."""

    def __init__(self) -> None:
        self.keys: dict[str, KeyRecord] = {}
        self.invites: dict[str, InviteRecord] = {}
        self._lock = threading.Lock()

    def find_key_by_hash(self, key_hash: str) -> KeyRecord | None:
        # Snapshot: lookups run on worker threads, concurrently with writes.
        for rec in list(self.keys.values()):
            if rec.key_hash == key_hash and rec.active:
                return rec
        return None

    def touch_key(self, key_id: str) -> None:
        rec = self.keys.get(key_id)
        if rec:
            rec.last_used = _now()

    def put_key(self, record: KeyRecord) -> None:
        self.keys[record.key_id] = record

    def set_key_active(self, key_id: str, active: bool) -> bool:
        rec = self.keys.get(key_id)
        if not rec:
            return False
        rec.active = active
        return True

    def find_invite_by_token_hash(self, token_hash: str) -> InviteRecord | None:
        for rec in list(self.invites.values()):
            if rec.token_hash == token_hash:
                return rec
        return None

    def get_invite(self, invite_id: str) -> InviteRecord | None:
        return self.invites.get(invite_id)

    def put_invite(self, record: InviteRecord) -> None:
        self.invites[record.invite_id] = record

    def claim_invite_atomic(self, invite_id: str, key: KeyRecord) -> None:
        """Mint the key and mark the invite claimed, together.

        The lock is what stops two clicks in the same second minting two keys.
        A real backend should use a transaction; the point is that the check and
        the write cannot be separated.
        """
        with self._lock:
            inv = self.invites.get(invite_id)
            if inv is None or inv.status != "pending":
                raise InviteError("This invite is no longer available.", status=409)
            self.keys[key.key_id] = key
            inv.status = "claimed"
            inv.claimed_at = _now()
            inv.key_id = key.key_id


class JsonFileStore(MemoryStore):
    """MemoryStore that persists to a JSON file after every write.

    For small deployments and for trying this out. Not for several processes
    writing at once.

    Edits to the file are picked up live: change a key's tools or limits in
    the JSON, save, and the next request uses them — no restart. An edit
    that doesn't parse (half-saved, a typo) is ignored with a warning and the
    previous contents stay in force, rather than locking everyone out.
    """

    TOUCH_INTERVAL_S = 60

    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = path
        # Requests run store calls on worker threads; two saves racing on the
        # same .tmp file would corrupt it, and a save must never overwrite an
        # edit it hasn't loaded yet.
        self._file_lock = threading.RLock()
        self._mtime = None
        if os.path.exists(path):
            self._load()

    def _file_mtime(self):
        try:
            return os.stat(self.path).st_mtime_ns
        except FileNotFoundError:
            return None

    def _refresh(self) -> None:
        """Reload if the file changed under us (an admin edited it)."""
        with self._file_lock:
            m = self._file_mtime()
            if m is None or m == self._mtime:
                return
            try:
                self._load()
            except (ValueError, KeyError, TypeError) as e:
                log.warning("ignoring unreadable edit to %s (%s); keeping the "
                            "previous contents", self.path, e)
                self._mtime = m

    def _iso(self, v):
        return v.isoformat() if isinstance(v, datetime) else v

    def _dt(self, v):
        return datetime.fromisoformat(v) if isinstance(v, str) else v

    def _load(self) -> None:
        m = self._file_mtime()
        with open(self.path, encoding="utf-8") as f:
            raw = json.load(f)
        keys, invites = {}, {}
        for d in raw.get("keys", []):
            for k in ("created_at", "last_used"):
                d[k] = self._dt(d.get(k))
            keys[d["key_id"]] = KeyRecord(**d)
        for d in raw.get("invites", []):
            for k in ("expires_at", "created_at", "claimed_at"):
                d[k] = self._dt(d.get(k))
            invites[d["invite_id"]] = InviteRecord(**d)
        # Swap only once the whole file parsed: a broken edit changes nothing.
        self.keys, self.invites = keys, invites
        self._mtime = m

    def _save(self) -> None:
        def enc(rec):
            d = asdict(rec)
            return {k: self._iso(v) for k, v in d.items()}

        tmp = self.path + ".tmp"
        with self._file_lock:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"keys": [enc(r) for r in list(self.keys.values())],
                           "invites": [enc(r) for r in list(self.invites.values())]},
                          f, indent=1)
            os.replace(tmp, self.path)
            self._mtime = self._file_mtime()

    # Reads pick up outside edits; writes do too, first, so they never
    # overwrite an edit they haven't seen.

    def find_key_by_hash(self, key_hash):
        self._refresh()
        return super().find_key_by_hash(key_hash)

    def find_invite_by_token_hash(self, token_hash):
        self._refresh()
        return super().find_invite_by_token_hash(token_hash)

    def get_invite(self, invite_id):
        self._refresh()
        return super().get_invite(invite_id)

    def touch_key(self, key_id):
        # `last_used` is written at most once a minute per key. Rewriting the
        # whole file on every request would be slow, and would race with an
        # admin editing it.
        with self._file_lock:
            self._refresh()
            rec = self.keys.get(key_id)
            if rec is None:
                return
            last = rec.last_used
            if last and (_now() - last).total_seconds() < self.TOUCH_INTERVAL_S:
                return
            super().touch_key(key_id)
            self._save()

    def put_key(self, record):
        with self._file_lock:
            self._refresh(); super().put_key(record); self._save()

    def set_key_active(self, key_id, active):
        with self._file_lock:
            self._refresh(); ok = super().set_key_active(key_id, active); self._save()
            return ok

    def put_invite(self, record):
        with self._file_lock:
            self._refresh(); super().put_invite(record); self._save()

    def claim_invite_atomic(self, invite_id, key):
        with self._file_lock:
            self._refresh(); super().claim_invite_atomic(invite_id, key); self._save()


class InviteError(Exception):
    """A refusal that should reach the caller as a message, not a stack trace."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status
