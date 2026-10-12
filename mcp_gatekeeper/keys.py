"""Minting keys, and the claim-link flow.

## Why invites instead of "create key, then send it"

The obvious bulk flow is: create N keys, collect N secrets, email them out. That
puts N live credentials into an email pipeline, an agent transcript, and
whatever log sits in between — and none of it can be un-sent.

So the key is NOT created up front. An invite stores only the *specification* of
a key: who it is for and what it may reach, plus a hashed single-use expiring
token. The secret is generated at the moment the invitee claims it, shown once
in their browser, and persisted only as a SHA-256 hash.

Consequences worth stating, because they are the point:

  * There is no secret at rest anywhere. A leaked invite link is not a leaked key.
  * The link is identity-bound: the claimant must prove they are the invited
    address, so a forwarded link is useless to anyone else. That is what makes
    it safe to email.
  * A bulk caller can be handed the STATUS of 40 invites without ever being
    handed 40 credentials.

The cost is one extra click for the recipient. That is the whole cost.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from .policy import ServerPolicy
from .store import InviteError, InviteRecord, KeyRecord, Store

DEFAULT_TTL_HOURS = 48
MAX_TTL_HOURS = 24 * 14

KEY_PREFIX = "sk_"


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _norm_email(v: str | None) -> str:
    return (v or "").strip().lower()


LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def _claim_base_ok(base_url: str) -> bool:
    """https anywhere; plain http only for a local development host.

    Parsed, not substring-matched: an earlier check allowed any URL that
    merely *contained* "localhost", so http://localhost.evil.com passed.
    """
    u = urlsplit(base_url or "")
    if u.scheme == "https" and u.hostname:
        return True
    return u.scheme == "http" and u.hostname in LOCAL_HOSTS


def granted_servers(permissions: dict) -> list[str]:
    """Servers this permission set actually opens.

    A block of `{"access": "none"}` is present but opens nothing. Counting it as
    a grant is how a key gets advertised as reaching four servers when it reaches
    one.
    """
    out = []
    for name, block in (permissions or {}).items():
        if ServerPolicy.from_dict(block) is not None:
            out.append(name)
    return sorted(out)


def mint_key(store: Store, *, name: str, email: str, permissions: dict,
             created_by: str = "", key_id: str | None = None) -> tuple[str, KeyRecord]:
    """Create a key directly. Returns (secret, record). The secret is returned
    exactly once and never stored.

    Prefer `create_invite` + `claim_invite` for anything you have to deliver to
    a person — this one hands you a live credential to carry around.
    """
    if not granted_servers(permissions):
        raise InviteError(
            "Every server in this permission set is access=none, so the key "
            "would open nothing.")

    secret = KEY_PREFIX + secrets.token_hex(32)
    rec = KeyRecord(
        key_id=key_id or uuid.uuid4().hex,
        key_hash=hash_secret(secret),
        key_prefix=secret[:12] + "...",
        name=name, email=_norm_email(email),
        permissions=permissions, active=True,
        created_at=_now(), created_by=created_by,
    )
    store.put_key(rec)
    return secret, rec


def create_invite(store: Store, *, name: str, email: str, permissions: dict,
                  base_url: str, ttl_hours: int = DEFAULT_TTL_HOURS,
                  created_by: str = "") -> tuple[str, InviteRecord]:
    """Create an invite. Returns (claim_url, record).

    ⚠️ The claim URL is returned ONCE and is not recoverable afterwards — only
    its hash is stored. Treat it like a password-reset link, because that is
    exactly what it is: do not log it, do not echo it into a transcript, hand it
    straight to the delivery mechanism.

    If you lose it, revoke the invite and issue a new one. There is deliberately
    no "resend": the original link genuinely cannot be reconstructed, and that
    is the guarantee rather than a limitation.
    """
    if not (1 <= int(ttl_hours) <= MAX_TTL_HOURS):
        raise InviteError("ttl_hours must be between 1 and %d." % MAX_TTL_HOURS)
    if not _norm_email(email) or "@" not in _norm_email(email):
        raise InviteError("A valid email address is required.")
    if not granted_servers(permissions):
        raise InviteError(
            "Every server in this permission set is access=none, so the key "
            "would open nothing.")
    if not _claim_base_ok(base_url):
        # An http claim link puts a single-use credential-bearing token on the
        # wire in clear. Refuse rather than silently downgrade.
        raise InviteError("base_url must be https.")

    token = secrets.token_urlsafe(32)
    rec = InviteRecord(
        invite_id=uuid.uuid4().hex,
        token_hash=hash_secret(token),
        name=name, email=_norm_email(email),
        permissions=permissions,
        status="pending",
        expires_at=_now() + timedelta(hours=int(ttl_hours)),
        created_at=_now(), created_by=created_by,
    )
    store.put_invite(rec)
    return "%s/claim/%s" % (base_url.rstrip("/"), token), rec


def peek_invite(store: Store, token: str) -> dict:
    """What the claim page shows BEFORE sign-in.

    Deliberately thin: who it is for and whether it is still live. It does NOT
    disclose what the key would reach, so an intercepted link does not also
    leak the shape of your infrastructure.
    """
    rec = store.find_invite_by_token_hash(hash_secret(token))
    if rec is None:
        raise InviteError("This claim link is not valid.", status=404)
    status = rec.status
    if status == "pending" and rec.expires_at and rec.expires_at < _now():
        status = "expired"
    return {"name": rec.name, "email": rec.email, "status": status,
            "expires_at": rec.expires_at}


def claim_invite(store: Store, token: str, claimant_email: str) -> str:
    """Mint the key. Returns the secret ONCE.

    ⚠️ `claimant_email` must be a VERIFIED identity — the result of checking a
    real ID token from your identity provider in the browser session. If the
    caller can spoof this argument, the whole design collapses into "anyone with
    the link gets the key".

    Never expose this on an agent-callable path.
    """
    claimant = _norm_email(claimant_email)
    if not claimant:
        raise InviteError("Sign in to claim this key.", status=401)

    rec = store.find_invite_by_token_hash(hash_secret(token))
    if rec is None:
        raise InviteError("This claim link is not valid.", status=404)

    if rec.status == "claimed":
        # Note this is reachable: the token hash is KEPT after claiming, so a
        # second click gets "already claimed" instead of "not valid". Deleting
        # the hash on claim makes the invite un-findable and turns an honest
        # message into a confusing one.
        raise InviteError("This key has already been claimed. Ask for a new invite.",
                          status=409)
    if rec.status == "revoked":
        raise InviteError("This invite was revoked.", status=403)
    if rec.expires_at and rec.expires_at < _now():
        rec.status = "expired"
        store.put_invite(rec)
        raise InviteError("This claim link has expired. Ask for a new one.", status=410)

    if _norm_email(rec.email) != claimant:
        # Deliberately does not say which address it WAS meant for.
        raise InviteError("This invite is for a different account. You are "
                          "signed in as %s." % claimant, status=403)

    secret = KEY_PREFIX + secrets.token_hex(32)
    key = KeyRecord(
        key_id=uuid.uuid4().hex,
        key_hash=hash_secret(secret),
        key_prefix=secret[:12] + "...",
        name=rec.name, email=rec.email,
        permissions=rec.permissions, active=True,
        created_at=_now(), created_by=rec.created_by,
        claimed_via_invite=rec.invite_id,
    )
    store.claim_invite_atomic(rec.invite_id, key)
    return secret


def revoke_invite(store: Store, token_or_id: str, *, by_token: bool = True) -> None:
    """Revoke a pending invite.

    An admin usually does NOT have the token — it left in the claim URL and only
    its hash was kept — so revoking by `invite_id` (`by_token=False`) is the
    common case.
    """
    rec = (store.find_invite_by_token_hash(hash_secret(token_or_id))
           if by_token else store.get_invite(token_or_id))
    if rec is None:
        raise InviteError("Invite not found.", status=404)
    if rec.status == "claimed":
        raise InviteError("Already claimed — revoke the key instead.", status=409)
    rec.status = "revoked"
    store.put_invite(rec)
