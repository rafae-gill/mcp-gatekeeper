"""mcp-gatekeeper — per-person, per-tool, time-boxed, audited access to MCP servers."""

from .audit import AuditEvent, AuditSink, ListAudit, NullAudit, PrintAudit
from .keys import (claim_invite, create_invite, granted_servers, hash_secret,
                   mint_key, peek_invite, revoke_invite)
from .limits import Limiter
from .middleware import Gatekeeper, current_principal, validate_key
from .policy import Principal, ServerPolicy
from .reconcile import ToolRegistryDrift, assert_grantable, reconcile
from .store import (InviteError, InviteRecord, JsonFileStore, KeyRecord,
                    MemoryStore, Store)

__version__ = "0.1.0"

__all__ = [
    "Gatekeeper", "validate_key", "current_principal", "Limiter",
    "ServerPolicy", "Principal",
    "Store", "MemoryStore", "JsonFileStore", "KeyRecord", "InviteRecord", "InviteError",
    "mint_key", "create_invite", "peek_invite", "claim_invite", "revoke_invite",
    "granted_servers", "hash_secret",
    "AuditSink", "NullAudit", "ListAudit", "PrintAudit", "AuditEvent",
    "reconcile", "assert_grantable", "ToolRegistryDrift",
]
