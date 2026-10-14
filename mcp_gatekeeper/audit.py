"""Who called what.

An interface, because the useful destination differs: stdout in development, a
table you can query in production, an append-only log where compliance can read
it.

What matters is that a refusal is recorded as loudly as a success. A denied call
is the one you most want to see afterwards. Code that swallows its permission
check tends to swallow the audit line too, and then the requests that get
through ungated leave no trace at all.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from .policy import Principal


@dataclass
class AuditEvent:
    timestamp: datetime
    actor: str
    actor_key_id: str
    server: str
    action: str
    details: str = ""


class AuditSink(Protocol):
    def record(self, principal: Principal, server: str, action: str,
               details: str = "") -> None: ...


class NullAudit:
    def record(self, principal, server, action, details="") -> None:
        return None


class ListAudit:
    """Keeps events in memory. For tests, and for seeing what a run did."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, principal, server, action, details="") -> None:
        self.events.append(AuditEvent(
            timestamp=datetime.now(timezone.utc),
            actor=getattr(principal, "name", "unknown"),
            actor_key_id=getattr(principal, "key_id", ""),
            server=server, action=action, details=details))

    def actions(self) -> list[str]:
        return [e.action for e in self.events]


class PrintAudit:
    def record(self, principal, server, action, details="") -> None:
        stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        line = "%s  %-16s %-12s %s" % (stamp, getattr(principal, "name", "?"),
                                       server, action)
        print(line + ("  — " + details if details else ""))
