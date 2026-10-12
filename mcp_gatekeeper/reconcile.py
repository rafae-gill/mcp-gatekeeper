"""Catch the gap between what a server SERVES and what you can GRANT.

This exists because of a specific production failure, and it is the one piece
here that is not standard practice.

If access is granted from a registry — a dashboard, a config file, a seed
script — that registry lists tool names. A tool added to the server but not to
the registry **cannot be granted to anybody**. It then fails for every normal
user while continuing to work for anyone holding a `"*"` wildcard.

That combination is nasty:

  * the person who added the tool is usually an admin, so it works for them;
  * it is refused for everyone else, as a permission error at call time;
  * nothing fails at deploy, nothing logs at startup.

Ours went unnoticed for weeks. It was found when a colleague on a normal key
ran the same workflow and the state writes silently did nothing.

The inverse — a name in the registry that the server does not serve — is
harmless: the grant simply never matches. So the check is deliberately
asymmetric, and only `served_not_grantable` should fail a build.

Usage:

    from mcp_gatekeeper.reconcile import reconcile, assert_grantable

    served = [t.name for t in await mcp.list_tools()]
    assert_grantable(served, REGISTRY["warehouse"])   # raises on a real gap
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Reconciliation:
    served_not_grantable: list[str]
    grantable_not_served: list[str]

    @property
    def ok(self) -> bool:
        """Only the dangerous direction counts as failure."""
        return not self.served_not_grantable

    def report(self) -> str:
        lines = []
        if self.served_not_grantable:
            lines.append(
                "SERVED BUT NOT GRANTABLE (%d) — nobody without a wildcard can "
                "call these:\n    %s"
                % (len(self.served_not_grantable),
                   ", ".join(self.served_not_grantable)))
        if self.grantable_not_served:
            lines.append(
                "grantable but not served (%d) — harmless, the grant never "
                "matches:\n    %s"
                % (len(self.grantable_not_served),
                   ", ".join(self.grantable_not_served)))
        return "\n".join(lines) or "tools reconcile: registry matches what is served"


def reconcile(served: list[str], grantable: list[str]) -> Reconciliation:
    s, g = set(served or []), set(grantable or [])
    return Reconciliation(sorted(s - g), sorted(g - s))


class ToolRegistryDrift(RuntimeError):
    pass


def assert_grantable(served: list[str], grantable: list[str]) -> None:
    """Raise if any served tool cannot be granted. Call it at startup or in CI.

    Cheap enough to run on every boot, and it turns a permission error that
    surfaces weeks later for one unlucky colleague into a failure at the moment
    the tool was added.
    """
    r = reconcile(served, grantable)
    if not r.ok:
        raise ToolRegistryDrift(r.report())
