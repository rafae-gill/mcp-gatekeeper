"""What a key is allowed to do on one server.

A policy is plain data. It is read at request time from wherever keys are
stored, so changing someone's access is a write to that store — not a redeploy.
That is the single most useful property of this design: the people who grant
access are not the people who deploy.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

log = logging.getLogger("mcp_gatekeeper")

WEEKDAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
DEFAULT_TZ = "UTC"


@dataclass
class ServerPolicy:
    """Per-server permissions carried on a key.

    `tools` is an allowlist of tool names. `["*"]` is full access — convenient
    for an admin key, and worth knowing about because it hides gaps: a tool that
    cannot be granted to anyone still works for a wildcard holder, so the person
    testing never sees the failure their colleagues hit. See `reconcile.py`.

    `extra` carries server-specific knobs (query timeouts, concurrency ceilings,
    row limits). The gatekeeper does not interpret them; it hands them to the
    server, which enforces what it understands. Adding a knob needs no change
    here.
    """

    access: str = "user"
    tools: list[str] = field(default_factory=list)

    hours_from: int = 0
    hours_to: int = 0
    minutes_from: int = 0
    minutes_to: int = 0
    hours_tz: str = DEFAULT_TZ
    allowed_weekdays: list[int] = field(default_factory=list)

    extra: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict | str | None) -> "ServerPolicy | None":
        """Build a policy from stored data. Returns None when access is denied.

        Accepts a bare string for the legacy shape where a server mapped
        straight to an access level.
        """
        if d is None:
            return None
        if isinstance(d, str):
            if d.lower() == "none":
                return None
            return cls(access=d, tools=["*"])
        if not isinstance(d, dict):
            return None
        if str(d.get("access", "user")).lower() == "none":
            return None

        known = {"access", "tools", "hours_from", "hours_to", "minutes_from",
                 "minutes_to", "hours_tz", "allowed_weekdays"}
        return cls(
            access=str(d.get("access", "user")),
            tools=list(d.get("tools") or []),
            hours_from=int(d.get("hours_from") or 0),
            hours_to=int(d.get("hours_to") or 0),
            minutes_from=int(d.get("minutes_from") or 0),
            minutes_to=int(d.get("minutes_to") or 0),
            hours_tz=str(d.get("hours_tz") or DEFAULT_TZ),
            allowed_weekdays=[int(x) for x in (d.get("allowed_weekdays") or [])],
            extra={k: v for k, v in d.items() if k not in known},
        )

    def grants(self, tool_name: str) -> bool:
        if "*" in self.tools:
            return True
        return tool_name in self.tools

    def window_error(self, now: datetime | None = None) -> str | None:
        """None if the call is inside the allowed window, else a refusal string.

        ⚠️ This FAILS OPEN. An unreadable policy or an unknown timezone logs a
        warning and allows the call.

        That asymmetry is deliberate and worth stating: authentication and tool
        grants fail CLOSED, scheduling fails OPEN. A typo in a timezone field
        must not lock a key out of its database with an error nobody can
        interpret — the failure mode of a misconfigured schedule should be "no
        schedule", not "no access". They are different kinds of rule and deserve
        different defaults.
        """
        try:
            t_from = self.hours_from * 60 + self.minutes_from
            t_to = self.hours_to * 60 + self.minutes_to
            days = sorted({int(d) for d in self.allowed_weekdays})
        except (TypeError, ValueError):
            log.warning("unreadable time-window policy, allowing: %r", self)
            return None

        if t_from == t_to and not days:
            return None                                   # knob off

        if now is None:
            try:
                from zoneinfo import ZoneInfo
                now = datetime.now(ZoneInfo(self.hours_tz))
            except Exception as e:
                log.warning("bad timezone %r (%s); window not enforced",
                            self.hours_tz, e)
                return None

        if days and now.weekday() not in days:
            allowed = ", ".join(WEEKDAY_NAMES[d] for d in days if 0 <= d <= 6)
            return ("RESTRICTED: this key may only be used on %s. It is %s %s in %s."
                    % (allowed, WEEKDAY_NAMES[now.weekday()],
                       now.strftime("%H:%M"), self.hours_tz))

        if t_from != t_to:
            t = now.hour * 60 + now.minute
            # The window WRAPS: 22:00 -> 06:00 means "22:00 through 05:59",
            # not an empty range. from == to disables the check entirely, which
            # is why the default 0/0 means "any time".
            inside = (t_from <= t < t_to) if t_from < t_to else (t >= t_from or t < t_to)
            if not inside:
                return ("RESTRICTED: this key may only be used between "
                        "%02d:%02d and %02d:%02d %s. It is %s there now."
                        % (self.hours_from, self.minutes_from,
                           self.hours_to, self.minutes_to,
                           self.hours_tz, now.strftime("%H:%M")))
        return None


@dataclass
class Principal:
    """A validated caller, for one server."""

    key_id: str
    name: str
    email: str = ""
    policy: ServerPolicy = field(default_factory=ServerPolicy)

    @property
    def access_level(self) -> str:
        return self.policy.access

    def grants(self, tool_name: str) -> bool:
        return self.policy.grants(tool_name)
