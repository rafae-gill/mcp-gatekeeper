"""How often, and how much at once, one key may call one server.

Three knobs, all per key and per server, all read from the key's policy on
every call — so tightening someone's limit is the same live store write as
changing their tools:

    "max_calls_per_minute": 30     # bursts: a runaway agent loop stops here
    "max_calls_per_day":    2000   # overall usage, rolling 24 hours
    "max_concurrent":       4      # calls running at the same time

These exist because an agent hitting a shared warehouse is a different
failure mode from a person doing it: it does not get bored, and it will happily
fire the same expensive query forty times in parallel. Throttling at the key
stops one agent starving everyone else, without touching the database.

⚠️ Counts are kept in this process's memory. One process (the usual MCP server
deployment) gets exact limits; N replicas behind a load balancer let a key
make up to N× its limit, and a restart resets the counters. Shared counters
(Redis, or the Postgres store) are the fix if that matters for you.
"""
from __future__ import annotations

import time
from collections import deque

WINDOWS = (("max_calls_per_minute", 60, "minute"),
           ("max_calls_per_day", 86_400, "day"))


class Limiter:
    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._calls: dict[tuple[str, str], dict[int, deque]] = {}
        self._running: dict[tuple[str, str], int] = {}

    def acquire(self, key_id: str, server: str, policy) -> tuple[str | None, object]:
        """Reserve a slot for one call.

        Returns (refusal, release). `refusal` is None when the call may go
        ahead; then `release()` must be called once it has finished. Checks
        and bookkeeping happen together, on the event loop, so there is no
        await between deciding and counting.
        """
        k = (key_id, server)
        now = self._clock()
        windows = self._calls.setdefault(k, {})

        for field, seconds, label in WINDOWS:
            limit = int(getattr(policy, field, 0) or 0)
            if limit <= 0:
                continue
            q = windows.setdefault(seconds, deque())
            while q and q[0] <= now - seconds:
                q.popleft()
            if len(q) >= limit:
                wait = max(1, int(q[0] + seconds - now) + 1)
                return ("RATE LIMITED: this key may make %d calls per %s to '%s'. "
                        "Try again in %s." % (limit, label, server, _human(wait))), None

        max_running = int(getattr(policy, "max_concurrent", 0) or 0)
        running = self._running.get(k, 0)
        if max_running > 0 and running >= max_running:
            return ("BUSY: this key already has %d calls running on '%s'. "
                    "Wait for one to finish." % (running, server)), None

        for field, seconds, _ in WINDOWS:
            if int(getattr(policy, field, 0) or 0) > 0:
                windows[seconds].append(now)
        self._running[k] = running + 1

        released = []

        def release():
            if not released:                       # idempotent
                released.append(True)
                self._running[k] = max(0, self._running.get(k, 1) - 1)

        return None, release


def _human(seconds: int) -> str:
    if seconds < 120:
        return "%ds" % seconds
    if seconds < 7200:
        return "%d min" % (seconds // 60)
    return "%d h" % (seconds // 3600)
