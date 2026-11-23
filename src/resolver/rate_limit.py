"""Token-spacing rate limiter for HTTP probing (optional, --rate)."""

from __future__ import annotations

import asyncio


class RateLimiter:
    """Limits the *start rate* of async operations (requests per second).

    ``rps <= 0`` disables limiting entirely (the concurrency cap is then the
    only throttle). Slots are scheduled while holding a lock, so parallel
    workers keep a minimum interval between request starts.
    """

    def __init__(self, rps: float = 0):
        self._interval = 1.0 / rps if rps and rps > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_slot = 0.0

    async def acquire(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            scheduled = max(now, self._next_slot)
            self._next_slot = scheduled + self._interval
        wait = scheduled - now
        if wait > 0:
            await asyncio.sleep(wait)
