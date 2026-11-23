"""Tests for the token-spacing rate limiter."""

import asyncio
import time

from src.resolver.rate_limit import RateLimiter


def test_zero_rps_is_unlimited():
    limiter = RateLimiter(0)

    async def run():
        await asyncio.gather(*[limiter.acquire() for _ in range(10)])

    start = time.perf_counter()
    asyncio.run(run())
    assert time.perf_counter() - start < 0.5


def test_rps_spacing():
    limiter = RateLimiter(20)  # 50 ms between starts

    async def run():
        await asyncio.gather(limiter.acquire(), limiter.acquire(), limiter.acquire())

    start = time.perf_counter()
    asyncio.run(run())
    elapsed = time.perf_counter() - start
    # 3 starts at 20 rps → two waits of ~50 ms each.
    assert elapsed >= 0.09
