"""Tests for rate limiter."""

import time

from git_guardian.scanner.rate_limiter import (
    TokenBucketRateLimiter,
    get_npm_rate_limiter,
)


class TestTokenBucketRateLimiter:
    """Test the token bucket rate limiter."""

    def test_init_defaults(self):
        limiter = TokenBucketRateLimiter()
        assert limiter.bucket_size == 10
        assert limiter.refill_rate == 5.0

    def test_init_custom(self):
        limiter = TokenBucketRateLimiter(bucket_size=20, refill_rate=10.0)
        assert limiter.bucket_size == 20
        assert limiter.refill_rate == 10.0

    def test_acquire_immediate(self):
        limiter = TokenBucketRateLimiter(bucket_size=5, refill_rate=1.0)
        assert limiter.acquire(1) is True
        assert limiter.total_requests == 1

    def test_acquire_multiple(self):
        limiter = TokenBucketRateLimiter(bucket_size=5, refill_rate=1.0)
        assert limiter.acquire(5) is True
        assert limiter.total_requests == 1

    def test_acquire_exhausted_non_blocking(self):
        limiter = TokenBucketRateLimiter(bucket_size=2, refill_rate=0.1)
        limiter.acquire(2)
        assert limiter.try_acquire(1) is False

    def test_acquire_blocking_waits(self):
        limiter = TokenBucketRateLimiter(bucket_size=1, refill_rate=100.0)
        limiter.acquire(1)
        start = time.monotonic()
        limiter.acquire(1, blocking=True)
        elapsed = time.monotonic() - start
        assert elapsed >= 0.005  # Should have waited some time
        assert limiter.total_requests == 2

    def test_refill_over_time(self):
        limiter = TokenBucketRateLimiter(bucket_size=10, refill_rate=100.0)
        limiter.acquire(10)
        assert limiter.available_tokens < 1
        time.sleep(0.05)
        assert limiter.available_tokens > 1

    def test_try_acquire(self):
        limiter = TokenBucketRateLimiter(bucket_size=3, refill_rate=1.0)
        assert limiter.try_acquire(3) is True
        assert limiter.try_acquire(1) is False

    def test_stats(self):
        limiter = TokenBucketRateLimiter(bucket_size=5, refill_rate=2.0)
        limiter.acquire(2)
        stats = limiter.get_stats()
        assert stats["total_requests"] == 1
        assert stats["bucket_size"] == 5
        assert stats["refill_rate"] == 2.0
        assert isinstance(stats["available_tokens"], float)

    def test_available_tokens_refills(self):
        limiter = TokenBucketRateLimiter(bucket_size=10, refill_rate=1000.0)
        limiter.acquire(10)
        assert limiter.available_tokens < 1
        time.sleep(0.02)
        assert limiter.available_tokens > 1

    def test_thread_safety(self):
        """Test concurrent acquire calls."""
        import threading

        limiter = TokenBucketRateLimiter(bucket_size=100, refill_rate=1000.0)
        results = []

        def acquire_worker():
            for _ in range(10):
                limiter.acquire(1)
            results.append(True)

        threads = [threading.Thread(target=acquire_worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 5
        assert limiter.total_requests == 50


class TestGlobalRateLimiter:
    """Test the global rate limiter singleton."""

    def test_get_npm_rate_limiter(self):
        # Reset global state
        import git_guardian.scanner.rate_limiter as mod
        mod._npm_rate_limiter = None

        limiter = get_npm_rate_limiter()
        assert isinstance(limiter, TokenBucketRateLimiter)
        assert limiter.bucket_size == 10
        assert limiter.refill_rate == 5.0

    def test_singleton(self):
        import git_guardian.scanner.rate_limiter as mod
        mod._npm_rate_limiter = None

        limiter1 = get_npm_rate_limiter()
        limiter2 = get_npm_rate_limiter()
        assert limiter1 is limiter2
