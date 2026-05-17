"""Rate limiter for npm registry requests using token bucket algorithm."""

import threading
import time


class TokenBucketRateLimiter:
    """Token bucket rate limiter for controlling request rates.

    Allows burst up to bucket_size, then refills at refill_rate tokens/second.
    Thread-safe for use across multiple scan workers.
    """

    def __init__(
        self,
        bucket_size: int = 10,
        refill_rate: float = 5.0,
    ) -> None:
        """Initialize rate limiter.

        Args:
            bucket_size: Maximum tokens in bucket (burst capacity)
            refill_rate: Tokens added per second
        """
        self.bucket_size = bucket_size
        self.refill_rate = refill_rate
        self._tokens = float(bucket_size)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

        # Stats
        self.total_requests = 0
        self.total_wait_seconds = 0.0

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            self.bucket_size,
            self._tokens + elapsed * self.refill_rate,
        )
        self._last_refill = now

    def acquire(self, tokens: int = 1, blocking: bool = True) -> bool:
        """Acquire tokens from the bucket.

        Args:
            tokens: Number of tokens to acquire
            blocking: If True, wait until tokens available. If False, return immediately.

        Returns:
            True if tokens acquired, False if non-blocking and not available
        """
        with self._lock:
            self._refill()

            if self._tokens >= tokens:
                self._tokens -= tokens
                self.total_requests += 1
                return True

            if not blocking:
                return False

            # Calculate wait time
            deficit = tokens - self._tokens
            wait_time = deficit / self.refill_rate

        # Wait outside the lock
        time.sleep(wait_time)

        with self._lock:
            self._refill()
            self._tokens -= tokens
            self.total_requests += 1
            self.total_wait_seconds += wait_time
            return True

    def try_acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens without blocking.

        Args:
            tokens: Number of tokens to acquire

        Returns:
            True if tokens acquired, False otherwise
        """
        return self.acquire(tokens, blocking=False)

    @property
    def available_tokens(self) -> float:
        """Get current number of available tokens."""
        with self._lock:
            self._refill()
            return self._tokens

    def get_stats(self) -> dict[str, float | int]:
        """Get rate limiter statistics."""
        return {
            "total_requests": self.total_requests,
            "total_wait_seconds": round(self.total_wait_seconds, 3),
            "available_tokens": round(self.available_tokens, 1),
            "bucket_size": self.bucket_size,
            "refill_rate": self.refill_rate,
        }


# Global rate limiter for npm registry
_npm_rate_limiter: TokenBucketRateLimiter | None = None
_limiter_lock = threading.Lock()


def get_npm_rate_limiter() -> TokenBucketRateLimiter:
    """Get the global npm rate limiter instance."""
    global _npm_rate_limiter
    with _limiter_lock:
        if _npm_rate_limiter is None:
            _npm_rate_limiter = TokenBucketRateLimiter(
                bucket_size=10,
                refill_rate=5.0,
            )
        return _npm_rate_limiter
