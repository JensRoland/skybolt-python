"""
Cache Digest - Cuckoo Filter implementation for compact cache state tracking

A space-efficient probabilistic data structure that compresses cache state
tracking by ~85%, keeping cookies small even with many assets.

Key properties:
- No false negatives: if an asset is cached, the filter will always report it
- Small false positive rate (~1-3%): occasionally reports uncached assets as cached
- Compact: ~2 bytes per asset vs ~40+ bytes for full serialization
"""

from __future__ import annotations

import base64

FINGERPRINT_BITS = 12
BUCKET_SIZE = 4


def fnv1a(s: str) -> int:
    """FNV-1a hash function (32-bit)."""
    hash_val = 2166136261
    for char in s:
        hash_val ^= ord(char)
        hash_val = (hash_val * 16777619) & 0xFFFFFFFF
    return hash_val


def fingerprint(s: str) -> int:
    """Generate fingerprint from string."""
    hash_val = fnv1a(s)
    fp = hash_val & ((1 << FINGERPRINT_BITS) - 1)
    return fp if fp != 0 else 1


def compute_alternate_bucket(bucket: int, fp: int, num_buckets: int) -> int:
    """Compute alternate bucket using partial-key cuckoo hashing."""
    fp_hash = fnv1a(str(fp))
    bucket_mask = num_buckets - 1
    offset = (fp_hash | 1) & bucket_mask
    return (bucket ^ offset) & bucket_mask


class CacheDigest:
    """
    Cache Digest - Cuckoo Filter for compact cache state tracking.

    A space-efficient probabilistic data structure that provides:
    - No false negatives: if an asset is cached, the filter will always report it
    - Small false positive rate (~1-3%): occasionally reports uncached assets as cached
    """

    def __init__(self) -> None:
        self._buckets: list[int] | None = None
        self._num_buckets: int = 0

    @classmethod
    def from_base64(cls, digest: str) -> "CacheDigest":
        """Create a CacheDigest from a base64-encoded cookie value."""
        instance = cls()
        instance._parse(digest)
        return instance

    def lookup(self, item: str) -> bool:
        """
        Check if an item might be in the filter.

        Args:
            item: The item to look up (e.g., "src/css/main.css:Pw3rT8vL")

        Returns:
            True if item might be present (possible false positive),
            False if item is definitely not present
        """
        if self._buckets is None:
            return False

        fp = fingerprint(item)
        i1 = self._primary_bucket(item)
        i2 = compute_alternate_bucket(i1, fp, self._num_buckets)

        return self._bucket_contains(i1, fp) or self._bucket_contains(i2, fp)

    def is_valid(self) -> bool:
        """Check if the digest was successfully parsed."""
        return self._buckets is not None

    def _parse(self, digest: str) -> bool:
        """Parse a base64-encoded Cache Digest."""
        if not digest:
            return False

        # Handle URL-safe base64
        normalized = digest.replace("-", "+").replace("_", "/")
        # Add padding if needed
        padding = (4 - len(normalized) % 4) % 4
        normalized += "=" * padding

        try:
            data = base64.b64decode(normalized)
        except Exception:
            return False

        if len(data) < 5:
            return False

        # Check version
        if data[0] != 1:
            return False

        self._num_buckets = (data[1] << 8) | data[2]
        num_fingerprints = self._num_buckets * BUCKET_SIZE

        self._buckets = []
        for i in range(num_fingerprints):
            offset = 5 + i * 2
            if offset + 1 < len(data):
                self._buckets.append((data[offset] << 8) | data[offset + 1])
            else:
                self._buckets.append(0)

        return True

    def _primary_bucket(self, s: str) -> int:
        """Compute primary bucket index."""
        return fnv1a(s) % self._num_buckets

    def _bucket_contains(self, bucket_index: int, fp: int) -> bool:
        """Check if bucket contains fingerprint."""
        if self._buckets is None:
            return False
        offset = bucket_index * BUCKET_SIZE
        for i in range(BUCKET_SIZE):
            if self._buckets[offset + i] == fp:
                return True
        return False
