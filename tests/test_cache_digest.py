"""
Tests for CacheDigest (Cuckoo filter implementation)

These tests use cross-language test vectors to ensure compatibility
with the JavaScript implementation.
"""

import pytest
from skybolt.cache_digest import (
    CacheDigest,
    fnv1a,
    fingerprint,
    compute_alternate_bucket,
    FINGERPRINT_BITS,
)


class TestFnv1a:
    """Cross-language test vectors for FNV-1a hash."""

    def test_matches_javascript(self):
        """Test vectors verified against JavaScript BigInt implementation."""
        test_cases = [
            ("src/css/critical.css:abc123", 821208812),
            ("src/css/main.css:def456", 26790494),
            ("skybolt-launcher:xyz789", 452074441),
            ("123", 1916298011),
            ("", 2166136261),  # Empty string returns offset basis
            ("a", 3826002220),
            ("test", 2949673445),
        ]

        for input_str, expected in test_cases:
            assert fnv1a(input_str) == expected, f"FNV-1a hash mismatch for '{input_str}'"


class TestFingerprint:
    """Test fingerprint generation."""

    def test_in_valid_range(self):
        """Fingerprint should be in range [1, 4095] (12 bits, never 0)."""
        test_cases = [
            "src/css/critical.css:abc123",
            "src/css/main.css:def456",
            "skybolt-launcher:xyz789",
        ]

        for input_str in test_cases:
            fp = fingerprint(input_str)
            assert 1 <= fp <= 4095

    def test_never_zero(self):
        """Fingerprint should never return 0."""
        for i in range(1000):
            fp = fingerprint(f"test-{i}")
            assert fp != 0, "Fingerprint should never be 0"


class TestAlternateBucket:
    """Test alternate bucket calculation."""

    def test_reversible(self):
        """Alternate bucket calculation should be reversible."""
        num_buckets = 16  # Power of 2

        for bucket in range(num_buckets):
            for fp in range(1, 101):
                alt = compute_alternate_bucket(bucket, fp, num_buckets)
                original = compute_alternate_bucket(alt, fp, num_buckets)
                assert bucket == original, f"Alternate bucket should be reversible: bucket={bucket}, fp={fp}"


class TestCacheDigest:
    """Test CacheDigest class."""

    # This digest was created by the JavaScript implementation with these assets:
    # - src/css/critical.css:B20ictSB
    # - src/css/main.css:DfFbFQk_
    # - src/js/app.js:DW873Fox
    # - skybolt-launcher:ptJmv_9y
    VALID_DIGEST = "AQAEAAQAAAAAAAAAAAXNB-UAAAAACT4NhgAAAAAAAAAAAAAAAA"

    def test_parse_valid_digest(self):
        """Test parsing a valid digest from JavaScript."""
        cd = CacheDigest.from_base64(self.VALID_DIGEST)

        assert cd.is_valid()

        # These should be found
        assert cd.lookup("src/css/critical.css:B20ictSB")
        assert cd.lookup("src/css/main.css:DfFbFQk_")
        assert cd.lookup("src/js/app.js:DW873Fox")
        assert cd.lookup("skybolt-launcher:ptJmv_9y")

        # These should NOT be found (different hashes)
        assert not cd.lookup("src/css/critical.css:DIFFERENT")
        assert not cd.lookup("src/css/main.css:DIFFERENT")
        assert not cd.lookup("nonexistent:asset")

    def test_parse_empty_digest(self):
        """Test parsing empty digest."""
        cd = CacheDigest.from_base64("")
        assert not cd.is_valid()
        assert not cd.lookup("anything")

    def test_parse_invalid_base64(self):
        """Test parsing invalid base64."""
        cd = CacheDigest.from_base64("not-valid-base64!!!")
        assert not cd.is_valid()

    def test_parse_wrong_version(self):
        """Test parsing digest with wrong version."""
        import base64
        # Version 2 header (invalid)
        cd = CacheDigest.from_base64(base64.b64encode(b"\x02\x00\x04\x00\x00").decode())
        assert not cd.is_valid()

    def test_parse_truncated_digest(self):
        """Test parsing truncated digest."""
        import base64
        # Too short
        cd = CacheDigest.from_base64(base64.b64encode(b"\x01\x00").decode())
        assert not cd.is_valid()

    def test_url_safe_base64(self):
        """Test URL-safe base64 handling."""
        # Same digest with URL-safe characters (- instead of +, _ instead of /)
        cd = CacheDigest.from_base64(self.VALID_DIGEST)

        assert cd.is_valid()
        assert cd.lookup("src/css/critical.css:B20ictSB")
