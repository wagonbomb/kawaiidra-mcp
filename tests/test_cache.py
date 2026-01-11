"""
Unit tests for the Kawaiidra cache module.

Tests cover:
- CacheEntry dataclass
- KawaiidraCache class
- Cache key generation
- TTL expiration
- Binary/project modification time validation
- Cache eviction (LRU)
- Statistics tracking
"""

import pytest
import time
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from kawaiidra_mcp.cache import (
    CacheEntry,
    KawaiidraCache,
    get_cache,
    clear_cache,
    get_cache_stats,
)


class TestCacheEntry:
    """Tests for CacheEntry dataclass."""

    def test_create_entry(self):
        """Should create a cache entry with all fields."""
        entry = CacheEntry(
            key="test:key",
            data={"result": "value"},
            created_at=time.time(),
            binary_mtime=1000.0,
            project_mtime=2000.0,
            tool_name="list_functions",
            binary_name="test.exe",
            project_name="default",
            params_hash="abc123",
            hits=0
        )

        assert entry.key == "test:key"
        assert entry.data == {"result": "value"}
        assert entry.tool_name == "list_functions"
        assert entry.hits == 0

    def test_to_dict(self):
        """Should convert entry to dictionary."""
        entry = CacheEntry(
            key="test:key",
            data={"result": "value"},
            created_at=1234567890.0,
            binary_mtime=1000.0,
            project_mtime=2000.0,
            tool_name="list_functions",
            binary_name="test.exe",
            project_name="default",
            params_hash="abc123",
            hits=5
        )

        d = entry.to_dict()

        assert isinstance(d, dict)
        assert d["key"] == "test:key"
        assert d["hits"] == 5
        assert d["data"] == {"result": "value"}

    def test_from_dict(self):
        """Should create entry from dictionary."""
        d = {
            "key": "test:key",
            "data": {"result": "value"},
            "created_at": 1234567890.0,
            "binary_mtime": 1000.0,
            "project_mtime": 2000.0,
            "tool_name": "list_functions",
            "binary_name": "test.exe",
            "project_name": "default",
            "params_hash": "abc123",
            "hits": 10
        }

        entry = CacheEntry.from_dict(d)

        assert entry.key == "test:key"
        assert entry.hits == 10
        assert entry.data == {"result": "value"}

    def test_round_trip(self):
        """Should survive to_dict -> from_dict round trip."""
        original = CacheEntry(
            key="round:trip",
            data={"nested": {"data": [1, 2, 3]}},
            created_at=time.time(),
            binary_mtime=1000.0,
            project_mtime=2000.0,
            tool_name="test_tool",
            binary_name="binary.exe",
            project_name="project",
            params_hash="hash123",
            hits=42
        )

        restored = CacheEntry.from_dict(original.to_dict())

        assert restored.key == original.key
        assert restored.data == original.data
        assert restored.hits == original.hits


class TestKawaiidraCacheInit:
    """Tests for KawaiidraCache initialization."""

    def test_creates_cache_dir(self, tmp_path):
        """Should create cache directory if it doesn't exist."""
        cache_dir = tmp_path / "new_cache"
        assert not cache_dir.exists()

        cache = KawaiidraCache(cache_dir=cache_dir)

        assert cache_dir.exists()
        assert cache.cache_dir == cache_dir

    def test_default_enabled(self, tmp_path):
        """Cache should be enabled by default."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        assert cache.enabled is True

    def test_can_disable(self, tmp_path):
        """Should be able to disable cache."""
        cache = KawaiidraCache(cache_dir=tmp_path, enabled=False)

        assert cache.enabled is False

    def test_custom_max_size(self, tmp_path):
        """Should accept custom max size."""
        cache = KawaiidraCache(cache_dir=tmp_path, max_size_mb=100)

        assert cache.max_size_bytes == 100 * 1024 * 1024

    def test_custom_ttl(self, tmp_path):
        """Should accept custom TTL settings."""
        custom_ttl = {"list_functions": 60}  # 1 minute
        cache = KawaiidraCache(cache_dir=tmp_path, custom_ttl=custom_ttl)

        assert cache.ttl["list_functions"] == 60

    def test_initial_stats(self, tmp_path):
        """Should initialize stats to zero."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        assert cache.stats["hits"] == 0
        assert cache.stats["misses"] == 0
        assert cache.stats["invalidations"] == 0
        assert cache.stats["evictions"] == 0


class TestKawaiidraCacheKeyGeneration:
    """Tests for cache key generation."""

    def test_generates_deterministic_key(self, tmp_path):
        """Same inputs should generate same key."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        key1 = cache._generate_key("list_functions", "test.exe", "default", {"limit": 100})
        key2 = cache._generate_key("list_functions", "test.exe", "default", {"limit": 100})

        assert key1 == key2

    def test_different_params_different_key(self, tmp_path):
        """Different params should generate different keys."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        key1 = cache._generate_key("list_functions", "test.exe", "default", {"limit": 100})
        key2 = cache._generate_key("list_functions", "test.exe", "default", {"limit": 200})

        assert key1 != key2

    def test_different_binary_different_key(self, tmp_path):
        """Different binary should generate different key."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        key1 = cache._generate_key("list_functions", "test1.exe", "default", {})
        key2 = cache._generate_key("list_functions", "test2.exe", "default", {})

        assert key1 != key2

    def test_different_tool_different_key(self, tmp_path):
        """Different tool should generate different key."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        key1 = cache._generate_key("list_functions", "test.exe", "default", {})
        key2 = cache._generate_key("list_strings", "test.exe", "default", {})

        assert key1 != key2

    def test_param_order_does_not_matter(self, tmp_path):
        """Parameter order should not affect key."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        key1 = cache._generate_key("tool", "binary", "project", {"a": 1, "b": 2})
        key2 = cache._generate_key("tool", "binary", "project", {"b": 2, "a": 1})

        assert key1 == key2


class TestKawaiidraCacheIsCacheable:
    """Tests for is_cacheable method."""

    def test_list_functions_is_cacheable(self, tmp_path):
        """list_functions should be cacheable."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        assert cache.is_cacheable("list_functions") is True

    def test_get_function_decompile_is_cacheable(self, tmp_path):
        """get_function_decompile should be cacheable."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        assert cache.is_cacheable("get_function_decompile") is True

    def test_analyze_binary_not_cacheable(self, tmp_path):
        """analyze_binary should NOT be cacheable."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        assert cache.is_cacheable("analyze_binary") is False

    def test_rename_function_not_cacheable(self, tmp_path):
        """rename_function should NOT be cacheable."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        assert cache.is_cacheable("rename_function") is False

    def test_set_comment_not_cacheable(self, tmp_path):
        """set_comment should NOT be cacheable."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        assert cache.is_cacheable("set_comment") is False


class TestKawaiidraCacheSetGet:
    """Tests for cache set and get operations."""

    def test_set_and_get(self, tmp_path):
        """Should store and retrieve data."""
        cache = KawaiidraCache(cache_dir=tmp_path)
        data = {"functions": [{"name": "main", "address": "0x1000"}]}

        cache.set("list_functions", "test.exe", "default", {"limit": 10}, data)
        result = cache.get("list_functions", "test.exe", "default", {"limit": 10})

        assert result == data

    def test_get_nonexistent_returns_none(self, tmp_path):
        """Should return None for nonexistent entries."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        result = cache.get("list_functions", "nonexistent.exe", "default", {})

        assert result is None

    def test_disabled_cache_returns_none(self, tmp_path):
        """Disabled cache should always return None."""
        cache = KawaiidraCache(cache_dir=tmp_path, enabled=False)
        data = {"test": "data"}

        cache.set("list_functions", "test.exe", "default", {}, data)
        result = cache.get("list_functions", "test.exe", "default", {})

        assert result is None

    def test_non_cacheable_operations_not_stored(self, tmp_path):
        """Non-cacheable operations should not be stored."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        cache.set("analyze_binary", "test.exe", "default", {}, {"success": True})
        result = cache.get("analyze_binary", "test.exe", "default", {})

        assert result is None

    def test_increments_hit_count(self, tmp_path):
        """Should increment hit count on cache hit."""
        cache = KawaiidraCache(cache_dir=tmp_path)
        cache.set("list_functions", "test.exe", "default", {}, {"data": 1})

        # Access multiple times
        cache.get("list_functions", "test.exe", "default", {})
        cache.get("list_functions", "test.exe", "default", {})

        assert cache.stats["hits"] == 2

    def test_increments_miss_count(self, tmp_path):
        """Should increment miss count on cache miss."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        cache.get("list_functions", "nonexistent.exe", "default", {})
        cache.get("list_functions", "another.exe", "default", {})

        assert cache.stats["misses"] == 2


class TestKawaiidraCacheTTL:
    """Tests for TTL (time-to-live) expiration."""

    def test_expired_entry_returns_none(self, tmp_path):
        """Should return None for expired entries."""
        cache = KawaiidraCache(cache_dir=tmp_path, custom_ttl={"test_tool": 1})
        cache.set("test_tool", "test.exe", "default", {}, {"data": 1})

        # Wait for expiration
        time.sleep(1.5)
        result = cache.get("test_tool", "test.exe", "default", {})

        assert result is None

    def test_non_expired_entry_returns_data(self, tmp_path):
        """Should return data for non-expired entries."""
        cache = KawaiidraCache(cache_dir=tmp_path, custom_ttl={"test_tool": 60})
        data = {"data": "value"}
        cache.set("test_tool", "test.exe", "default", {}, data)

        result = cache.get("test_tool", "test.exe", "default", {})

        assert result == data

    def test_uses_default_ttl_for_unknown_tool(self, tmp_path):
        """Should use default TTL for unknown tools."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        # Default TTL is 1 hour
        assert "unknown_tool" not in cache.ttl
        assert cache.ttl["default"] == 3600


class TestKawaiidraCacheModificationTime:
    """Tests for binary/project modification time validation."""

    def test_invalidates_when_binary_modified(self, tmp_path):
        """Should invalidate cache when binary is modified."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        # Create a binary file
        binary = tmp_path / "test.exe"
        binary.write_bytes(b"original content")

        # Cache some data
        cache.set("list_functions", "test.exe", "default", {}, {"data": 1},
                  binary_path=binary)

        # Modify the binary
        time.sleep(0.1)
        binary.write_bytes(b"modified content")

        # Should return None due to modification
        result = cache.get("list_functions", "test.exe", "default", {},
                          binary_path=binary)

        assert result is None

    def test_returns_data_when_binary_unchanged(self, tmp_path):
        """Should return data when binary is unchanged."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        binary = tmp_path / "test.exe"
        binary.write_bytes(b"content")

        data = {"data": "cached"}
        cache.set("list_functions", "test.exe", "default", {}, data,
                  binary_path=binary)

        result = cache.get("list_functions", "test.exe", "default", {},
                          binary_path=binary)

        assert result == data

    def test_invalidates_when_project_modified(self, tmp_path):
        """Should invalidate cache when project is modified."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        # Create project directory structure
        project_dir = tmp_path / "projects" / "default"
        project_dir.mkdir(parents=True)
        gpr_file = project_dir / "default.gpr"
        gpr_file.write_text("project file")

        # Cache some data
        cache.set("list_functions", "test.exe", "default", {}, {"data": 1},
                  project_dir=project_dir)

        # Modify the project
        time.sleep(0.1)
        gpr_file.write_text("modified project")

        # Should return None due to modification
        result = cache.get("list_functions", "test.exe", "default", {},
                          project_dir=project_dir)

        assert result is None


class TestKawaiidraCacheClear:
    """Tests for cache clearing."""

    def test_clear_all(self, tmp_path):
        """Should clear all cache entries."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        cache.set("list_functions", "test1.exe", "default", {}, {"data": 1})
        cache.set("list_functions", "test2.exe", "default", {}, {"data": 2})
        cache.set("list_strings", "test1.exe", "default", {}, {"data": 3})

        cleared = cache.clear()

        assert cleared == 3
        assert cache.get("list_functions", "test1.exe", "default", {}) is None
        assert cache.get("list_functions", "test2.exe", "default", {}) is None
        assert cache.get("list_strings", "test1.exe", "default", {}) is None

    def test_clear_by_binary(self, tmp_path):
        """Should clear only entries for specific binary."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        cache.set("list_functions", "test1.exe", "default", {}, {"data": 1})
        cache.set("list_functions", "test2.exe", "default", {}, {"data": 2})

        cleared = cache.clear(binary_name="test1.exe")

        assert cleared == 1
        assert cache.get("list_functions", "test1.exe", "default", {}) is None
        assert cache.get("list_functions", "test2.exe", "default", {}) is not None

    def test_clear_by_project(self, tmp_path):
        """Should clear only entries for specific project."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        cache.set("list_functions", "test.exe", "project1", {}, {"data": 1})
        cache.set("list_functions", "test.exe", "project2", {}, {"data": 2})

        cleared = cache.clear(project_name="project1")

        assert cleared == 1
        assert cache.get("list_functions", "test.exe", "project1", {}) is None
        assert cache.get("list_functions", "test.exe", "project2", {}) is not None


class TestKawaiidraCacheStats:
    """Tests for cache statistics."""

    def test_get_stats_structure(self, tmp_path):
        """Should return stats with expected keys."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        stats = cache.get_stats()

        assert "enabled" in stats
        assert "cache_dir" in stats
        assert "entry_count" in stats
        assert "total_size_mb" in stats
        assert "max_size_mb" in stats
        assert "hits" in stats
        assert "misses" in stats
        assert "hit_rate_percent" in stats
        assert "invalidations" in stats
        assert "evictions" in stats

    def test_stats_track_entries(self, tmp_path):
        """Should track number of entries."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        cache.set("list_functions", "test1.exe", "default", {}, {"data": 1})
        cache.set("list_functions", "test2.exe", "default", {}, {"data": 2})

        stats = cache.get_stats()

        assert stats["entry_count"] == 2

    def test_stats_calculate_hit_rate(self, tmp_path):
        """Should calculate hit rate correctly."""
        cache = KawaiidraCache(cache_dir=tmp_path)
        cache.set("list_functions", "test.exe", "default", {}, {"data": 1})

        # 2 hits, 2 misses = 50% hit rate
        cache.get("list_functions", "test.exe", "default", {})  # hit
        cache.get("list_functions", "test.exe", "default", {})  # hit
        cache.get("list_functions", "nonexistent.exe", "default", {})  # miss
        cache.get("list_strings", "test.exe", "default", {})  # miss

        stats = cache.get_stats()

        assert stats["hits"] == 2
        assert stats["misses"] == 2
        assert stats["hit_rate_percent"] == 50.0


class TestKawaiidraCacheEviction:
    """Tests for cache eviction."""

    def test_evicts_when_over_size(self, tmp_path):
        """Should evict old entries when over size limit."""
        # Create cache with 1MB limit, then manually set to tiny size
        cache = KawaiidraCache(cache_dir=tmp_path, max_size_mb=1)
        cache.max_size_bytes = 1024  # Override to 1KB for testing

        # Add entries until eviction triggers
        large_data = {"data": "x" * 500}  # ~500 bytes per entry
        for i in range(10):
            cache.set("list_functions", f"test{i}.exe", "default", {}, large_data)
            time.sleep(0.01)  # Ensure different timestamps

        # Should have evicted some entries
        assert cache.stats["evictions"] > 0


class TestGlobalCacheFunctions:
    """Tests for global cache functions."""

    def test_get_cache_returns_instance(self):
        """get_cache should return a cache instance."""
        cache = get_cache()

        assert isinstance(cache, KawaiidraCache)

    def test_get_cache_stats_returns_dict(self):
        """get_cache_stats should return stats dictionary."""
        stats = get_cache_stats()

        assert isinstance(stats, dict)
        assert "enabled" in stats

    def test_clear_cache_returns_count(self):
        """clear_cache should return number of cleared entries."""
        # This test uses the global cache, be careful with state
        count = clear_cache()

        assert isinstance(count, int)


class TestCacheEdgeCases:
    """Tests for edge cases and error handling."""

    def test_handles_corrupted_cache_file(self, tmp_path):
        """Should handle corrupted cache files gracefully."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        # Create a corrupted cache file
        key = cache._generate_key("list_functions", "test.exe", "default", {})
        cache_path = cache._get_cache_path(key)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text("not valid json {{{")

        # Should return None instead of crashing
        result = cache.get("list_functions", "test.exe", "default", {})

        assert result is None

    def test_handles_missing_binary_path(self, tmp_path):
        """Should handle missing binary path gracefully."""
        cache = KawaiidraCache(cache_dir=tmp_path)

        cache.set("list_functions", "test.exe", "default", {}, {"data": 1},
                  binary_path=tmp_path / "nonexistent.exe")
        result = cache.get("list_functions", "test.exe", "default", {},
                          binary_path=tmp_path / "nonexistent.exe")

        # Should still work, just with mtime of 0
        assert result == {"data": 1}

    def test_handles_special_characters_in_key(self, tmp_path):
        """Should handle special characters in binary/project names."""
        cache = KawaiidraCache(cache_dir=tmp_path)
        data = {"data": "test"}

        cache.set("list_functions", "path/to/binary.exe", "project:name", {}, data)
        result = cache.get("list_functions", "path/to/binary.exe", "project:name", {})

        assert result == data

    def test_handles_complex_data_types(self, tmp_path):
        """Should handle complex data types in cache."""
        cache = KawaiidraCache(cache_dir=tmp_path)
        data = {
            "list": [1, 2, {"nested": True}],
            "string": "hello",
            "number": 42.5,
            "null": None,
            "bool": True
        }

        cache.set("list_functions", "test.exe", "default", {}, data)
        result = cache.get("list_functions", "test.exe", "default", {})

        assert result == data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
