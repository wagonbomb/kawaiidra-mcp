"""Caching system for Kawaiidra MCP Server.

Provides intelligent caching of expensive Ghidra operations to significantly
speed up repeated queries on the same binaries.

Cache invalidation is based on:
- Binary file modification time
- Ghidra project modification time
- Cache TTL (time-to-live)
- Manual invalidation

Cacheable operations:
- list_functions, list_strings, list_exports, list_imports
- get_function_decompile, get_function_disassembly
- get_call_graph, detect_libraries, semantic_code_search
- detect_vulnerabilities, get_data_structures
- generate_report (expensive, benefits most from caching)
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger("kawaiidra.cache")


@dataclass
class CacheEntry:
    """Represents a cached result entry."""
    key: str
    data: Any
    created_at: float
    binary_mtime: float
    project_mtime: float
    tool_name: str
    binary_name: str
    project_name: str
    params_hash: str
    hits: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "CacheEntry":
        return cls(**d)


class KawaiidraCache:
    """File-based cache for Kawaiidra MCP operations.

    Features:
    - Automatic invalidation based on file modification times
    - Configurable TTL per operation type
    - Statistics tracking
    - Size-limited cache with LRU eviction
    """

    # Default TTL settings (in seconds)
    DEFAULT_TTL = {
        # Read-only operations - long TTL since data doesn't change
        "list_functions": 3600 * 24,      # 24 hours
        "list_strings": 3600 * 24,         # 24 hours
        "list_exports": 3600 * 24,         # 24 hours
        "list_imports": 3600 * 24,         # 24 hours
        "list_data_items": 3600 * 24,      # 24 hours
        "list_namespaces": 3600 * 24,      # 24 hours
        "get_binary_info": 3600 * 24,      # 24 hours
        "get_memory_map": 3600 * 24,       # 24 hours

        # Decompilation - moderately long TTL
        "get_function_decompile": 3600 * 12,  # 12 hours
        "get_function_disassembly": 3600 * 12,  # 12 hours
        "get_annotated_disassembly": 3600 * 12,  # 12 hours
        "get_function_with_context": 3600 * 12,  # 12 hours
        "get_control_flow_graph": 3600 * 12,  # 12 hours

        # Analysis operations - medium TTL
        "get_call_graph": 3600 * 6,        # 6 hours
        "detect_libraries": 3600 * 6,      # 6 hours
        "semantic_code_search": 3600 * 6,  # 6 hours
        "get_data_structures": 3600 * 6,   # 6 hours
        "find_similar_functions": 3600 * 6,  # 6 hours

        # Vulnerability detection - shorter TTL (might update signatures)
        "detect_vulnerabilities": 3600 * 2,  # 2 hours

        # Full reports - long TTL since they're expensive
        "generate_report": 3600 * 24,      # 24 hours

        # Cross-references - medium TTL
        "get_function_xrefs": 3600 * 6,    # 6 hours

        # iOS/macOS specific - long TTL
        "detect_kpp_ktrr": 3600 * 24,      # 24 hours
        "analyze_mach_traps": 3600 * 24,   # 24 hours
        "find_pac_gadgets": 3600 * 24,     # 24 hours
        "analyze_sandbox_ops": 3600 * 24,  # 24 hours
        "find_iokit_classes": 3600 * 24,   # 24 hours
        "detect_entitlement_checks": 3600 * 24,  # 24 hours
        "find_kernel_symbols": 3600 * 24,  # 24 hours
        "analyze_mach_ports": 3600 * 24,   # 24 hours

        # Default for unknown operations
        "default": 3600,  # 1 hour
    }

    # Operations that should NOT be cached (modify state)
    NON_CACHEABLE = {
        "analyze_binary",  # Creates new analysis
        "rename_function",
        "rename_data",
        "rename_variable",
        "set_comment",
        "set_function_prototype",
        "set_local_variable_type",
        "export_analysis",
        "suggest_symbol_names",  # May vary with context
    }

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        enabled: bool = True,
        max_size_mb: int = 500,
        custom_ttl: Optional[dict[str, int]] = None
    ):
        """Initialize the cache.

        Args:
            cache_dir: Directory to store cache files. Defaults to ~/.kawaiidra/cache
            enabled: Whether caching is enabled
            max_size_mb: Maximum cache size in megabytes
            custom_ttl: Override default TTL settings
        """
        self.enabled = enabled
        self.max_size_bytes = max_size_mb * 1024 * 1024

        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / ".kawaiidra" / "cache"

        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Merge custom TTL settings
        self.ttl = dict(self.DEFAULT_TTL)
        if custom_ttl:
            self.ttl.update(custom_ttl)

        # Statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "invalidations": 0,
            "evictions": 0,
        }

        # In-memory index for faster lookups
        self._index: dict[str, Path] = {}
        self._load_index()

        logger.info(f"Cache initialized: dir={self.cache_dir}, enabled={enabled}, max_size={max_size_mb}MB")

    def _load_index(self) -> None:
        """Load cache index from disk."""
        index_file = self.cache_dir / "index.json"
        if index_file.exists():
            try:
                with open(index_file, "r") as f:
                    index_data = json.load(f)
                    self._index = {k: Path(v) for k, v in index_data.items()}
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load cache index: {e}")
                self._index = {}

    def _save_index(self) -> None:
        """Save cache index to disk."""
        index_file = self.cache_dir / "index.json"
        try:
            with open(index_file, "w") as f:
                json.dump({k: str(v) for k, v in self._index.items()}, f)
        except IOError as e:
            logger.warning(f"Failed to save cache index: {e}")

    def _generate_key(
        self,
        tool_name: str,
        binary_name: str,
        project_name: str,
        params: dict[str, Any]
    ) -> str:
        """Generate a unique cache key for an operation.

        The key is based on:
        - Tool name
        - Binary name
        - Project name
        - Sorted, serialized parameters
        """
        # Sort params for consistent hashing
        params_str = json.dumps(params, sort_keys=True, default=str)
        params_hash = hashlib.md5(params_str.encode()).hexdigest()[:12]

        # Create readable key
        key = f"{project_name}:{binary_name}:{tool_name}:{params_hash}"
        return key

    def _get_cache_path(self, key: str) -> Path:
        """Get the file path for a cache entry."""
        # Use first 2 chars as subdirectory for better file distribution
        safe_key = key.replace(":", "_").replace("/", "_")
        subdir = safe_key[:2] if len(safe_key) >= 2 else "00"
        return self.cache_dir / subdir / f"{safe_key}.json"

    def _get_binary_mtime(self, binary_path: Path) -> float:
        """Get modification time of a binary file."""
        try:
            return binary_path.stat().st_mtime
        except (OSError, FileNotFoundError):
            return 0.0

    def _get_project_mtime(self, project_dir: Path, project_name: str) -> float:
        """Get modification time of a Ghidra project."""
        # Ghidra projects have .gpr file and .rep directory
        gpr_file = project_dir / f"{project_name}.gpr"
        rep_dir = project_dir / f"{project_name}.rep"

        mtime = 0.0
        try:
            if gpr_file.exists():
                mtime = max(mtime, gpr_file.stat().st_mtime)
            if rep_dir.exists():
                mtime = max(mtime, rep_dir.stat().st_mtime)
        except OSError:
            pass

        return mtime

    def is_cacheable(self, tool_name: str) -> bool:
        """Check if an operation is cacheable."""
        return tool_name not in self.NON_CACHEABLE

    def get(
        self,
        tool_name: str,
        binary_name: str,
        project_name: str,
        params: dict[str, Any],
        binary_path: Optional[Path] = None,
        project_dir: Optional[Path] = None
    ) -> Optional[Any]:
        """Get a cached result if available and valid.

        Args:
            tool_name: Name of the MCP tool
            binary_name: Name of the binary
            project_name: Ghidra project name
            params: Tool parameters
            binary_path: Path to binary file (for mtime validation)
            project_dir: Path to Ghidra project directory

        Returns:
            Cached data if valid, None otherwise
        """
        if not self.enabled or not self.is_cacheable(tool_name):
            return None

        key = self._generate_key(tool_name, binary_name, project_name, params)
        cache_path = self._get_cache_path(key)

        if not cache_path.exists():
            self.stats["misses"] += 1
            return None

        try:
            with open(cache_path, "r") as f:
                entry_data = json.load(f)
                entry = CacheEntry.from_dict(entry_data)
        except (json.JSONDecodeError, IOError, TypeError, KeyError) as e:
            logger.debug(f"Cache read error for {key}: {e}")
            self.stats["misses"] += 1
            return None

        # Check TTL
        ttl = self.ttl.get(tool_name, self.ttl["default"])
        age = time.time() - entry.created_at
        if age > ttl:
            logger.debug(f"Cache expired for {key} (age={age:.0f}s, ttl={ttl}s)")
            self._invalidate(key, cache_path)
            return None

        # Check binary modification time
        if binary_path:
            current_mtime = self._get_binary_mtime(binary_path)
            if current_mtime > entry.binary_mtime:
                logger.debug(f"Binary modified since cache for {key}")
                self._invalidate(key, cache_path)
                return None

        # Check project modification time
        if project_dir:
            current_mtime = self._get_project_mtime(project_dir, project_name)
            if current_mtime > entry.project_mtime:
                logger.debug(f"Project modified since cache for {key}")
                self._invalidate(key, cache_path)
                return None

        # Valid cache hit!
        self.stats["hits"] += 1
        entry.hits += 1

        # Update hit count in file (async would be better)
        try:
            with open(cache_path, "w") as f:
                json.dump(entry.to_dict(), f)
        except IOError:
            pass

        logger.debug(f"Cache hit for {key} (age={age:.0f}s, hits={entry.hits})")
        return entry.data

    def set(
        self,
        tool_name: str,
        binary_name: str,
        project_name: str,
        params: dict[str, Any],
        data: Any,
        binary_path: Optional[Path] = None,
        project_dir: Optional[Path] = None
    ) -> None:
        """Store a result in the cache.

        Args:
            tool_name: Name of the MCP tool
            binary_name: Name of the binary
            project_name: Ghidra project name
            params: Tool parameters
            data: Result data to cache
            binary_path: Path to binary file
            project_dir: Path to Ghidra project directory
        """
        if not self.enabled or not self.is_cacheable(tool_name):
            return

        key = self._generate_key(tool_name, binary_name, project_name, params)
        cache_path = self._get_cache_path(key)

        # Ensure directory exists
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        # Get modification times
        binary_mtime = self._get_binary_mtime(binary_path) if binary_path else 0.0
        project_mtime = self._get_project_mtime(project_dir, project_name) if project_dir else 0.0

        # Create entry
        params_str = json.dumps(params, sort_keys=True, default=str)
        params_hash = hashlib.md5(params_str.encode()).hexdigest()[:12]

        entry = CacheEntry(
            key=key,
            data=data,
            created_at=time.time(),
            binary_mtime=binary_mtime,
            project_mtime=project_mtime,
            tool_name=tool_name,
            binary_name=binary_name,
            project_name=project_name,
            params_hash=params_hash,
            hits=0
        )

        try:
            with open(cache_path, "w") as f:
                json.dump(entry.to_dict(), f)
            self._index[key] = cache_path
            self._save_index()
            logger.debug(f"Cached result for {key}")
        except IOError as e:
            logger.warning(f"Failed to cache {key}: {e}")

        # Check cache size and evict if needed
        self._maybe_evict()

    def _invalidate(self, key: str, cache_path: Path) -> None:
        """Invalidate a cache entry."""
        try:
            cache_path.unlink(missing_ok=True)
            self._index.pop(key, None)
            self.stats["invalidations"] += 1
        except OSError:
            pass

    def _maybe_evict(self) -> None:
        """Evict old entries if cache is over size limit."""
        total_size = sum(
            f.stat().st_size
            for f in self.cache_dir.rglob("*.json")
            if f.is_file() and f.name != "index.json"
        )

        if total_size <= self.max_size_bytes:
            return

        # Collect all cache entries with metadata
        entries = []
        for cache_file in self.cache_dir.rglob("*.json"):
            if cache_file.name == "index.json":
                continue
            try:
                with open(cache_file, "r") as f:
                    entry_data = json.load(f)
                    entries.append({
                        "path": cache_file,
                        "size": cache_file.stat().st_size,
                        "created_at": entry_data.get("created_at", 0),
                        "hits": entry_data.get("hits", 0),
                        "key": entry_data.get("key", "")
                    })
            except (json.JSONDecodeError, IOError, KeyError):
                # Remove corrupted entries
                cache_file.unlink(missing_ok=True)

        # Sort by score: older and less accessed entries first
        # Score = created_at + (hits * 3600)  # Each hit adds 1 hour of "lifetime"
        entries.sort(key=lambda e: e["created_at"] + (e["hits"] * 3600))

        # Evict until under 80% of max size
        target_size = int(self.max_size_bytes * 0.8)
        while total_size > target_size and entries:
            entry = entries.pop(0)
            try:
                entry["path"].unlink()
                self._index.pop(entry["key"], None)
                total_size -= entry["size"]
                self.stats["evictions"] += 1
                logger.debug(f"Evicted cache entry: {entry['key']}")
            except OSError:
                pass

        self._save_index()

    def clear(self, binary_name: Optional[str] = None, project_name: Optional[str] = None) -> int:
        """Clear cache entries.

        Args:
            binary_name: Clear only entries for this binary (optional)
            project_name: Clear only entries for this project (optional)

        Returns:
            Number of entries cleared
        """
        cleared = 0

        for cache_file in self.cache_dir.rglob("*.json"):
            if cache_file.name == "index.json":
                continue

            should_clear = True

            if binary_name or project_name:
                try:
                    with open(cache_file, "r") as f:
                        entry_data = json.load(f)
                        if binary_name and entry_data.get("binary_name") != binary_name:
                            should_clear = False
                        if project_name and entry_data.get("project_name") != project_name:
                            should_clear = False
                except (json.JSONDecodeError, IOError):
                    pass

            if should_clear:
                try:
                    key = cache_file.stem
                    cache_file.unlink()
                    self._index.pop(key, None)
                    cleared += 1
                except OSError:
                    pass

        self._save_index()
        logger.info(f"Cleared {cleared} cache entries")
        return cleared

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        # Calculate cache size
        total_size = 0
        entry_count = 0

        for cache_file in self.cache_dir.rglob("*.json"):
            if cache_file.name == "index.json":
                continue
            try:
                total_size += cache_file.stat().st_size
                entry_count += 1
            except OSError:
                pass

        hit_rate = 0.0
        total_requests = self.stats["hits"] + self.stats["misses"]
        if total_requests > 0:
            hit_rate = self.stats["hits"] / total_requests * 100

        return {
            "enabled": self.enabled,
            "cache_dir": str(self.cache_dir),
            "entry_count": entry_count,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "max_size_mb": self.max_size_bytes // (1024 * 1024),
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "hit_rate_percent": round(hit_rate, 1),
            "invalidations": self.stats["invalidations"],
            "evictions": self.stats["evictions"],
        }


# Global cache instance
_cache: Optional[KawaiidraCache] = None


def get_cache() -> KawaiidraCache:
    """Get the global cache instance, creating it if necessary."""
    global _cache
    if _cache is None:
        # Check environment variables for configuration
        cache_enabled = os.environ.get("KAWAIIDRA_CACHE_ENABLED", "true").lower() == "true"
        cache_dir = os.environ.get("KAWAIIDRA_CACHE_DIR")
        max_size = int(os.environ.get("KAWAIIDRA_CACHE_MAX_SIZE_MB", "500"))

        _cache = KawaiidraCache(
            cache_dir=Path(cache_dir) if cache_dir else None,
            enabled=cache_enabled,
            max_size_mb=max_size
        )
    return _cache


def clear_cache(binary_name: Optional[str] = None, project_name: Optional[str] = None) -> int:
    """Clear cache entries (convenience function)."""
    return get_cache().clear(binary_name, project_name)


def get_cache_stats() -> dict[str, Any]:
    """Get cache statistics (convenience function)."""
    return get_cache().get_stats()
