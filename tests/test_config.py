"""
Unit tests for the Kawaiidra config module.

Tests cover:
- Config initialization
- Environment variable handling
- Path resolution
- Ghidra detection
- Directory creation
"""

import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from kawaiidra_mcp.config import Config


class TestConfigInit:
    """Tests for Config initialization."""

    def test_config_creates_with_ghidra_env(self, monkeypatch, tmp_path):
        """Should create config when GHIDRA_INSTALL_DIR is set."""
        # Create a mock Ghidra installation
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))

        config = Config()

        assert config.ghidra_home == ghidra_dir

    def test_config_uses_default_project_dir(self, monkeypatch, tmp_path):
        """Should use default project directory from package root."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.delenv("KAWAIIDRA_PROJECT_DIR", raising=False)

        config = Config()

        # Project dir should be relative to package root
        assert "projects" in str(config.project_dir)

    def test_config_respects_project_dir_env(self, monkeypatch, tmp_path):
        """Should use KAWAIIDRA_PROJECT_DIR if set."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        custom_project_dir = tmp_path / "custom_projects"

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_PROJECT_DIR", str(custom_project_dir))

        config = Config()

        assert config.project_dir == custom_project_dir

    def test_config_respects_timeout_env(self, monkeypatch, tmp_path):
        """Should use KAWAIIDRA_TIMEOUT if set."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_TIMEOUT", "600")

        config = Config()

        assert config.analysis_timeout == 600

    def test_config_default_timeout(self, monkeypatch, tmp_path):
        """Should use default timeout of 300 seconds."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.delenv("KAWAIIDRA_TIMEOUT", raising=False)

        config = Config()

        assert config.analysis_timeout == 300

    def test_config_respects_max_memory_env(self, monkeypatch, tmp_path):
        """Should use KAWAIIDRA_MAX_MEMORY if set."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_MAX_MEMORY", "8G")

        config = Config()

        assert config.max_memory == "8G"

    def test_config_default_max_memory(self, monkeypatch, tmp_path):
        """Should use default max memory of 4G."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.delenv("KAWAIIDRA_MAX_MEMORY", raising=False)

        config = Config()

        assert config.max_memory == "4G"


class TestConfigCacheSettings:
    """Tests for cache configuration."""

    def test_cache_enabled_by_default(self, monkeypatch, tmp_path):
        """Cache should be enabled by default."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.delenv("KAWAIIDRA_CACHE_ENABLED", raising=False)

        config = Config()

        assert config.cache_enabled is True

    def test_cache_can_be_disabled(self, monkeypatch, tmp_path):
        """Cache should be disabled when env var is false."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_CACHE_ENABLED", "false")

        config = Config()

        assert config.cache_enabled is False

    def test_cache_dir_default(self, monkeypatch, tmp_path):
        """Cache dir should default to ~/.kawaiidra/cache."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.delenv("KAWAIIDRA_CACHE_DIR", raising=False)

        config = Config()

        assert config.cache_dir == Path.home() / ".kawaiidra" / "cache"

    def test_cache_max_size_default(self, monkeypatch, tmp_path):
        """Cache max size should default to 500MB."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.delenv("KAWAIIDRA_CACHE_MAX_SIZE_MB", raising=False)

        config = Config()

        assert config.cache_max_size_mb == 500


class TestConfigBridgeSettings:
    """Tests for JPype bridge configuration."""

    def test_bridge_enabled_by_default(self, monkeypatch, tmp_path):
        """Bridge should be enabled by default."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.delenv("KAWAIIDRA_USE_BRIDGE", raising=False)

        config = Config()

        assert config.use_bridge is True

    def test_bridge_can_be_disabled(self, monkeypatch, tmp_path):
        """Bridge should be disabled when env var is false."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_USE_BRIDGE", "false")

        config = Config()

        assert config.use_bridge is False

    def test_bridge_cache_programs_default(self, monkeypatch, tmp_path):
        """Program caching should be enabled by default."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.delenv("KAWAIIDRA_BRIDGE_CACHE_PROGRAMS", raising=False)

        config = Config()

        assert config.bridge_cache_programs is True

    def test_bridge_max_programs_default(self, monkeypatch, tmp_path):
        """Max cached programs should default to 5."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.delenv("KAWAIIDRA_BRIDGE_MAX_PROGRAMS", raising=False)

        config = Config()

        assert config.bridge_max_cached_programs == 5


class TestConfigFindGhidraBinary:
    """Tests for _find_ghidra_binary method."""

    def test_finds_traditional_sh_binary(self, monkeypatch, tmp_path):
        """Should find traditional analyzeHeadless shell script."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        headless = support_dir / "analyzeHeadless"
        headless.write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))

        config = Config()
        result = config._find_ghidra_binary(ghidra_dir)

        assert result == headless

    def test_finds_traditional_bat_binary(self, monkeypatch, tmp_path):
        """Should find traditional analyzeHeadless.bat on Windows."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        headless = support_dir / "analyzeHeadless.bat"
        headless.write_text("@echo off")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))

        config = Config()
        result = config._find_ghidra_binary(ghidra_dir)

        assert result == headless

    def test_finds_homebrew_binary(self, monkeypatch, tmp_path):
        """Should find Homebrew Cellar installation."""
        brew_dir = tmp_path / "homebrew"
        cellar_dir = brew_dir / "Cellar" / "ghidra" / "12.0" / "libexec" / "support"
        cellar_dir.mkdir(parents=True)
        headless = cellar_dir / "analyzeHeadless"
        headless.write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(brew_dir))

        config = Config()
        result = config._find_ghidra_binary(brew_dir)

        assert result == headless

    def test_returns_none_for_empty_dir(self, monkeypatch, tmp_path):
        """Should return None for directory without Ghidra."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        # Need to set a valid ghidra for Config init
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))

        config = Config()
        result = config._find_ghidra_binary(empty_dir)

        assert result is None


class TestConfigEnsureDirectories:
    """Tests for ensure_directories method."""

    def test_creates_all_directories(self, monkeypatch, tmp_path):
        """Should create all required directories."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        project_dir = tmp_path / "projects"
        binaries_dir = tmp_path / "binaries"
        exports_dir = tmp_path / "exports"
        log_dir = tmp_path / "logs"

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_PROJECT_DIR", str(project_dir))
        monkeypatch.setenv("KAWAIIDRA_BINARIES_DIR", str(binaries_dir))
        monkeypatch.setenv("KAWAIIDRA_EXPORTS_DIR", str(exports_dir))
        monkeypatch.setenv("KAWAIIDRA_LOG_DIR", str(log_dir))

        config = Config()
        config.ensure_directories()

        assert project_dir.exists()
        assert binaries_dir.exists()
        assert exports_dir.exists()
        assert log_dir.exists()

    def test_handles_existing_directories(self, monkeypatch, tmp_path):
        """Should not fail if directories already exist."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        project_dir = tmp_path / "projects"
        project_dir.mkdir()

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_PROJECT_DIR", str(project_dir))

        config = Config()
        # Should not raise
        config.ensure_directories()

        assert project_dir.exists()


class TestConfigGetProjectPath:
    """Tests for get_project_path method."""

    def test_returns_path_with_project_name(self, monkeypatch, tmp_path):
        """Should return project directory path."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        project_dir = tmp_path / "projects"

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_PROJECT_DIR", str(project_dir))

        config = Config()
        result = config.get_project_path("myproject")

        assert result == project_dir / "myproject"

    def test_uses_default_project_when_none(self, monkeypatch, tmp_path):
        """Should use default project name when None provided."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        project_dir = tmp_path / "projects"

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_PROJECT_DIR", str(project_dir))
        monkeypatch.delenv("KAWAIIDRA_DEFAULT_PROJECT", raising=False)

        config = Config()
        result = config.get_project_path(None)

        assert result == project_dir / "default"

    def test_respects_custom_default_project(self, monkeypatch, tmp_path):
        """Should use custom default project name."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        project_dir = tmp_path / "projects"

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_PROJECT_DIR", str(project_dir))
        monkeypatch.setenv("KAWAIIDRA_DEFAULT_PROJECT", "custom_default")

        config = Config()
        result = config.get_project_path(None)

        assert result == project_dir / "custom_default"


class TestConfigValidate:
    """Tests for validate method."""

    def test_returns_empty_for_valid_config(self, monkeypatch, tmp_path):
        """Should return empty list for valid configuration."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))

        config = Config()
        errors = config.validate()

        assert errors == []

    def test_returns_errors_for_missing_ghidra(self, monkeypatch, tmp_path):
        """Should return error for missing Ghidra directory."""
        # First create a valid config
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))

        config = Config()

        # Then modify the path to non-existent location
        config.ghidra_home = tmp_path / "nonexistent"
        errors = config.validate()

        assert len(errors) > 0
        assert "not found" in errors[0].lower()


class TestConfigRepr:
    """Tests for __repr__ method."""

    def test_repr_contains_key_info(self, monkeypatch, tmp_path):
        """__repr__ should contain key configuration info."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))

        config = Config()
        repr_str = repr(config)

        assert "ghidra_home" in repr_str
        assert "project_dir" in repr_str
        assert "binaries_dir" in repr_str
        assert "analysis_timeout" in repr_str


class TestConfigAnalyzeHeadless:
    """Tests for analyze_headless property."""

    def test_returns_path_to_analyzer(self, monkeypatch, tmp_path):
        """Should return path to analyzer script."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        headless = support_dir / "analyzeHeadless"
        headless.write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))

        config = Config()

        assert config.analyze_headless == headless

    def test_raises_for_missing_analyzer(self, monkeypatch, tmp_path):
        """Should raise FileNotFoundError for missing analyzer."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        headless = support_dir / "analyzeHeadless"
        headless.write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))

        config = Config()

        # Remove the analyzer
        headless.unlink()
        config._analyzer_type = None  # Reset cached value

        with pytest.raises(FileNotFoundError):
            _ = config.analyze_headless


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
