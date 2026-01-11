"""
Unit tests for Ghidra index file parsing and binary listing.

These tests verify the core functionality for parsing Ghidra project
index files and listing analyzed binaries.
"""

import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from kawaiidra_mcp.server import (
    parse_ghidra_index,
    get_analyzed_binaries,
    binary_exists,
    _GHIDRA_INDEX_ENTRY_PATTERN,
)


class TestGhidraIndexPattern:
    """Tests for the regex pattern matching Ghidra index entries."""

    def test_matches_simple_entry(self):
        """Should match a simple indented entry."""
        line = "  00000000:binary_name:abc123def456"
        match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
        assert match is not None
        assert match.group(1) == "00000000"
        assert match.group(2) == "binary_name"
        assert match.group(3) == "abc123def456"

    def test_matches_entry_with_spaces_indent(self):
        """Should match entry with various indentation."""
        line = "    00000001:another:fedcba987654"
        match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
        assert match is not None
        assert match.group(2) == "another"

    def test_matches_entry_with_path_in_name(self):
        """Should match entries with paths containing slashes."""
        line = "  00000002:path/to/binary.exe:abcdef123456"
        match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
        assert match is not None
        assert match.group(2) == "path/to/binary.exe"

    def test_matches_entry_with_dots_in_name(self):
        """Should match entries with dots in the name."""
        line = "  00000003:my.binary.v2.0:123456abcdef"
        match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
        assert match is not None
        assert match.group(2) == "my.binary.v2.0"

    def test_matches_uppercase_hex(self):
        """Should match uppercase hex characters."""
        line = "  ABCDEF01:binary:FEDCBA987654"
        match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
        assert match is not None
        assert match.group(1) == "ABCDEF01"

    def test_no_match_without_indent(self):
        """Should not match entries without leading whitespace."""
        line = "00000000:binary:abc123"
        match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
        assert match is None

    def test_no_match_version_line(self):
        """Should not match VERSION metadata line."""
        line = "VERSION=1"
        match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
        assert match is None

    def test_no_match_next_id_line(self):
        """Should not match NEXT-ID metadata line."""
        line = "NEXT-ID:5"
        match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
        assert match is None

    def test_no_match_md5_line(self):
        """Should not match MD5 metadata line."""
        line = "MD5:d41d8cd98f00b204e9800998ecf8427e"
        match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
        assert match is None

    def test_no_match_folder_line(self):
        """Should not match folder path lines."""
        line = "/"
        match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
        assert match is None

    def test_no_match_subfolder_line(self):
        """Should not match subfolder path lines."""
        line = "/subdir"
        match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
        assert match is None

    def test_no_match_short_id(self):
        """Should not match IDs shorter than 8 hex chars."""
        line = "  0000000:binary:abc123"  # 7 chars
        match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
        assert match is None

    def test_no_match_non_hex_hash(self):
        """Should not match entries with non-hex hash characters."""
        line = "  00000000:binary:ghijkl"  # g, h, i, j, k, l are not hex
        match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
        assert match is None


class TestParseGhidraIndex:
    """Tests for parse_ghidra_index function."""

    def test_parse_simple_index(self, tmp_path):
        """Should parse a simple index file with one binary."""
        index_content = """VERSION=1
/
  00000000:test_binary:abc123def456
NEXT-ID:1
MD5:d41d8cd98f00b204e9800998ecf8427e
"""
        index_file = tmp_path / "~index.dat"
        index_file.write_text(index_content)

        entries = parse_ghidra_index(index_file)

        assert len(entries) == 1
        assert entries[0]["id"] == "00000000"
        assert entries[0]["name"] == "test_binary"
        assert entries[0]["hash"] == "abc123def456"

    def test_parse_multiple_binaries(self, tmp_path):
        """Should parse index with multiple binaries."""
        index_content = """VERSION=1
/
  00000000:first_binary:aaaaaaaaaaaa
  00000001:second_binary:bbbbbbbbbbbb
  00000002:third_binary:cccccccccccc
NEXT-ID:3
MD5:d41d8cd98f00b204e9800998ecf8427e
"""
        index_file = tmp_path / "~index.dat"
        index_file.write_text(index_content)

        entries = parse_ghidra_index(index_file)

        assert len(entries) == 3
        assert entries[0]["name"] == "first_binary"
        assert entries[1]["name"] == "second_binary"
        assert entries[2]["name"] == "third_binary"

    def test_parse_with_subfolders(self, tmp_path):
        """Should parse index with binaries in subfolders."""
        index_content = """VERSION=1
/
  00000000:root_binary:aaaaaaaaaaaa
/subfolder
  00000001:nested_binary:bbbbbbbbbbbb
/deep/nested/path
  00000002:deep_binary:cccccccccccc
NEXT-ID:3
MD5:d41d8cd98f00b204e9800998ecf8427e
"""
        index_file = tmp_path / "~index.dat"
        index_file.write_text(index_content)

        entries = parse_ghidra_index(index_file)

        assert len(entries) == 3
        names = [e["name"] for e in entries]
        assert "root_binary" in names
        assert "nested_binary" in names
        assert "deep_binary" in names

    def test_parse_binary_with_path_in_name(self, tmp_path):
        """Should parse binaries that have paths in their names."""
        index_content = """VERSION=1
/
  00000000:path/to/binary.exe:aaaaaaaaaaaa
NEXT-ID:1
MD5:d41d8cd98f00b204e9800998ecf8427e
"""
        index_file = tmp_path / "~index.dat"
        index_file.write_text(index_content)

        entries = parse_ghidra_index(index_file)

        assert len(entries) == 1
        assert entries[0]["name"] == "path/to/binary.exe"

    def test_parse_nonexistent_file(self, tmp_path):
        """Should return empty list for nonexistent file."""
        index_file = tmp_path / "nonexistent.dat"

        entries = parse_ghidra_index(index_file)

        assert entries == []

    def test_parse_empty_file(self, tmp_path):
        """Should return empty list for empty file."""
        index_file = tmp_path / "~index.dat"
        index_file.write_text("")

        entries = parse_ghidra_index(index_file)

        assert entries == []

    def test_parse_metadata_only(self, tmp_path):
        """Should return empty list for file with only metadata."""
        index_content = """VERSION=1
/
NEXT-ID:0
MD5:d41d8cd98f00b204e9800998ecf8427e
"""
        index_file = tmp_path / "~index.dat"
        index_file.write_text(index_content)

        entries = parse_ghidra_index(index_file)

        assert entries == []

    def test_parse_preserves_order(self, tmp_path):
        """Should preserve the order of entries as they appear in file."""
        index_content = """VERSION=1
/
  00000000:zebra:aaaaaaaaaaaa
  00000001:alpha:bbbbbbbbbbbb
  00000002:middle:cccccccccccc
NEXT-ID:3
MD5:d41d8cd98f00b204e9800998ecf8427e
"""
        index_file = tmp_path / "~index.dat"
        index_file.write_text(index_content)

        entries = parse_ghidra_index(index_file)

        assert entries[0]["name"] == "zebra"
        assert entries[1]["name"] == "alpha"
        assert entries[2]["name"] == "middle"

    def test_parse_special_characters_in_name(self, tmp_path):
        """Should handle special characters in binary names."""
        index_content = """VERSION=1
/
  00000000:binary-with-dashes:aaaaaaaaaaaa
  00000001:binary_with_underscores:bbbbbbbbbbbb
  00000002:binary.with.dots.exe:cccccccccccc
NEXT-ID:3
MD5:d41d8cd98f00b204e9800998ecf8427e
"""
        index_file = tmp_path / "~index.dat"
        index_file.write_text(index_content)

        entries = parse_ghidra_index(index_file)

        assert len(entries) == 3
        names = [e["name"] for e in entries]
        assert "binary-with-dashes" in names
        assert "binary_with_underscores" in names
        assert "binary.with.dots.exe" in names


class TestGetAnalyzedBinaries:
    """Tests for get_analyzed_binaries function."""

    def _create_mock_project(self, tmp_path, project_name, binaries):
        """Helper to create a mock Ghidra project structure."""
        rep_dir = tmp_path / project_name / f"{project_name}.rep"
        idata_dir = rep_dir / "idata"
        idata_dir.mkdir(parents=True)

        # Create index file
        lines = ["VERSION=1", "/"]
        for i, name in enumerate(binaries):
            lines.append(f"  {i:08x}:{name}:{'a' * 24}")
            # Create folder for each binary
            (idata_dir / f"{i:02d}").mkdir()
        lines.append(f"NEXT-ID:{len(binaries)}")
        lines.append("MD5:d41d8cd98f00b204e9800998ecf8427e")

        (idata_dir / "~index.dat").write_text("\n".join(lines))

        return tmp_path / project_name

    def test_returns_binary_names_not_folder_ids(self, tmp_path, monkeypatch):
        """Should return actual binary names, not folder IDs like '00'."""
        # Patch the config module's config object directly
        import kawaiidra_mcp.server as server_module
        original_config = server_module.config

        self._create_mock_project(
            tmp_path, "test_project", ["my_binary", "another_one"]
        )

        # Create a mock config with our tmp directory
        class MockConfig:
            project_dir = tmp_path
            default_project = "default"
            def get_project_path(self, name=None):
                return self.project_dir / (name or self.default_project)

        monkeypatch.setattr(server_module, "config", MockConfig())

        try:
            binaries = get_analyzed_binaries("test_project")

            assert "my_binary" in binaries
            assert "another_one" in binaries
            assert "00" not in binaries
            assert "01" not in binaries
        finally:
            monkeypatch.setattr(server_module, "config", original_config)

    def test_fallback_to_folders_on_parse_failure(self, tmp_path, monkeypatch):
        """Should fall back to folder listing if index parsing fails."""
        import kawaiidra_mcp.server as server_module
        original_config = server_module.config

        # Create project structure without valid index
        project_name = "test_project"
        rep_dir = tmp_path / project_name / f"{project_name}.rep"
        idata_dir = rep_dir / "idata"
        idata_dir.mkdir(parents=True)

        # Create folders but no valid index file
        (idata_dir / "00").mkdir()
        (idata_dir / "01").mkdir()
        (idata_dir / "~index.dat").write_text("invalid content")

        class MockConfig:
            project_dir = tmp_path
            default_project = "default"
            def get_project_path(self, name=None):
                return self.project_dir / (name or self.default_project)

        monkeypatch.setattr(server_module, "config", MockConfig())

        try:
            binaries = get_analyzed_binaries("test_project")

            # Should fall back to folder names
            assert "00" in binaries
            assert "01" in binaries
        finally:
            monkeypatch.setattr(server_module, "config", original_config)


class TestBinaryExists:
    """Tests for binary_exists function."""

    def _create_mock_project(self, tmp_path, project_name, binaries):
        """Helper to create a mock Ghidra project structure."""
        rep_dir = tmp_path / project_name / f"{project_name}.rep"
        idata_dir = rep_dir / "idata"
        idata_dir.mkdir(parents=True)

        lines = ["VERSION=1", "/"]
        for i, name in enumerate(binaries):
            lines.append(f"  {i:08x}:{name}:{'a' * 24}")
        lines.append(f"NEXT-ID:{len(binaries)}")
        lines.append("MD5:d41d8cd98f00b204e9800998ecf8427e")

        (idata_dir / "~index.dat").write_text("\n".join(lines))

    def test_returns_true_for_existing_binary(self, tmp_path, monkeypatch):
        """Should return True for a binary that exists."""
        import kawaiidra_mcp.server as server_module
        original_config = server_module.config

        self._create_mock_project(tmp_path, "test_project", ["existing_binary"])

        class MockConfig:
            project_dir = tmp_path
            default_project = "default"
            def get_project_path(self, name=None):
                return self.project_dir / (name or self.default_project)

        monkeypatch.setattr(server_module, "config", MockConfig())

        try:
            assert binary_exists("existing_binary", "test_project") is True
        finally:
            monkeypatch.setattr(server_module, "config", original_config)

    def test_returns_false_for_nonexistent_binary(self, tmp_path, monkeypatch):
        """Should return False for a binary that doesn't exist."""
        import kawaiidra_mcp.server as server_module
        original_config = server_module.config

        self._create_mock_project(tmp_path, "test_project", ["some_binary"])

        class MockConfig:
            project_dir = tmp_path
            default_project = "default"
            def get_project_path(self, name=None):
                return self.project_dir / (name or self.default_project)

        monkeypatch.setattr(server_module, "config", MockConfig())

        try:
            assert binary_exists("nonexistent", "test_project") is False
        finally:
            monkeypatch.setattr(server_module, "config", original_config)

    def test_returns_false_for_nonexistent_project(self, tmp_path, monkeypatch):
        """Should return False for a nonexistent project."""
        import kawaiidra_mcp.server as server_module
        original_config = server_module.config

        class MockConfig:
            project_dir = tmp_path
            default_project = "default"
            def get_project_path(self, name=None):
                return self.project_dir / (name or self.default_project)

        monkeypatch.setattr(server_module, "config", MockConfig())

        try:
            assert binary_exists("any_binary", "nonexistent_project") is False
        finally:
            monkeypatch.setattr(server_module, "config", original_config)


class TestRealWorldIndexFormats:
    """Tests with real-world Ghidra index file formats."""

    def test_actual_ghidra_12_format(self, tmp_path):
        """Should parse actual Ghidra 12.x index format."""
        # Real format from Ghidra 12.0
        index_content = """VERSION=1
/
  00000000:cursed:7f001f1a2105563751282041
NEXT-ID:1
MD5:d41d8cd98f00b204e9800998ecf8427e
"""
        index_file = tmp_path / "~index.dat"
        index_file.write_text(index_content)

        entries = parse_ghidra_index(index_file)

        assert len(entries) == 1
        assert entries[0]["name"] == "cursed"
        assert entries[0]["hash"] == "7f001f1a2105563751282041"

    def test_windows_line_endings(self, tmp_path):
        """Should handle Windows-style line endings (CRLF)."""
        index_content = "VERSION=1\r\n/\r\n  00000000:binary:abc123\r\nNEXT-ID:1\r\nMD5:d41d8cd98f00b204e9800998ecf8427e\r\n"
        index_file = tmp_path / "~index.dat"
        index_file.write_bytes(index_content.encode("utf-8"))

        entries = parse_ghidra_index(index_file)

        assert len(entries) == 1
        assert entries[0]["name"] == "binary"

    def test_mixed_line_endings(self, tmp_path):
        """Should handle mixed line endings."""
        index_content = "VERSION=1\n/\r\n  00000000:binary:abc123\nNEXT-ID:1\r\n"
        index_file = tmp_path / "~index.dat"
        index_file.write_bytes(index_content.encode("utf-8"))

        entries = parse_ghidra_index(index_file)

        assert len(entries) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
