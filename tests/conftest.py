"""
Pytest configuration and shared fixtures for Kawaiidra MCP tests.
"""

import pytest
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture
def mock_project_dir(tmp_path):
    """Create a temporary project directory structure."""
    project_dir = tmp_path / "projects"
    project_dir.mkdir()
    return project_dir


@pytest.fixture
def mock_ghidra_project(tmp_path):
    """Create a mock Ghidra project with sample binaries."""
    def _create_project(project_name: str, binaries: list[str]):
        project_dir = tmp_path / project_name
        rep_dir = project_dir / f"{project_name}.rep"
        idata_dir = rep_dir / "idata"
        idata_dir.mkdir(parents=True)

        # Create index file
        lines = ["VERSION=1", "/"]
        for i, name in enumerate(binaries):
            hex_id = f"{i:08x}"
            hex_hash = f"{i:024x}"
            lines.append(f"  {hex_id}:{name}:{hex_hash}")
            # Create folder for the binary
            (idata_dir / f"{i:02d}").mkdir()

        lines.append(f"NEXT-ID:{len(binaries)}")
        lines.append("MD5:d41d8cd98f00b204e9800998ecf8427e")

        (idata_dir / "~index.dat").write_text("\n".join(lines))

        return project_dir

    return _create_project


@pytest.fixture
def sample_index_content():
    """Sample Ghidra index file content."""
    return """VERSION=1
/
  00000000:test_binary:abc123def456789012345678
  00000001:another_binary:fedcba987654321098765432
NEXT-ID:2
MD5:d41d8cd98f00b204e9800998ecf8427e
"""


@pytest.fixture
def mock_config(tmp_path, monkeypatch):
    """Mock the config module with temporary directories."""
    from kawaiidra_mcp import config as cfg

    project_dir = tmp_path / "projects"
    project_dir.mkdir()

    binaries_dir = tmp_path / "binaries"
    binaries_dir.mkdir()

    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()

    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    monkeypatch.setattr(cfg.config, "project_dir", project_dir)
    monkeypatch.setattr(cfg.config, "binaries_dir", binaries_dir)
    monkeypatch.setattr(cfg.config, "scripts_dir", scripts_dir)
    monkeypatch.setattr(cfg.config, "log_dir", log_dir)

    return {
        "project_dir": project_dir,
        "binaries_dir": binaries_dir,
        "scripts_dir": scripts_dir,
        "log_dir": log_dir,
    }
