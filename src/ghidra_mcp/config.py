"""Configuration management for Ghidra MCP Server."""

import os
from pathlib import Path
from typing import Optional


class Config:
    """Configuration for Ghidra MCP Server.

    Configuration is read from environment variables with sensible defaults.
    """

    def __init__(self):
        # Base paths
        self._package_root = Path(__file__).resolve().parent
        self._project_root = self._package_root.parent.parent

        # Ghidra installation path
        ghidra_env = os.environ.get("GHIDRA_INSTALL_DIR")
        if not ghidra_env:
            raise ValueError(
                "GHIDRA_INSTALL_DIR environment variable not set. "
                "Please set it to your Ghidra installation directory.\n"
                "Examples:\n"
                "  Windows: C:\\ghidra_11.2_PUBLIC\n"
                "  Linux:   /opt/ghidra\n"
                "  macOS:   /Applications/ghidra"
            )
        self.ghidra_home = Path(ghidra_env)

        # Project directories
        self.project_dir = Path(os.environ.get(
            "GHIDRA_MCP_PROJECT_DIR",
            str(self._project_root / "projects")
        ))
        self.binaries_dir = Path(os.environ.get(
            "GHIDRA_MCP_BINARIES_DIR",
            str(self._project_root / "binaries")
        ))
        self.exports_dir = Path(os.environ.get(
            "GHIDRA_MCP_EXPORTS_DIR",
            str(self._project_root / "exports")
        ))
        self.log_dir = Path(os.environ.get(
            "GHIDRA_MCP_LOG_DIR",
            str(self._project_root / "logs")
        ))
        self.scripts_dir = self._package_root / "scripts"

        # Timeouts
        self.analysis_timeout = int(os.environ.get("GHIDRA_MCP_TIMEOUT", "300"))
        self.decompile_timeout = int(os.environ.get("GHIDRA_MCP_DECOMPILE_TIMEOUT", "180"))

        # Performance
        max_cpu = os.environ.get("GHIDRA_MCP_MAX_CPU")
        self.max_cpu: Optional[int] = int(max_cpu) if max_cpu else None

        # Memory settings (for JVM)
        self.max_memory = os.environ.get("GHIDRA_MCP_MAX_MEMORY", "4G")

        # Default project name
        self.default_project = os.environ.get("GHIDRA_MCP_DEFAULT_PROJECT", "default")

    @property
    def analyze_headless(self) -> Path:
        """Path to analyzeHeadless script."""
        bat = self.ghidra_home / "support" / "analyzeHeadless.bat"
        sh = self.ghidra_home / "support" / "analyzeHeadless"

        if bat.exists():
            return bat
        elif sh.exists():
            return sh
        else:
            raise FileNotFoundError(
                f"analyzeHeadless not found in {self.ghidra_home / 'support'}"
            )

    def validate(self) -> list[str]:
        """Validate configuration. Returns list of error messages."""
        errors = []

        if not self.ghidra_home.exists():
            errors.append(f"Ghidra installation not found at: {self.ghidra_home}")
        else:
            try:
                _ = self.analyze_headless
            except FileNotFoundError as e:
                errors.append(str(e))

        return errors

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        for directory in [self.project_dir, self.binaries_dir,
                          self.exports_dir, self.log_dir]:
            directory.mkdir(parents=True, exist_ok=True)

    def get_project_path(self, project_name: Optional[str] = None) -> Path:
        """Get path to a Ghidra project directory."""
        name = project_name or self.default_project
        return self.project_dir / name

    def __repr__(self) -> str:
        return (
            f"Config(\n"
            f"  ghidra_home={self.ghidra_home},\n"
            f"  project_dir={self.project_dir},\n"
            f"  binaries_dir={self.binaries_dir},\n"
            f"  analysis_timeout={self.analysis_timeout}s\n"
            f")"
        )


# Global config instance
config = Config()
