"""Configuration management for Kawaiidra MCP Server."""

import os
import sys
from pathlib import Path
from typing import Optional


class Config:
    """Configuration for Kawaiidra MCP Server.

    Configuration is read from environment variables with sensible defaults.
    """

    def __init__(self):
        # Base paths
        self._package_root = Path(__file__).resolve().parent
        self._project_root = self._package_root.parent.parent

        # Ghidra installation path - try environment variable first, then auto-detect
        ghidra_env = os.environ.get("GHIDRA_INSTALL_DIR")

        if ghidra_env:
            self.ghidra_home = Path(ghidra_env)
        else:
            # Try to auto-detect common installation locations
            detected = self._detect_ghidra_installation()
            if detected:
                self.ghidra_home = detected
            else:
                raise ValueError(
                    "GHIDRA_INSTALL_DIR environment variable not set and Ghidra not found in common locations.\n"
                    "Please set it to your Ghidra installation directory.\n\n"
                    "Examples:\n"
                    "  Windows (manual):   C:\\ghidra_11.2_PUBLIC\n"
                    "  Linux (manual):     /opt/ghidra\n"
                    "  macOS (manual):     /Applications/ghidra_11.2_PUBLIC\n"
                    "  macOS (Homebrew):   /opt/homebrew\n"
                    "  Linux (Homebrew):   /home/linuxbrew/.linuxbrew\n"
                )

        # Store the detected analyzer type for later use
        self._analyzer_type: Optional[str] = None

        # Project directories
        self.project_dir = Path(os.environ.get(
            "KAWAIIDRA_PROJECT_DIR",
            str(self._project_root / "projects")
        ))
        self.binaries_dir = Path(os.environ.get(
            "KAWAIIDRA_BINARIES_DIR",
            str(self._project_root / "binaries")
        ))
        self.exports_dir = Path(os.environ.get(
            "KAWAIIDRA_EXPORTS_DIR",
            str(self._project_root / "exports")
        ))
        self.log_dir = Path(os.environ.get(
            "KAWAIIDRA_LOG_DIR",
            str(self._project_root / "logs")
        ))
        self.scripts_dir = self._package_root / "scripts"

        # Timeouts
        self.analysis_timeout = int(os.environ.get("KAWAIIDRA_TIMEOUT", "300"))
        self.decompile_timeout = int(os.environ.get("KAWAIIDRA_DECOMPILE_TIMEOUT", "180"))

        # Performance
        max_cpu = os.environ.get("KAWAIIDRA_MAX_CPU")
        self.max_cpu: Optional[int] = int(max_cpu) if max_cpu else None

        # Memory settings (for JVM)
        self.max_memory = os.environ.get("KAWAIIDRA_MAX_MEMORY", "4G")

        # Default project name
        self.default_project = os.environ.get("KAWAIIDRA_DEFAULT_PROJECT", "default")

    def _detect_ghidra_installation(self) -> Optional[Path]:
        """Auto-detect Ghidra installation in common locations."""
        common_locations = []

        if sys.platform == "darwin":  # macOS
            common_locations = [
                Path("/opt/homebrew"),  # Apple Silicon Homebrew
                Path("/usr/local"),  # Intel Homebrew
                Path("/Applications/ghidra_11.2_PUBLIC"),
                Path("/Applications/ghidra_11.1_PUBLIC"),
                Path("/Applications/ghidra_11.0_PUBLIC"),
                Path("/Applications/ghidra"),
            ]
        elif sys.platform == "linux":
            common_locations = [
                Path("/home/linuxbrew/.linuxbrew"),  # Linux Homebrew
                Path("/opt/ghidra"),
                Path.home() / "ghidra",
                Path("/usr/local/ghidra"),
            ]
        elif sys.platform == "win32":
            common_locations = [
                Path("C:/ghidra"),
                Path("C:/ghidra_11.2_PUBLIC"),
                Path("C:/ghidra_11.1_PUBLIC"),
                Path("C:/ghidra_11.0_PUBLIC"),
                Path.home() / "ghidra",
            ]

        for location in common_locations:
            if location.exists():
                # Verify it has Ghidra binaries
                if self._find_ghidra_binary(location):
                    return location

        return None

    def _find_ghidra_binary(self, base_path: Path) -> Optional[Path]:
        """Find the Ghidra analyzer binary in a given path.

        Supports:
        - Traditional installations: {base}/support/analyzeHeadless[.bat]
        - Homebrew (macOS/Linux): {base}/Cellar/ghidra/*/libexec/support/analyzeHeadless
        - Direct binary path: if base_path itself is the binary
        """
        # Check if base_path itself is a binary (e.g., /opt/homebrew/bin/ghidraRun)
        if base_path.is_file() and base_path.name in ("ghidraRun", "analyzeHeadless", "analyzeHeadless.bat"):
            return base_path

        # Check for Homebrew Cellar installation
        if (base_path / "Cellar" / "ghidra").exists():
            cellar_path = base_path / "Cellar" / "ghidra"
            # Find the version directory (there should be one)
            version_dirs = [d for d in cellar_path.iterdir() if d.is_dir()]
            if version_dirs:
                # Sort to get the latest version
                version_dirs.sort(reverse=True)
                for version_dir in version_dirs:
                    headless = version_dir / "libexec" / "support" / "analyzeHeadless"
                    if headless.exists():
                        return headless

        # Check for traditional installation structure
        traditional_bat = base_path / "support" / "analyzeHeadless.bat"
        traditional_sh = base_path / "support" / "analyzeHeadless"

        if traditional_bat.exists():
            return traditional_bat
        elif traditional_sh.exists():
            return traditional_sh

        return None

    @property
    def analyze_headless(self) -> Path:
        """Path to Ghidra headless analyzer script.

        Supports multiple installation methods:
        - Homebrew: {ghidra_home}/bin/ghidraRun
        - Traditional: {ghidra_home}/support/analyzeHeadless[.bat]
        """
        if self._analyzer_type is None:
            # Find the analyzer binary
            binary = self._find_ghidra_binary(self.ghidra_home)

            if binary:
                self._analyzer_type = "found"
                self._analyzer_path = binary
            else:
                # Provide detailed error message
                error_msg = (
                    f"Ghidra headless analyzer not found in: {self.ghidra_home}\n\n"
                    f"Searched for:\n"
                    f"  - Homebrew: {self.ghidra_home}/bin/ghidraRun\n"
                    f"  - Traditional: {self.ghidra_home}/support/analyzeHeadless[.bat]\n\n"
                    f"Please ensure GHIDRA_INSTALL_DIR points to a valid Ghidra installation."
                )
                raise FileNotFoundError(error_msg)

        return self._analyzer_path

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
