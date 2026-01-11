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

        # Cache settings
        self.cache_enabled = os.environ.get("KAWAIIDRA_CACHE_ENABLED", "true").lower() == "true"
        cache_dir_env = os.environ.get("KAWAIIDRA_CACHE_DIR")
        self.cache_dir = Path(cache_dir_env) if cache_dir_env else Path.home() / ".kawaiidra" / "cache"
        self.cache_max_size_mb = int(os.environ.get("KAWAIIDRA_CACHE_MAX_SIZE_MB", "500"))

        # JPype Bridge settings
        # Use bridge for ~100-1000x faster operations (requires JPype1 + Java JDK 17+)
        self.use_bridge = os.environ.get("KAWAIIDRA_USE_BRIDGE", "true").lower() == "true"
        # Keep programs loaded in memory for faster subsequent calls
        self.bridge_cache_programs = os.environ.get("KAWAIIDRA_BRIDGE_CACHE_PROGRAMS", "true").lower() == "true"
        # Max programs to keep in memory (LRU eviction)
        self.bridge_max_cached_programs = int(os.environ.get("KAWAIIDRA_BRIDGE_MAX_PROGRAMS", "5"))

        # GUI Mode settings
        # Enable GUI mode to connect to a running Ghidra instance via ghidra_bridge
        # Requires: pip install ghidra_bridge AND running ghidra_bridge_server in Ghidra
        self.gui_mode = os.environ.get("KAWAIIDRA_GUI_MODE", "false").lower() == "true"
        # Host and port for ghidra_bridge connection (default: localhost:4768)
        self.gui_bridge_host = os.environ.get("KAWAIIDRA_GUI_HOST", "127.0.0.1")
        self.gui_bridge_port = int(os.environ.get("KAWAIIDRA_GUI_PORT", "4768"))
        # Timeout for GUI bridge operations in seconds
        self.gui_bridge_timeout = int(os.environ.get("KAWAIIDRA_GUI_TIMEOUT", "10"))

    def _detect_ghidra_installation(self) -> Optional[Path]:
        """Auto-detect Ghidra installation in common locations.

        Searches for all known Ghidra versions (9.x through 12.x) and also
        uses glob patterns to find any version dynamically.
        """
        # All known Ghidra versions (newest first for priority)
        # Source: https://github.com/NationalSecurityAgency/ghidra/releases
        KNOWN_VERSIONS = [
            # 12.x
            "12.0",
            # 11.x
            "11.4.3", "11.4.2", "11.4.1", "11.4",
            "11.3.2", "11.3.1", "11.3",
            "11.2.1", "11.2",
            "11.1.2", "11.1.1", "11.1",
            "11.0.3", "11.0.2", "11.0.1", "11.0",
            # 10.x
            "10.4",
            "10.3.3", "10.3.2", "10.3.1", "10.3",
            "10.2.3", "10.2.2", "10.2.1", "10.2",
            "10.1.5", "10.1.4", "10.1.3", "10.1.2", "10.1.1", "10.1",
            "10.0.4", "10.0.3", "10.0.2", "10.0.1", "10.0",
            # 9.x
            "9.2.4", "9.2.3", "9.2.2", "9.2.1", "9.2",
            "9.1.2", "9.1.1", "9.1",
            "9.0.4", "9.0.2", "9.0.1", "9.0",
        ]

        common_locations = []

        if sys.platform == "darwin":  # macOS
            # Homebrew locations (highest priority)
            common_locations = [
                Path("/opt/homebrew"),  # Apple Silicon Homebrew
                Path("/usr/local"),  # Intel Homebrew
            ]

            # Check /Applications for versioned installs
            apps_dir = Path("/Applications")
            if apps_dir.exists():
                # Try glob pattern first to catch any version
                for ghidra_dir in sorted(apps_dir.glob("ghidra_*"), reverse=True):
                    common_locations.append(ghidra_dir)
                # Also try ghidra_*_PUBLIC pattern
                for ghidra_dir in sorted(apps_dir.glob("Ghidra_*"), reverse=True):
                    common_locations.append(ghidra_dir)

            # Add specific known versions as fallback
            for ver in KNOWN_VERSIONS:
                common_locations.append(Path(f"/Applications/ghidra_{ver}_PUBLIC"))
                common_locations.append(Path(f"/Applications/ghidra_{ver}"))
                common_locations.append(Path(f"/Applications/Ghidra_{ver}_PUBLIC"))
                common_locations.append(Path(f"/Applications/Ghidra_{ver}"))

            # Generic locations
            common_locations.extend([
                Path("/Applications/ghidra"),
                Path("/Applications/Ghidra"),
                Path.home() / "ghidra",
                Path("/opt/ghidra"),
            ])

        elif sys.platform == "linux":
            # Homebrew
            common_locations = [
                Path("/home/linuxbrew/.linuxbrew"),  # Linux Homebrew
            ]

            # Check /opt for versioned installs
            opt_dir = Path("/opt")
            if opt_dir.exists():
                for ghidra_dir in sorted(opt_dir.glob("ghidra_*"), reverse=True):
                    common_locations.append(ghidra_dir)
                for ghidra_dir in sorted(opt_dir.glob("ghidra-*"), reverse=True):
                    common_locations.append(ghidra_dir)

            # Check home directory
            home_dir = Path.home()
            for ghidra_dir in sorted(home_dir.glob("ghidra_*"), reverse=True):
                common_locations.append(ghidra_dir)
            for ghidra_dir in sorted(home_dir.glob("ghidra-*"), reverse=True):
                common_locations.append(ghidra_dir)

            # Add specific known versions
            for ver in KNOWN_VERSIONS:
                common_locations.append(Path(f"/opt/ghidra_{ver}_PUBLIC"))
                common_locations.append(Path(f"/opt/ghidra_{ver}"))
                common_locations.append(Path(f"/opt/ghidra-{ver}"))
                common_locations.append(home_dir / f"ghidra_{ver}_PUBLIC")
                common_locations.append(home_dir / f"ghidra_{ver}")

            # Generic locations
            common_locations.extend([
                Path("/opt/ghidra"),
                home_dir / "ghidra",
                Path("/usr/local/ghidra"),
                Path("/usr/share/ghidra"),
            ])

        elif sys.platform == "win32":
            # Check common Windows locations with glob
            for drive in ["C:", "D:", "E:"]:
                drive_path = Path(drive + "/")
                if drive_path.exists():
                    # Glob for any ghidra version
                    for ghidra_dir in sorted(drive_path.glob("ghidra_*"), reverse=True):
                        common_locations.append(ghidra_dir)
                    for ghidra_dir in sorted(drive_path.glob("Ghidra_*"), reverse=True):
                        common_locations.append(ghidra_dir)

            # Program Files locations
            program_files = [
                Path(os.environ.get("ProgramFiles", "C:/Program Files")),
                Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")),
            ]
            for pf in program_files:
                if pf.exists():
                    for ghidra_dir in sorted(pf.glob("ghidra_*"), reverse=True):
                        common_locations.append(ghidra_dir)
                    for ghidra_dir in sorted(pf.glob("Ghidra*"), reverse=True):
                        common_locations.append(ghidra_dir)

            # Add specific known versions
            for ver in KNOWN_VERSIONS:
                common_locations.append(Path(f"C:/ghidra_{ver}_PUBLIC"))
                common_locations.append(Path(f"C:/ghidra_{ver}"))
                common_locations.append(Path(f"C:/Ghidra_{ver}_PUBLIC"))

            # Generic locations
            common_locations.extend([
                Path("C:/ghidra"),
                Path("C:/Ghidra"),
                Path.home() / "ghidra",
                Path.home() / "Downloads" / "ghidra",
            ])

        # Remove duplicates while preserving order
        seen = set()
        unique_locations = []
        for loc in common_locations:
            if loc not in seen:
                seen.add(loc)
                unique_locations.append(loc)

        for location in unique_locations:
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
