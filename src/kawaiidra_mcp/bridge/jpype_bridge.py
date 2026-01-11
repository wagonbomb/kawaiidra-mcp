"""
JPype-based Ghidra Bridge - Direct JVM access for maximum performance.

This module provides a persistent JVM connection to Ghidra, eliminating
the ~5-15 second startup overhead of analyzeHeadless per tool call.

Performance:
    - First call to a binary: ~2-5s (program load)
    - Subsequent calls: ~1-50ms (direct API access)
    - vs subprocess: 5-15s per call

Architecture:
    Python Process
        ↓
    JPype (in-process JVM)
        ↓
    Ghidra Libraries (loaded once)
        ↓
    Program Cache (loaded binaries stay in memory)
"""

import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any, Optional, Dict, List, Tuple
from dataclasses import dataclass, field
from functools import lru_cache
import time

logger = logging.getLogger("kawaiidra.bridge")


class BridgeError(Exception):
    """Base exception for bridge errors."""
    pass


class BridgeNotStartedError(BridgeError):
    """Raised when bridge is used before starting."""
    pass


class ProgramNotFoundError(BridgeError):
    """Raised when a program/binary is not found in the project."""
    pass


@dataclass
class ProgramHandle:
    """Handle to a loaded Ghidra program."""
    program: Any  # Java Program object
    project: Any  # Java GhidraProject object
    name: str
    path: str
    load_time: float
    access_count: int = 0
    last_access: float = field(default_factory=time.time)

    def touch(self):
        """Update access time and count."""
        self.access_count += 1
        self.last_access = time.time()


class GhidraBridge:
    """
    Direct JPype bridge to Ghidra APIs.

    This class manages:
    - JVM lifecycle (start/stop)
    - Ghidra classpath configuration
    - Program loading and caching
    - All Ghidra API operations

    Thread Safety:
    - JVM operations are thread-safe via JPype
    - Program cache uses threading.Lock for concurrent access
    """

    def __init__(self, ghidra_home: Path, max_memory: str = "4G"):
        """
        Initialize the bridge (does not start JVM yet).

        Args:
            ghidra_home: Path to Ghidra installation
            max_memory: JVM max heap size (e.g., "4G", "8G")
        """
        self.ghidra_home = Path(ghidra_home)
        self.max_memory = max_memory
        self._started = False
        self._lock = threading.Lock()

        # Program cache: project_name:binary_name -> ProgramHandle
        self._program_cache: Dict[str, ProgramHandle] = {}
        self._cache_lock = threading.Lock()

        # Java class references (populated after JVM start)
        self._java_classes: Dict[str, Any] = {}

        # Decompiler cache per program
        self._decompiler_cache: Dict[str, Any] = {}

    def _find_ghidra_classpath(self) -> List[Path]:
        """
        Find all Ghidra JAR files needed for the classpath.

        Returns a comprehensive list covering:
        - Framework JARs (Generic, SoftwareModeling, etc.)
        - Feature JARs (Base, Decompiler, etc.)
        - Processor JARs
        """
        jars = []

        # Key directories containing JARs
        jar_dirs = [
            # Framework
            self.ghidra_home / "Ghidra" / "Framework" / "Generic" / "lib",
            self.ghidra_home / "Ghidra" / "Framework" / "SoftwareModeling" / "lib",
            self.ghidra_home / "Ghidra" / "Framework" / "Project" / "lib",
            self.ghidra_home / "Ghidra" / "Framework" / "Docking" / "lib",
            self.ghidra_home / "Ghidra" / "Framework" / "Graph" / "lib",
            self.ghidra_home / "Ghidra" / "Framework" / "Utility" / "lib",
            self.ghidra_home / "Ghidra" / "Framework" / "DB" / "lib",
            self.ghidra_home / "Ghidra" / "Framework" / "FileSystem" / "lib",
            self.ghidra_home / "Ghidra" / "Framework" / "Help" / "lib",
            self.ghidra_home / "Ghidra" / "Framework" / "Gui" / "lib",
            self.ghidra_home / "Ghidra" / "Framework" / "Emulation" / "lib",

            # Features
            self.ghidra_home / "Ghidra" / "Features" / "Base" / "lib",
            self.ghidra_home / "Ghidra" / "Features" / "Decompiler" / "lib",
            self.ghidra_home / "Ghidra" / "Features" / "PDB" / "lib",
            self.ghidra_home / "Ghidra" / "Features" / "Python" / "lib",
            self.ghidra_home / "Ghidra" / "Features" / "MicrosoftCodeAnalyzer" / "lib",
            self.ghidra_home / "Ghidra" / "Features" / "GnuDemangler" / "lib",
            self.ghidra_home / "Ghidra" / "Features" / "FileFormats" / "lib",
            self.ghidra_home / "Ghidra" / "Features" / "FunctionID" / "lib",
            self.ghidra_home / "Ghidra" / "Features" / "VersionTracking" / "lib",
            self.ghidra_home / "Ghidra" / "Features" / "BytePatterns" / "lib",
            self.ghidra_home / "Ghidra" / "Features" / "BSim" / "lib",
            self.ghidra_home / "Ghidra" / "Features" / "MicrosoftDmang" / "lib",
            self.ghidra_home / "Ghidra" / "Features" / "SystemEmulation" / "lib",

            # Processors (architecture support)
            self.ghidra_home / "Ghidra" / "Processors" / "x86" / "lib",
            self.ghidra_home / "Ghidra" / "Processors" / "ARM" / "lib",
            self.ghidra_home / "Ghidra" / "Processors" / "AARCH64" / "lib",
            self.ghidra_home / "Ghidra" / "Processors" / "MIPS" / "lib",
            self.ghidra_home / "Ghidra" / "Processors" / "PowerPC" / "lib",
            self.ghidra_home / "Ghidra" / "Processors" / "Sparc" / "lib",

            # Support libraries
            self.ghidra_home / "support" / "lib",
        ]

        # Also check for Homebrew-style installation
        if (self.ghidra_home / "Cellar" / "ghidra").exists():
            cellar = self.ghidra_home / "Cellar" / "ghidra"
            versions = sorted([d for d in cellar.iterdir() if d.is_dir()], reverse=True)
            if versions:
                libexec = versions[0] / "libexec"
                jar_dirs = [libexec / d.relative_to(self.ghidra_home) for d in jar_dirs
                            if self.ghidra_home in d.parents or d == self.ghidra_home]
                # Add the standard libexec paths
                jar_dirs.extend([
                    libexec / "Ghidra" / "Framework" / "Generic" / "lib",
                    libexec / "Ghidra" / "Framework" / "SoftwareModeling" / "lib",
                    libexec / "Ghidra" / "Framework" / "Project" / "lib",
                    libexec / "Ghidra" / "Features" / "Base" / "lib",
                    libexec / "Ghidra" / "Features" / "Decompiler" / "lib",
                ])

        for jar_dir in jar_dirs:
            if jar_dir.exists():
                jars.extend(jar_dir.glob("*.jar"))

        # Remove duplicates while preserving order
        seen = set()
        unique_jars = []
        for jar in jars:
            if jar not in seen:
                seen.add(jar)
                unique_jars.append(jar)

        return unique_jars

    def _get_ghidra_app_properties(self) -> Path:
        """Find the Ghidra application.properties file."""
        candidates = [
            self.ghidra_home / "Ghidra" / "application.properties",
            self.ghidra_home / "application.properties",
        ]

        # Homebrew
        if (self.ghidra_home / "Cellar" / "ghidra").exists():
            cellar = self.ghidra_home / "Cellar" / "ghidra"
            versions = sorted([d for d in cellar.iterdir() if d.is_dir()], reverse=True)
            if versions:
                candidates.insert(0, versions[0] / "libexec" / "Ghidra" / "application.properties")

        for candidate in candidates:
            if candidate.exists():
                return candidate

        raise BridgeError(f"Cannot find Ghidra application.properties in {self.ghidra_home}")

    def start(self) -> None:
        """
        Start the JVM with Ghidra libraries loaded.

        This is idempotent - calling multiple times is safe.
        """
        with self._lock:
            if self._started:
                return

            try:
                import jpype
                import jpype.imports
            except ImportError:
                raise BridgeError(
                    "JPype not installed. Run: pip install JPype1\n"
                    "Note: Requires Java JDK 17+ installed."
                )

            if jpype.isJVMStarted():
                logger.info("JVM already running, attaching to existing instance")
                self._started = True
                self._load_java_classes()
                return

            # Build classpath
            jars = self._find_ghidra_classpath()
            if not jars:
                raise BridgeError(
                    f"No Ghidra JARs found in {self.ghidra_home}. "
                    "Ensure GHIDRA_INSTALL_DIR points to valid installation."
                )

            classpath = os.pathsep.join(str(j) for j in jars)

            # Find Ghidra application root for system property
            app_props = self._get_ghidra_app_properties()
            ghidra_root = app_props.parent.parent  # Go up from Ghidra/application.properties

            logger.info(f"Starting JVM with {len(jars)} JARs, max memory: {self.max_memory}")
            logger.debug(f"Ghidra root: {ghidra_root}")

            try:
                jpype.startJVM(
                    f"-Xmx{self.max_memory}",
                    f"-Dghidra.root={ghidra_root}",
                    "-Djava.awt.headless=true",
                    "-Dlog4j.configurationFile=log4j2.xml",
                    classpath=classpath,
                    convertStrings=True,
                )
            except Exception as e:
                raise BridgeError(f"Failed to start JVM: {e}")

            self._started = True
            self._load_java_classes()
            self._initialize_ghidra()
            logger.info("JVM started successfully")

    def _load_java_classes(self) -> None:
        """Load commonly used Java classes after JVM start."""
        import jpype.imports

        # Core Ghidra classes
        from ghidra.app.util.headless import HeadlessGhidraApplicationConfiguration
        from ghidra.base.project import GhidraProject
        from ghidra.program.model.listing import Program, Function, FunctionManager
        from ghidra.program.model.symbol import SymbolTable, ReferenceManager
        from ghidra.program.model.mem import MemoryAccessException
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra.framework import Application, ApplicationConfiguration

        # Import/export
        from ghidra.app.util.importer import AutoImporter, MessageLog
        from ghidra.app.util.opinion import Loader

        # Address handling
        from ghidra.program.model.address import AddressFactory, Address

        # Store references
        self._java_classes = {
            "HeadlessGhidraApplicationConfiguration": HeadlessGhidraApplicationConfiguration,
            "GhidraProject": GhidraProject,
            "Program": Program,
            "Function": Function,
            "FunctionManager": FunctionManager,
            "SymbolTable": SymbolTable,
            "ReferenceManager": ReferenceManager,
            "DecompInterface": DecompInterface,
            "DecompileOptions": DecompileOptions,
            "ConsoleTaskMonitor": ConsoleTaskMonitor,
            "AutoImporter": AutoImporter,
            "MessageLog": MessageLog,
            "Application": Application,
            "ApplicationConfiguration": ApplicationConfiguration,
        }

    def _initialize_ghidra(self) -> None:
        """Initialize Ghidra application (required before using APIs)."""
        Application = self._java_classes["Application"]
        HeadlessConfig = self._java_classes["HeadlessGhidraApplicationConfiguration"]

        if not Application.isInitialized():
            logger.info("Initializing Ghidra application...")
            config = HeadlessConfig()
            Application.initializeApplication(config)
            logger.info("Ghidra application initialized")

    def ensure_started(self) -> None:
        """Ensure the bridge is started, starting it if needed."""
        if not self._started:
            self.start()

    def stop(self) -> None:
        """
        Stop the JVM (if running).

        Note: In JPype, the JVM cannot be restarted after shutdown.
        """
        with self._lock:
            if not self._started:
                return

            # Close all cached programs
            self._close_all_programs()

            # Clear decompiler cache
            for decomp in self._decompiler_cache.values():
                try:
                    decomp.dispose()
                except Exception:
                    pass
            self._decompiler_cache.clear()

            import jpype
            if jpype.isJVMStarted():
                jpype.shutdownJVM()

            self._started = False
            logger.info("JVM stopped")

    @property
    def is_started(self) -> bool:
        """Check if the bridge is started."""
        return self._started

    # =========================================================================
    # Program Management
    # =========================================================================

    def _get_cache_key(self, project_name: str, binary_name: str) -> str:
        """Generate cache key for a program."""
        return f"{project_name}:{binary_name}"

    def open_program(
        self,
        binary_path: str,
        project_name: str = "default",
        project_dir: Optional[Path] = None,
        analyze: bool = True
    ) -> ProgramHandle:
        """
        Open/import a binary into Ghidra and return a program handle.

        Args:
            binary_path: Path to the binary file
            project_name: Ghidra project name
            project_dir: Directory for Ghidra project files
            analyze: Whether to run auto-analysis on import

        Returns:
            ProgramHandle for the loaded program
        """
        self.ensure_started()

        binary_path = Path(binary_path)
        binary_name = binary_path.name
        cache_key = self._get_cache_key(project_name, binary_name)

        # Check cache first
        with self._cache_lock:
            if cache_key in self._program_cache:
                handle = self._program_cache[cache_key]
                handle.touch()
                logger.debug(f"Cache hit for {cache_key} (accesses: {handle.access_count})")
                return handle

        # Need to load - this is the slow path
        logger.info(f"Loading program: {binary_path} into project {project_name}")
        start_time = time.time()

        import jpype
        from java.io import File as JFile
        from java.lang import Boolean

        GhidraProject = self._java_classes["GhidraProject"]
        ConsoleTaskMonitor = self._java_classes["ConsoleTaskMonitor"]
        AutoImporter = self._java_classes["AutoImporter"]
        MessageLog = self._java_classes["MessageLog"]

        # Set up project directory
        if project_dir is None:
            from ..config import config
            project_dir = config.project_dir

        project_dir = Path(project_dir)
        project_dir.mkdir(parents=True, exist_ok=True)

        monitor = ConsoleTaskMonitor()

        try:
            # Open or create project
            project_path = project_dir / project_name
            gpr_file = project_path / f"{project_name}.gpr"

            if gpr_file.exists():
                project = GhidraProject.openProject(
                    JFile(str(project_dir)),
                    project_name,
                    True  # readOnly=false
                )
            else:
                project = GhidraProject.createProject(
                    JFile(str(project_dir)),
                    project_name,
                    False  # not temporary
                )

            # Check if already imported
            program = None
            try:
                program = project.openProgram("/", binary_name, False)
            except Exception:
                pass

            if program is None:
                # Import the binary
                logger.info(f"Importing {binary_name}...")
                program = project.importProgram(
                    JFile(str(binary_path)),
                    monitor
                )

                if program is None:
                    raise BridgeError(f"Failed to import {binary_path}")

                if analyze:
                    logger.info(f"Analyzing {binary_name}...")
                    from ghidra.app.util.headless import AnalyzeHeadless
                    # Use Ghidra's auto-analysis
                    from ghidra.program.util import GhidraProgramUtilities
                    GhidraProgramUtilities.setAnalyzedFlag(program, True)

                    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
                    auto_mgr = AutoAnalysisManager.getAnalysisManager(program)
                    tid = program.startTransaction("Auto Analysis")
                    try:
                        auto_mgr.initializeOptions()
                        auto_mgr.reAnalyzeAll(None)
                        auto_mgr.startAnalysis(monitor)
                    finally:
                        program.endTransaction(tid, True)

                # Save the program
                project.saveAs(program, "/", binary_name, True)

            load_time = time.time() - start_time
            logger.info(f"Program loaded in {load_time:.2f}s")

            handle = ProgramHandle(
                program=program,
                project=project,
                name=binary_name,
                path=str(binary_path),
                load_time=load_time
            )

            with self._cache_lock:
                self._program_cache[cache_key] = handle

            return handle

        except Exception as e:
            logger.error(f"Failed to open program: {e}")
            raise BridgeError(f"Failed to open program {binary_path}: {e}")

    def get_program(self, project_name: str, binary_name: str) -> ProgramHandle:
        """
        Get an already-loaded program from cache.

        Args:
            project_name: Ghidra project name
            binary_name: Name of the binary

        Returns:
            ProgramHandle for the program

        Raises:
            ProgramNotFoundError if program is not loaded
        """
        self.ensure_started()

        cache_key = self._get_cache_key(project_name, binary_name)

        with self._cache_lock:
            if cache_key not in self._program_cache:
                raise ProgramNotFoundError(
                    f"Program {binary_name} not found in project {project_name}. "
                    "Use open_program() to load it first."
                )
            handle = self._program_cache[cache_key]
            handle.touch()
            return handle

    def close_program(self, project_name: str, binary_name: str) -> None:
        """Close a program and remove from cache."""
        cache_key = self._get_cache_key(project_name, binary_name)

        with self._cache_lock:
            if cache_key in self._program_cache:
                handle = self._program_cache.pop(cache_key)
                try:
                    handle.project.close()
                except Exception as e:
                    logger.warning(f"Error closing program: {e}")

        # Clear associated decompiler
        if cache_key in self._decompiler_cache:
            try:
                self._decompiler_cache.pop(cache_key).dispose()
            except Exception:
                pass

    def _close_all_programs(self) -> None:
        """Close all cached programs."""
        with self._cache_lock:
            for key, handle in list(self._program_cache.items()):
                try:
                    handle.project.close()
                except Exception as e:
                    logger.warning(f"Error closing {key}: {e}")
            self._program_cache.clear()

    # =========================================================================
    # Decompiler
    # =========================================================================

    def _get_decompiler(self, handle: ProgramHandle) -> Any:
        """Get or create a decompiler for a program."""
        cache_key = self._get_cache_key(handle.project.getName() if hasattr(handle.project, 'getName') else "default", handle.name)

        if cache_key not in self._decompiler_cache:
            DecompInterface = self._java_classes["DecompInterface"]
            DecompileOptions = self._java_classes["DecompileOptions"]

            decomp = DecompInterface()
            options = DecompileOptions()
            decomp.setOptions(options)
            decomp.openProgram(handle.program)

            self._decompiler_cache[cache_key] = decomp

        return self._decompiler_cache[cache_key]

    # =========================================================================
    # High-Level Operations (called by MCP tools)
    # =========================================================================

    def list_functions(
        self,
        handle: ProgramHandle,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        List functions in a program.

        Args:
            handle: Program handle
            limit: Maximum functions to return
            offset: Number of functions to skip

        Returns:
            List of function info dictionaries
        """
        program = handle.program
        fm = program.getFunctionManager()
        functions = []

        iterator = fm.getFunctions(True)  # Forward iterator
        count = 0
        skipped = 0

        while iterator.hasNext() and len(functions) < limit:
            func = iterator.next()

            if skipped < offset:
                skipped += 1
                continue

            functions.append({
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "signature": str(func.getSignature()),
                "size": func.getBody().getNumAddresses(),
                "is_thunk": func.isThunk(),
                "is_external": func.isExternal(),
                "calling_convention": str(func.getCallingConventionName()) if func.getCallingConventionName() else None,
            })
            count += 1

        return functions

    def find_functions(
        self,
        handle: ProgramHandle,
        pattern: str
    ) -> List[Dict[str, Any]]:
        """
        Find functions by name pattern.

        Args:
            handle: Program handle
            pattern: Pattern to search (case-insensitive substring)

        Returns:
            List of matching function info dictionaries
        """
        program = handle.program
        fm = program.getFunctionManager()
        pattern_lower = pattern.lower()
        functions = []

        iterator = fm.getFunctions(True)
        while iterator.hasNext():
            func = iterator.next()
            name = func.getName()

            if pattern_lower in name.lower():
                functions.append({
                    "name": name,
                    "address": str(func.getEntryPoint()),
                    "signature": str(func.getSignature()),
                    "size": func.getBody().getNumAddresses(),
                })

        return functions

    def get_function_by_name(self, handle: ProgramHandle, name: str) -> Optional[Any]:
        """Get a function by name."""
        program = handle.program
        fm = program.getFunctionManager()

        # Try exact match first
        funcs = list(program.getSymbolTable().getSymbols(name))
        for sym in funcs:
            func = fm.getFunctionAt(sym.getAddress())
            if func is not None:
                return func

        # Try by address if it looks like hex
        if name.startswith("0x") or name.startswith("0X"):
            try:
                addr = program.getAddressFactory().getAddress(name)
                return fm.getFunctionAt(addr)
            except Exception:
                pass

        return None

    def get_function_by_address(self, handle: ProgramHandle, address: str) -> Optional[Any]:
        """Get a function at a specific address."""
        program = handle.program
        fm = program.getFunctionManager()

        try:
            addr = program.getAddressFactory().getAddress(address)
            return fm.getFunctionAt(addr)
        except Exception:
            return None

    def decompile(
        self,
        handle: ProgramHandle,
        function_name: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Decompile a function.

        Args:
            handle: Program handle
            function_name: Function name or address
            timeout: Decompilation timeout in seconds

        Returns:
            Dict with decompiled code and metadata
        """
        func = self.get_function_by_name(handle, function_name)
        if func is None:
            func = self.get_function_by_address(handle, function_name)

        if func is None:
            return {
                "success": False,
                "error": f"Function '{function_name}' not found"
            }

        decomp = self._get_decompiler(handle)
        ConsoleTaskMonitor = self._java_classes["ConsoleTaskMonitor"]
        monitor = ConsoleTaskMonitor()

        result = decomp.decompileFunction(func, timeout, monitor)

        if result is None or result.decompileCompleted() == False:
            error_msg = result.getErrorMessage() if result else "Unknown error"
            return {
                "success": False,
                "error": f"Decompilation failed: {error_msg}"
            }

        decompiled = result.getDecompiledFunction()
        if decompiled is None:
            return {
                "success": False,
                "error": "No decompiled output"
            }

        return {
            "success": True,
            "function_name": func.getName(),
            "address": str(func.getEntryPoint()),
            "signature": str(func.getSignature()),
            "code": decompiled.getC(),
        }

    def get_disassembly(
        self,
        handle: ProgramHandle,
        function_name: str
    ) -> Dict[str, Any]:
        """
        Get disassembly for a function.

        Args:
            handle: Program handle
            function_name: Function name or address

        Returns:
            Dict with disassembly and metadata
        """
        func = self.get_function_by_name(handle, function_name)
        if func is None:
            func = self.get_function_by_address(handle, function_name)

        if func is None:
            return {
                "success": False,
                "error": f"Function '{function_name}' not found"
            }

        program = handle.program
        listing = program.getListing()
        body = func.getBody()

        instructions = []
        code_units = listing.getCodeUnits(body, True)

        while code_units.hasNext():
            cu = code_units.next()
            addr = cu.getAddress()

            instructions.append({
                "address": str(addr),
                "mnemonic": cu.getMnemonicString(),
                "operands": str(cu),
                "bytes": " ".join(f"{b & 0xff:02x}" for b in cu.getBytes()),
            })

        return {
            "success": True,
            "function_name": func.getName(),
            "address": str(func.getEntryPoint()),
            "instruction_count": len(instructions),
            "instructions": instructions,
        }

    def get_xrefs(
        self,
        handle: ProgramHandle,
        function_name: str,
        direction: str = "both"
    ) -> Dict[str, Any]:
        """
        Get cross-references to/from a function.

        Args:
            handle: Program handle
            function_name: Function name or address
            direction: "to", "from", or "both"

        Returns:
            Dict with xref information
        """
        func = self.get_function_by_name(handle, function_name)
        if func is None:
            func = self.get_function_by_address(handle, function_name)

        if func is None:
            return {
                "success": False,
                "error": f"Function '{function_name}' not found"
            }

        program = handle.program
        ref_mgr = program.getReferenceManager()
        fm = program.getFunctionManager()
        entry = func.getEntryPoint()
        body = func.getBody()

        refs_to = []
        refs_from = []

        if direction in ("to", "both"):
            # References TO this function
            iter_to = ref_mgr.getReferencesTo(entry)
            while iter_to.hasNext():
                ref = iter_to.next()
                from_addr = ref.getFromAddress()
                from_func = fm.getFunctionContaining(from_addr)
                refs_to.append({
                    "from_address": str(from_addr),
                    "from_function": from_func.getName() if from_func else None,
                    "ref_type": str(ref.getReferenceType()),
                })

        if direction in ("from", "both"):
            # References FROM this function
            for addr in body.getAddresses(True):
                iter_from = ref_mgr.getReferencesFrom(addr)
                while iter_from.hasNext():
                    ref = iter_from.next()
                    to_addr = ref.getToAddress()
                    to_func = fm.getFunctionContaining(to_addr)
                    refs_from.append({
                        "from_address": str(addr),
                        "to_address": str(to_addr),
                        "to_function": to_func.getName() if to_func else None,
                        "ref_type": str(ref.getReferenceType()),
                    })

        return {
            "success": True,
            "function_name": func.getName(),
            "address": str(entry),
            "references_to": refs_to,
            "references_from": refs_from,
        }

    def list_strings(
        self,
        handle: ProgramHandle,
        min_length: int = 4,
        limit: int = 200
    ) -> List[Dict[str, str]]:
        """
        List defined strings in the program.

        Args:
            handle: Program handle
            min_length: Minimum string length
            limit: Maximum strings to return

        Returns:
            List of string info dictionaries
        """
        program = handle.program
        listing = program.getListing()
        strings = []

        data_iter = listing.getDefinedData(True)
        while data_iter.hasNext() and len(strings) < limit:
            data = data_iter.next()
            dt = data.getDataType()

            if dt is None:
                continue

            type_name = dt.getName().lower()
            if "string" not in type_name:
                continue

            try:
                value = data.getValue()
                if value is not None:
                    str_value = str(value)
                    if len(str_value) >= min_length:
                        strings.append({
                            "address": str(data.getAddress()),
                            "value": str_value,
                            "type": dt.getName(),
                            "length": len(str_value),
                        })
            except Exception:
                continue

        return strings

    def search_strings(
        self,
        handle: ProgramHandle,
        pattern: str
    ) -> List[Dict[str, str]]:
        """
        Search for strings matching a pattern.

        Args:
            handle: Program handle
            pattern: Pattern to search (case-insensitive substring)

        Returns:
            List of matching string info
        """
        all_strings = self.list_strings(handle, min_length=1, limit=10000)
        pattern_lower = pattern.lower()

        return [
            s for s in all_strings
            if pattern_lower in s["value"].lower()
        ]

    def get_binary_info(self, handle: ProgramHandle) -> Dict[str, Any]:
        """Get metadata about the binary."""
        program = handle.program

        return {
            "success": True,
            "name": program.getName(),
            "path": str(program.getExecutablePath()),
            "format": str(program.getExecutableFormat()),
            "language": str(program.getLanguage().getLanguageID()),
            "compiler": str(program.getCompiler()) if program.getCompiler() else None,
            "address_size": program.getDefaultPointerSize(),
            "min_address": str(program.getMinAddress()),
            "max_address": str(program.getMaxAddress()),
            "function_count": program.getFunctionManager().getFunctionCount(),
            "symbol_count": program.getSymbolTable().getNumSymbols(),
        }

    def get_memory_map(self, handle: ProgramHandle) -> List[Dict[str, Any]]:
        """Get memory segments of the program."""
        program = handle.program
        memory = program.getMemory()
        segments = []

        for block in memory.getBlocks():
            segments.append({
                "name": block.getName(),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": block.getSize(),
                "readable": block.isRead(),
                "writable": block.isWrite(),
                "executable": block.isExecute(),
                "initialized": block.isInitialized(),
                "type": str(block.getType()),
            })

        return segments

    def list_imports(self, handle: ProgramHandle, limit: int = 100) -> List[Dict[str, Any]]:
        """List imported symbols."""
        program = handle.program
        st = program.getSymbolTable()
        imports = []

        ext_iter = st.getExternalSymbols()
        count = 0
        while ext_iter.hasNext() and count < limit:
            sym = ext_iter.next()
            imports.append({
                "name": sym.getName(),
                "address": str(sym.getAddress()),
                "namespace": str(sym.getParentNamespace().getName()),
            })
            count += 1

        return imports

    def list_exports(self, handle: ProgramHandle, limit: int = 100) -> List[Dict[str, Any]]:
        """List exported symbols."""
        program = handle.program
        st = program.getSymbolTable()
        exports = []

        sym_iter = st.getAllSymbols(True)
        count = 0
        while sym_iter.hasNext() and count < limit:
            sym = sym_iter.next()
            if sym.isExternalEntryPoint():
                exports.append({
                    "name": sym.getName(),
                    "address": str(sym.getAddress()),
                    "type": str(sym.getSymbolType()),
                })
                count += 1

        return exports

    # =========================================================================
    # Modification Operations
    # =========================================================================

    def rename_function(
        self,
        handle: ProgramHandle,
        old_name: str,
        new_name: str
    ) -> Dict[str, Any]:
        """Rename a function."""
        func = self.get_function_by_name(handle, old_name)
        if func is None:
            func = self.get_function_by_address(handle, old_name)

        if func is None:
            return {"success": False, "error": f"Function '{old_name}' not found"}

        program = handle.program
        from ghidra.program.model.symbol import SourceType

        tid = program.startTransaction("Rename function")
        try:
            func.setName(new_name, SourceType.USER_DEFINED)
            program.endTransaction(tid, True)
            return {
                "success": True,
                "old_name": old_name,
                "new_name": new_name,
                "address": str(func.getEntryPoint()),
            }
        except Exception as e:
            program.endTransaction(tid, False)
            return {"success": False, "error": str(e)}

    def set_comment(
        self,
        handle: ProgramHandle,
        address: str,
        comment: str,
        comment_type: str = "EOL"
    ) -> Dict[str, Any]:
        """Set a comment at an address."""
        program = handle.program

        try:
            addr = program.getAddressFactory().getAddress(address)
        except Exception as e:
            return {"success": False, "error": f"Invalid address: {e}"}

        from ghidra.program.model.listing import CodeUnit

        type_map = {
            "EOL": CodeUnit.EOL_COMMENT,
            "PRE": CodeUnit.PRE_COMMENT,
            "POST": CodeUnit.POST_COMMENT,
            "PLATE": CodeUnit.PLATE_COMMENT,
        }

        if comment_type not in type_map:
            return {"success": False, "error": f"Invalid comment type: {comment_type}"}

        listing = program.getListing()
        cu = listing.getCodeUnitAt(addr)

        if cu is None:
            return {"success": False, "error": f"No code unit at {address}"}

        tid = program.startTransaction("Set comment")
        try:
            cu.setComment(type_map[comment_type], comment)
            program.endTransaction(tid, True)
            return {
                "success": True,
                "address": address,
                "comment": comment,
                "type": comment_type,
            }
        except Exception as e:
            program.endTransaction(tid, False)
            return {"success": False, "error": str(e)}


# =============================================================================
# Global Bridge Instance
# =============================================================================

_bridge: Optional[GhidraBridge] = None
_bridge_lock = threading.Lock()


def get_bridge() -> GhidraBridge:
    """
    Get the global bridge instance, creating it if necessary.

    Configuration is read from environment/config module.
    """
    global _bridge

    with _bridge_lock:
        if _bridge is None:
            from ..config import config
            _bridge = GhidraBridge(
                ghidra_home=config.ghidra_home,
                max_memory=config.max_memory,
            )

        return _bridge


def close_bridge() -> None:
    """Close the global bridge instance."""
    global _bridge

    with _bridge_lock:
        if _bridge is not None:
            _bridge.stop()
            _bridge = None
