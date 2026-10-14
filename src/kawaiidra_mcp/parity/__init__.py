"""Parity tools: bethington/ghidra-mcp feature coverage on top of kawaiidra.

Tool modules register ``JTool`` definitions into ``framework.REGISTRY`` on
import. ``server.py`` appends ``mcp_tools()`` to its TOOLS list and routes any
registry name through ``handle()``.
"""

from .framework import REGISTRY, JTool, execute, handle, register  # noqa: F401
from . import tools_program  # noqa: F401  Phase 9
from . import tools_datatypes  # noqa: F401  Phase 10
from . import tools_listing  # noqa: F401  Phase 11
from . import tools_function  # noqa: F401  Phase 12
from . import tools_docs  # noqa: F401  Phase 13
from . import tools_emulation  # noqa: F401  Phase 14
from . import tools_project  # noqa: F401  Phase 15
from . import tools_gui  # noqa: F401  Phase 16
from . import tools_server  # noqa: F401  Phase 17


def mcp_tools(existing: set[str]) -> list:
    clashes = existing & set(REGISTRY)
    if clashes:
        raise ValueError(f"parity tools clash with core tools: {sorted(clashes)}")
    return [t.to_mcp() for t in REGISTRY.values()]
