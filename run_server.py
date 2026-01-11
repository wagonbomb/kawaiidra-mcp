#!/usr/bin/env python3
"""Wrapper script to run the Kawaiidra MCP server."""
import sys
import asyncio
from pathlib import Path

# Windows-specific: use ProactorEventLoop for better subprocess/pipe handling
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# Add src to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

# Run the server
from kawaiidra_mcp.server import main

if __name__ == "__main__":
    asyncio.run(main())
