"""Install the ghidra_bridge server scripts for kawaiidra GUI mode.

    python -m kawaiidra_mcp.install_bridge_server <dir on Ghidra's script path>

Differences from ``python -m ghidra_bridge.install_server``:
* no ``pkg_resources`` dependency (absent from modern setuptools/Python);
* adds ``# @runtime Jython`` to the server scripts — Ghidra 12 runs ``.py``
  scripts with PyGhidra unless they declare Jython, and the bridge server
  must run in Jython inside the GUI.

Then in Ghidra: Script Manager > ghidra_bridge_server_background.py, and start
kawaiidra with KAWAIIDRA_GUI_MODE=true.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

HEADER = "# @runtime Jython\n"


def install(dest: Path) -> list[Path]:
    try:
        import ghidra_bridge
        import jfx_bridge
    except ImportError:
        raise SystemExit("ghidra_bridge is not installed: pip install ghidra_bridge")

    dest.mkdir(parents=True, exist_ok=True)
    written = []
    jfx_dest = dest / "jfx_bridge"
    jfx_dest.mkdir(exist_ok=True)
    for f in Path(jfx_bridge.__file__).parent.glob("*.py"):
        if not f.name.startswith("test_"):
            shutil.copy(f, jfx_dest / f.name)
            written.append(jfx_dest / f.name)
    for f in (Path(ghidra_bridge.__file__).parent / "server").glob("*.py"):
        if f.name == "__init__.py":
            continue
        text = f.read_text(encoding="utf-8")
        if f.name.startswith("ghidra_bridge_server") and "@runtime" not in text:
            text = HEADER + text
        (dest / f.name).write_text(text, encoding="utf-8")
        written.append(dest / f.name)
    return written


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    for p in install(Path(sys.argv[1]).expanduser()):
        print("  " + str(p))
    print("Installed. Run ghidra_bridge_server_background.py from Ghidra's Script Manager.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
