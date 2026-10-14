# GUI debugger test harness

Boots the real Ghidra GUI, opens the **Debugger** tool on a program and runs a
Jython script inside that tool (used to start the ghidra_bridge server where
the Trace RMI debugger services exist). This is how the `debugger_*` tools were
validated live (VALIDATION_REPORT.md, Phase 16).

```bash
G=/path/to/ghidra_12.0.3_PUBLIC
CP=$(find $G/Ghidra -name '*.jar' -path '*/lib/*' | tr '\n' ';')   # ':' on Linux/macOS
javac -cp "$CP" -d build KawaiiDebugHarness.java && (cd build && jar cf kharness.jar KawaiiDebugHarness.class)
javac -d boot KBoot.java

# bridge server scripts (+ a starter that runs it unconditionally)
python -m kawaiidra_mcp.install_bridge_server bridge/
printf '# @runtime Jython\nimport sys\nsys.path.insert(0, r"%s")\nfrom ghidra_bridge_server import GhidraBridgeServer\nGhidraBridgeServer.run_server(background=True)\n' "$PWD/bridge" > bridge/start_bridge.py

java -Djava.system.class.loader=ghidra.GhidraClassLoader -Xshare:off --enable-native-access=ALL-UNNAMED \
  -cp "$G/Ghidra/Framework/Utility/lib/Utility.jar;boot" \
  KBoot build/kharness.jar KawaiiDebugHarness <project.gpr> <program> bridge/start_bridge.py
```

Why the two classes: `GhidraLauncher` resolves the launchable before honoring
extra classpath, and a harness on `-cp` would be loaded by the parent class
loader (no access to Ghidra modules). `KBoot` adds the harness jar to
`GhidraClassLoader` and then calls `ghidra.Ghidra.main`. The stock
`ghidra_bridge_server_background.py` only starts under `__name__ ==
"__main__"`, which a programmatically executed script does not get — hence the
starter. On Windows the dbgeng agent needs a Python with Ghidra's wheels
(`Ghidra/Debug/Debugger-agent-dbgeng/pypkg/dist`, `Debugger-rmi-trace/pypkg/dist`,
plus `psutil`) and `WINDBG_DIR` (System32's dbgeng.dll works).

Then:

```
set KAWAIIDRA_GUI_MODE=true
set KAWAIIDRA_SMOKE_DEBUGGER=1
set KAWAIIDRA_SMOKE_DEBUGGER_PYTHON=<agent python>
python run_comprehensive_tests.py --parity 16
```

Running the GUI writes Ghidra user preferences (recent project, theme, and
possibly the user-agreement flag); back them up first if that matters.
