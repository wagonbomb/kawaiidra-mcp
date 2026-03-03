@echo off
REM Set your Ghidra installation path (or use auto-detection by leaving unset)
REM set GHIDRA_INSTALL_DIR=C:\path\to\ghidra
set KAWAIIDRA_PROJECT_DIR=%~dp0projects
set KAWAIIDRA_BINARIES_DIR=%~dp0binaries
set KAWAIIDRA_TIMEOUT=600
python -u "%~dp0run_server.py"
