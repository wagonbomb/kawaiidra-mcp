# tools/data

`bethington_endpoints.json` is the endpoint catalog (`tests/endpoints.json`) from
[bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) v7.0.0
(commit 0724b02, Apache-2.0, © its authors), vendored unmodified so
`tools/gen_parity.py` can regenerate and verify `PARITY.md`:

    python tools/gen_parity.py tools/data/bethington_endpoints.json
