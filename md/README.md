# Analysis Documentation

This folder contains binary analysis reports and research findings generated using Kawaiidra MCP.

## Analysis Reports

| Report | Binary | Date | Description |
|--------|--------|------|-------------|
| [GE Cync Smart Home App](analysis/ge-cync-analysis.md) | com.ge.cbyge v6.20.0 | 2026-01-11 | Complete reverse engineering of GE's Cync smart lighting app |

## Report Structure

Each analysis report follows this structure:

```
analysis/
├── {target}-analysis.md      # Main analysis report
├── {target}-api-endpoints.md # API endpoints reference
├── {target}-device-types.md  # Device/hardware catalog
└── {target}-strings.md       # Notable strings dump
```

## Quick Links

### GE Cync Analysis
- [Full Analysis Report](analysis/ge-cync-analysis.md)
- [API Endpoints Reference](analysis/ge-cync-api-endpoints.md)
- [Device Types Catalog](analysis/ge-cync-device-types.md)

## Contributing

When adding new analysis reports:
1. Create a subfolder or prefix for the target
2. Follow the existing report structure
3. Include decompiled code samples where relevant
4. Document all discovered endpoints and protocols
5. Update this README with links to new reports
