# Analysis Documentation

This folder contains binary analysis reports and research findings generated using Kawaiidra MCP.

## Report Structure

When creating analysis reports, follow this structure:

```
analysis/
├── {target}-analysis.md      # Main analysis report
├── {target}-api-endpoints.md # API endpoints reference
├── {target}-device-types.md  # Device/hardware catalog
└── {target}-strings.md       # Notable strings dump
```

## Example Analysis Targets

Kawaiidra MCP excels at analyzing:
- **Mobile applications**: Android APKs (native libraries), iOS binaries
- **IoT firmware**: Embedded device binaries and firmware images
- **Desktop applications**: Windows PE, Linux ELF, macOS Mach-O
- **Security research**: Malware analysis, vulnerability research

## Contributing

When adding new analysis reports:
1. Create a subfolder or prefix for the target
2. Follow the existing report structure
3. Include decompiled code samples where relevant
4. Document all discovered endpoints and protocols
5. Update this README with links to new reports
