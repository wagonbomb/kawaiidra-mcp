# Kawaiidra MCP — Feature Roadmap

## Competitive Baseline

| Metric | Kawaiidra | Competitor (bethington/ghidra-mcp) |
|--------|-----------|-------------------------------------|
| Tool count | 61 | 193 |
| Architecture | Headless subprocess + JPype bridge | GUI plugin (Java bridge) |
| Unique strengths | Apple/iOS kernel tools (8), semantic code search, crypto constants, JNI analysis, hardcoded secrets, API endpoint extraction, exhaustive report generator, caching, CVE vuln detection | Ghidra Server integration, version control, knowledge DB, project lifecycle, data type CRUD |

## What We Have That They Don't

These are competitive differentiators — do not deprioritize:

- **Apple/iOS security research** (8 tools): KPP/KTRR, Mach traps, PAC gadgets, sandbox ops, IOKit classes, entitlement checks, kernel symbols, Mach ports
- **Automated analysis**: semantic_code_search, detect_libraries, detect_vulnerabilities (w/ CVE), find_crypto_constants, find_hardcoded_secrets, extract_api_endpoints
- **Context-rich output**: get_function_with_context, get_annotated_disassembly, get_control_flow_graph, suggest_symbol_names
- **Reporting & perf**: generate_report (exhaustive), cache system, JPype bridge mode
- **Mobile**: analyze_jni_methods

---

## Phased Rollout

### Phase 1 — Batch Ops & Low-Level Access ✅ DONE (b05b9f7)

**6 new tools + 2 pagination upgrades = 61 total**

| Tool | Status |
|------|--------|
| `batch_decompile` | ✅ |
| `read_memory` | ✅ |
| `search_bytes` | ✅ |
| `create_function` | ✅ |
| `delete_function` | ✅ |
| `run_script` | ✅ |
| `get_function_decompile` pagination | ✅ |
| `get_function_disassembly` pagination | ✅ |

---

### Phase 2 — Data Types & Structures ✅ DONE (9a183a7)

**Gap: They have 26 tools, we have 1 (`get_data_structures`)**

This is the largest functional gap and blocks serious RE workflows (struct recovery, enum creation, type application). Target: +12 tools → 73 total.

| Tool | Description | Type |
|------|-------------|------|
| `list_data_types` | List/search available data types with optional filter | read |
| `get_data_type_details` | Get detailed info on a specific type (size, fields, category) | read |
| `create_struct` | Create a new structure with optional fields | mutation |
| `add_struct_field` | Add a field to an existing structure | mutation |
| `modify_struct_field` | Change name/type/offset of an existing struct field | mutation |
| `remove_struct_field` | Remove a field from a structure | mutation |
| `create_enum` | Create an enumeration with values | mutation |
| `add_enum_value` | Add a value to an existing enum | mutation |
| `create_typedef` | Create a typedef alias for an existing type | mutation |
| `apply_data_type` | Apply a data type at an address | mutation |
| `delete_data_type` | Delete a user-defined data type | mutation |
| `get_function_variables` | List all variables (params, locals, return) with types | read |

**Implementation notes:**
- All mutation tools use `-noanalysis -save`
- `create_struct` accepts an optional `fields` array for one-shot struct creation
- `list_data_types` should support `filter` (substring match) and `category` params
- `get_function_variables` fills a major gap — needed before users can meaningfully use `set_local_variable_type`

---

### Phase 3 — Symbols, Labels & Bookmarks ✅ DONE

**Gap: They have 14 symbol tools + 3 bookmark tools, we have partial coverage**

Target: +8 tools → 81 total.

| Tool | Description | Type |
|------|-------------|------|
| `create_label` | Create a label/symbol at an address | mutation |
| `delete_label` | Delete a label at an address | mutation |
| `rename_label` | Rename an existing label | mutation |
| `list_labels` | List labels with optional filter and address range | read |
| `get_xrefs_to` | Get all cross-references TO a specific address | read |
| `get_xrefs_from` | Get all cross-references FROM a specific address | read |
| `set_bookmark` | Create a bookmark at an address with category/comment | mutation |
| `list_bookmarks` | List bookmarks, optionally filtered by category | read |

**Implementation notes:**
- `get_xrefs_to`/`get_xrefs_from` are address-level (vs function-level `get_function_xrefs`)
- `list_labels` covers what they split across `list_globals`, `list_external_locations`, `create_label`
- Bookmark tools are simple CRUD — low effort, high usability

---

### Phase 4 — Batch Operations & Comment Types ✅ DONE

**Gap: They have batch_rename, batch_set_comments, multiple comment types**

Target: +6 tools → 87 total.

| Tool | Description | Type |
|------|-------------|------|
| `batch_rename` | Rename multiple functions/labels in one call | mutation |
| `batch_set_comments` | Set comments at multiple addresses in one call | mutation |
| `set_plate_comment` | Set function-level plate comment (header block) | mutation |
| `set_pre_comment` | Set pre-instruction comment | mutation |
| `batch_set_types` | Set types for multiple variables in one call | mutation |
| `clear_comments` | Clear all comments for a function | mutation |

**Implementation notes:**
- Batch tools take arrays and execute in a single Ghidra invocation
- Comment type tools complement existing `set_comment` (which does EOL by default)
- `set_comment` already supports `comment_type` param — consider if the dedicated tools are needed or if this is just about discoverability

---

### Phase 5 — Function Analysis Extras

**Gap: Function hashing, metrics, signatures, disassemble_bytes**

Target: +7 tools → 94 total.

| Tool | Description | Type |
|------|-------------|------|
| `get_function_signature` | Get just the prototype string (lighter than full decompile) | read |
| `get_function_hash` | SHA-256 of normalized instruction bytes | read |
| `get_function_metrics` | Cyclomatic complexity, basic block count, instruction count | read |
| `disassemble_bytes` | Disassemble raw bytes at any address (not function-bound) | read |
| `find_dead_code` | Find unreachable/orphaned code blocks | read |
| `diff_functions` | Side-by-side diff of two functions' decompilation | read |
| `set_function_no_return` | Mark a function as non-returning | mutation |

---

### Phase 6 — Script Management & Analysis Control

**Gap: They have 9 script tools and 3 analysis control tools**

Target: +6 tools → 100 total.

| Tool | Description | Type |
|------|-------------|------|
| `list_scripts` | List saved Ghidra scripts in the scripts directory | read |
| `save_script` | Save a named Jython script for later re-use | mutation |
| `get_script` | Read contents of a saved script | read |
| `delete_script` | Delete a saved script | mutation |
| `list_analyzers` | List available Ghidra auto-analyzers | read |
| `run_analysis` | Trigger auto-analysis on a binary (with optional analyzer selection) | mutation |

**Implementation notes:**
- Script CRUD operates on our `scripts_dir` — simple filesystem ops, no Ghidra needed
- `run_analysis` is essentially `analyze_binary` without `-import` — re-analyze an already-imported binary
- `list_analyzers` requires Ghidra invocation to enumerate available analyzers

---

### Phase 7 — Security & Malware Analysis

**Gap: They have malware detection, anti-analysis, IOC extraction**

Target: +4 tools → 104 total.

| Tool | Description | Type |
|------|-------------|------|
| `detect_malware_behaviors` | Detect suspicious behavior categories (C2, persistence, evasion) | read |
| `find_anti_analysis` | Find anti-debugging, anti-VM, anti-disassembly techniques | read |
| `extract_iocs` | Extract IOCs (IPs, domains, URLs, hashes, registry keys) with context | read |
| `analyze_api_chains` | Detect dangerous API call sequences (e.g., VirtualAlloc→WriteProcessMemory→CreateRemoteThread) | read |

**Implementation notes:**
- These build on our existing `semantic_code_search` and `detect_vulnerabilities` infrastructure
- Pattern-based — define behavior signatures in the Jython scripts
- Could reuse the external script pattern (like DetectVulnerabilities.py)

---

### Phase 8 — Project & Multi-Binary Management

**Gap: They have 5 project lifecycle + 5 multi-program + 4 organization tools**

Target: +5 tools → 109 total.

| Tool | Description | Type |
|------|-------------|------|
| `list_projects` | List Ghidra projects in the projects directory | read |
| `delete_project` | Delete a project and its data | mutation |
| `list_project_binaries` | List all binaries in a project (alias for list_analyzed_binaries) | read |
| `get_entry_points` | Get binary entry points | read |
| `get_function_count` | Quick function count without full listing | read |

**Implementation notes:**
- Most project lifecycle tools are filesystem operations on our `project_dir`
- Multi-program tools (switch_program, open_program) are less relevant in headless mode since we specify binary_name per call
- Server connection, version control, and admin tools (18 tools) are **out of scope** — they require Ghidra Server infrastructure we don't target

---

### Deferred / Out of Scope

These competitor features are **not planned** due to architectural differences:

| Category | Tools | Reason |
|----------|-------|--------|
| Ghidra Server | 7 tools | Requires running Ghidra Server; we're headless |
| Version Control | 4 tools | Tied to Ghidra Server |
| Admin | 3 tools | Tied to Ghidra Server |
| Version History | 2 tools | Tied to Ghidra Server |
| Knowledge Database | 5 tools | Custom persistence layer; could be future work |
| Cross-Binary Documentation | 6 tools | Depends on knowledge DB |
| GUI-only features | `save_program`, `exit_ghidra` | Not applicable to headless |

**Total deferred: 27 tools** — these account for the remaining gap after Phase 8.

---

## Summary

| Phase | Focus | New Tools | Running Total | Effort |
|-------|-------|-----------|---------------|--------|
| 1 ✅ | Batch ops, low-level, pagination | 6 | 61 | Done |
| 2 | Data types & structures | 12 | 73 | Large |
| 3 ✅ | Symbols, labels, bookmarks | 8 | 81 | Done |
| 4 ✅ | Batch ops & comment types | 6 | 87 | Done |
| 5 | Function analysis extras | 7 | 94 | Medium |
| 6 | Script management & analysis control | 6 | 100 | Small |
| 7 | Security & malware analysis | 4 | 104 | Medium |
| 8 | Project & multi-binary management | 5 | 109 | Small |
| — | Deferred (server/VCS/KB) | 27 | — | N/A |

**Target: 109 tools** (56% of competitor count) covering 100% of headless-compatible functionality, plus ~20 unique tools they don't have.
