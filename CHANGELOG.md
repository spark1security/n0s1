# Changelog

All notable changes to n0s1 will be documented here.

## [v1.2.0]

### Added

#### `n0s1.mcp_tools` — transport-agnostic MCP tool specification (Phase A1.1)

Added a new subpackage `n0s1/mcp_tools/` that exposes 11 tool functions
shared by both the stdio (`n0s1-mcp`) and HTTP+SSE (`n0s1_api_backend`)
transports without duplicating any scan logic.

**New files:**

| File | Purpose |
|---|---|
| `n0s1/mcp_tools/context.py` | `ToolContext` dataclass injected by each transport |
| `n0s1/mcp_tools/schemas.py` | Pydantic v2 response models (`ScanResult`, `Finding`, `Status`, `FindingsPage`, `Usage`, `ScanSummary`, `Severity`) |
| `n0s1/mcp_tools/redaction.py` | `redact_match(raw, kind)` — deterministic non-reversible placeholder generation |
| `n0s1/mcp_tools/usage.py` | `tiktoken`-based token estimation (`estimate_tokens`, `naive_baseline_tokens`, `usage_block`) |
| `n0s1/mcp_tools/tools.py` | All 11 tool functions wrapping `SecretScanner`; in-memory scan state store |
| `n0s1/mcp_tools/__init__.py` | Package; re-exports all public symbols |

**Tool functions:** `scan_jira`, `scan_confluence`, `scan_slack`, `scan_asana`,
`scan_linear`, `scan_zendesk`, `scan_wrike`, `scan_github`, `scan_gitlab`,
`get_scan_status`, `get_scan_findings`.

**Design constraints honoured:**
- No MCP SDK dependency.
- No breaking changes to existing CLI or scanner API.
- Raw secret values are redacted before they leave the tools layer; the
  `sensitive_secret` field from `SecretScanner.report_sensitive_json` is used
  only transiently to produce a redacted placeholder.
- `on_scan_event` callback is fired exactly once per `scan_*` call and zero
  times for the read-only `get_scan_status` / `get_scan_findings` calls.

**New runtime dependencies:** `pydantic>=2`, `tiktoken>=0.7`.

**Tests:** `tests/test_mcp_tools.py` — schema round-trips, redaction safety,
usage math invariants, callback counts, pagination, and severity filtering.

This is Phase A1.1 of the agent-native roadmap described in
`AGENT_PLAN.md` in the `spark1security/n0s1_api_backend` repository.
