"""n0s1.mcp_tools — transport-agnostic MCP tool specification.

Provides the 11 tool functions that both the stdio (n0s1-mcp) and
HTTP+SSE (n0s1_api_backend) transports register, without depending on
either transport or the MCP SDK.
"""
from n0s1.mcp_tools.context import ToolContext
from n0s1.mcp_tools.redaction import redact_match
from n0s1.mcp_tools.schemas import (
    Finding,
    FindingsPage,
    ScanResult,
    ScanSummary,
    Severity,
    Status,
    Usage,
)
from n0s1.mcp_tools.tools import (
    get_scan_findings,
    get_scan_status,
    scan_asana,
    scan_confluence,
    scan_github,
    scan_gitlab,
    scan_jira,
    scan_linear,
    scan_slack,
    scan_wrike,
    scan_zendesk,
)
from n0s1.mcp_tools.usage import usage_block

__all__ = [
    # Context
    "ToolContext",
    # Schemas
    "Finding",
    "FindingsPage",
    "ScanResult",
    "ScanSummary",
    "Severity",
    "Status",
    "Usage",
    # Helpers (for transport-layer local tools such as scan_local)
    "redact_match",
    "usage_block",
    # Tools
    "scan_jira",
    "scan_confluence",
    "scan_slack",
    "scan_asana",
    "scan_linear",
    "scan_zendesk",
    "scan_wrike",
    "scan_github",
    "scan_gitlab",
    "get_scan_status",
    "get_scan_findings",
]
