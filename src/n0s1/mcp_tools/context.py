"""ToolContext: injected by the transport layer into every tool function.

Tool functions must read all transport-specific state from this object and
must not import any transport (stdio, HTTP) modules themselves.
"""
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class ToolContext:
    """Carries per-request state from the transport into tool functions.

    Attributes:
        user_id: SaaS user identifier; None when running under stdio/local.
        token_id: api_tokens row id; None for stdio transport.
        agent_session_id: session tracking id (Phase A4); None for now.
        runner: execution environment — "DOCKER" (default) or "AWS".
        on_scan_event: optional callback fired once per scan_* call with a
            dict containing at minimum report_uuid, tool_name,
            tokens_in_estimate, tokens_out_actual, tokens_saved_estimate.
    """

    user_id: Optional[str] = None
    token_id: Optional[str] = None
    agent_session_id: Optional[str] = None
    runner: str = "DOCKER"
    on_scan_event: Optional[Callable[[dict], None]] = None
