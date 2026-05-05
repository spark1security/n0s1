"""Transport-agnostic MCP tool functions for n0s1 secret scanning.

Each function wraps the existing :class:`n0s1.scanner.SecretScanner`; no
transport (stdio, HTTP, MCP SDK) code is imported here.

Authentication credentials are read from environment variables by the
underlying scanner, matching the existing CLI behaviour.  The transport
layer may pre-populate env vars via ToolContext.token_id in a later phase.

Runner dispatch:
  ctx.runner == "DOCKER"  ->  local SecretScanner (default)
  ctx.runner == "AWS"     ->  local SecretScanner (AWS Lambda dispatch
                               is reserved for Phase A4)

Scan state (report_uuid -> ScanResult) is kept in a module-level dict so
that get_scan_status and get_scan_findings can serve results after the
synchronous scan completes.  Replace with a persistent store in Phase A4.
"""
import json
import threading
import uuid
from typing import Dict, List, Optional

import n0s1.scanner as _scanner

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
from n0s1.mcp_tools.usage import usage_block

# ---------------------------------------------------------------------------
# In-memory scan state
# ---------------------------------------------------------------------------

_scan_store: Dict[str, ScanResult] = {}
_error_store: Dict[str, str] = {}
_store_lock = threading.Lock()

_PAGE_SIZE = 50


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _dispatch_scan(target: str, scanner_kwargs: dict, ctx: ToolContext):
    """Instantiate SecretScanner and run a scan.

    Both "DOCKER" and "AWS" runners use the local scanner in this phase.
    AWS Lambda dispatch will be wired in Phase A4.

    Returns:
        (report_json, sensitive_json) tuple.
    """
    s = _scanner.SecretScanner(target=target, **scanner_kwargs)
    report_json = s.scan()
    return report_json, s.report_sensitive_json


def _build_findings(report_json: dict, sensitive_json: Optional[dict]) -> List[Finding]:
    """Convert scanner report dict to a list of redacted :class:`Finding` objects."""
    results: List[Finding] = []
    for fid, f in (report_json.get("findings") or {}).items():
        matched_cfg = f.get("details", {}).get("matched_regex_config") or {}
        secret_type = matched_cfg.get("id", "unknown")

        # Use the raw matched secret (from sensitive_json) ONLY to produce the
        # redacted placeholder — it must never appear in any returned object.
        raw = ""
        if sensitive_json:
            raw = (
                sensitive_json.get("findings", {}).get(fid, {}).get("sensitive_secret", "")
            )
        if not raw:
            # Fall back to mocked_secret (example substitution) if sensitive
            # data is unavailable (e.g. scan ran with show_matched_secret_on_logs=False
            # and report_sensitive_json was not populated).
            raw = f.get("mocked_secret", "") or f.get("secret", "")

        redacted = redact_match(str(raw), secret_type)

        url = f.get("url", "")
        line_number: Optional[int] = None
        if "#L" in url:
            try:
                line_number = int(url.split("#L")[-1])
            except (ValueError, IndexError):
                pass

        results.append(
            Finding(
                file=url,
                line=line_number,
                type=secret_type,
                # Existing regex rules carry no severity field; defaulting to
                # "high" until a severity taxonomy is added in a later phase.
                severity=Severity.high,
                redacted_match=redacted,
            )
        )
    return results


def _build_summary(findings: List[Finding]) -> ScanSummary:
    by_severity: Dict[Severity, int] = {}
    by_type: Dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_type[f.type] = by_type.get(f.type, 0) + 1
    return ScanSummary(
        total_findings=len(findings),
        by_severity=by_severity,
        by_type=by_type,
    )


def _run_platform_scan(
    target: str,
    scanner_kwargs: dict,
    ctx: ToolContext,
    tool_name: str,
    input_repr,
) -> ScanResult:
    """Run a scan, build a ScanResult, persist it, fire the event callback."""
    report_uuid = str(uuid.uuid4())
    result: ScanResult
    error_msg: Optional[str] = None

    try:
        report_json, sensitive_json = _dispatch_scan(target, scanner_kwargs, ctx)
        findings = _build_findings(report_json, sensitive_json)
        summary = _build_summary(findings)
        use = usage_block(input_repr, report_json)
        result = ScanResult(
            report_uuid=report_uuid,
            status="complete",
            summary=summary,
            findings=findings,
            usage=use,
        )
    except Exception as exc:
        error_msg = str(exc)
        result = ScanResult(
            report_uuid=report_uuid,
            status="failed",
            summary=ScanSummary(total_findings=0, by_severity={}, by_type={}),
            usage=Usage(
                tokens_in_estimate=0,
                tokens_out_actual=0,
                tokens_saved_estimate=0,
                savings_pct=0.0,
            ),
        )

    with _store_lock:
        _scan_store[report_uuid] = result
        if error_msg:
            _error_store[report_uuid] = error_msg

    if ctx.on_scan_event is not None:
        ctx.on_scan_event(
            {
                "report_uuid": report_uuid,
                "tool_name": tool_name,
                "tokens_in_estimate": result.usage.tokens_in_estimate,
                "tokens_out_actual": result.usage.tokens_out_actual,
                "tokens_saved_estimate": result.usage.tokens_saved_estimate,
            }
        )

    return result


# ---------------------------------------------------------------------------
# Scope builders
# ---------------------------------------------------------------------------


def _jira_scope(project_key: Optional[str], since: Optional[str]) -> Optional[str]:
    parts = []
    if project_key:
        parts.append(f'project = "{project_key}"')
    if since:
        parts.append(f'created >= "{since}"')
    return ("jql:" + " AND ".join(parts)) if parts else None


def _confluence_scope(space_key: Optional[str], since: Optional[str]) -> Optional[str]:
    parts = []
    if space_key:
        parts.append(f'space = "{space_key}"')
    if since:
        parts.append(f'created >= "{since}"')
    return ("cql:" + " AND ".join(parts)) if parts else None


def _search_scope(query: Optional[str]) -> Optional[str]:
    return f"search:{query}" if query else None


# ---------------------------------------------------------------------------
# Public tool functions
# ---------------------------------------------------------------------------


def scan_jira(
    workspace_url: str,
    project_key: Optional[str] = None,
    since: Optional[str] = None,
    *,
    scope: Optional[str] = None,
    api_key: Optional[str] = None,
    email: Optional[str] = None,
    report_format: str = "n0s1",
    show_matched_secret_on_logs: bool = False,
    ctx: ToolContext,
) -> ScanResult:
    """Scan a Jira workspace for leaked secrets.

    Credentials are read from JIRA_TOKEN and JIRA_EMAIL env vars, or may be
    passed directly via api_key / email for backwards compatibility.
    """
    effective_scope = scope or _jira_scope(project_key, since)
    kwargs: dict = {
        "server": workspace_url,
        "show_matched_secret_on_logs": show_matched_secret_on_logs,
        "post_comment": False,
        "report_format": report_format,
    }
    if effective_scope:
        kwargs["scope"] = effective_scope
    if api_key:
        kwargs["api_key"] = api_key
    if email:
        kwargs["email"] = email
    return _run_platform_scan(
        "jira_scan",
        kwargs,
        ctx,
        "scan_jira",
        {"workspace_url": workspace_url, "project_key": project_key, "since": since},
    )


def scan_confluence(
    workspace_url: str,
    space_key: Optional[str] = None,
    since: Optional[str] = None,
    *,
    scope: Optional[str] = None,
    api_key: Optional[str] = None,
    email: Optional[str] = None,
    report_format: str = "n0s1",
    show_matched_secret_on_logs: bool = False,
    ctx: ToolContext,
) -> ScanResult:
    """Scan a Confluence workspace for leaked secrets.

    Credentials are read from CONFLUENCE_TOKEN / JIRA_TOKEN and
    CONFLUENCE_EMAIL / JIRA_EMAIL env vars, or may be passed directly
    via api_key / email for backwards compatibility.
    """
    effective_scope = scope or _confluence_scope(space_key, since)
    kwargs: dict = {
        "server": workspace_url,
        "show_matched_secret_on_logs": show_matched_secret_on_logs,
        "post_comment": False,
        "report_format": report_format,
    }
    if effective_scope:
        kwargs["scope"] = effective_scope
    if api_key:
        kwargs["api_key"] = api_key
    if email:
        kwargs["email"] = email
    return _run_platform_scan(
        "confluence_scan",
        kwargs,
        ctx,
        "scan_confluence",
        {"workspace_url": workspace_url, "space_key": space_key, "since": since},
    )


def scan_slack(
    workspace_url: Optional[str] = None,
    channel: Optional[str] = None,
    since: Optional[str] = None,
    *,
    api_key: Optional[str] = None,
    report_format: str = "n0s1",
    show_matched_secret_on_logs: bool = False,
    ctx: ToolContext,
) -> ScanResult:
    """Scan a Slack workspace for leaked secrets.

    Credentials are read from the SLACK_TOKEN env var, or may be passed
    directly via api_key for backwards compatibility.
    workspace_url is optional and recorded for traceability only.
    """
    scope = _search_scope(channel)
    kwargs: dict = {
        "show_matched_secret_on_logs": show_matched_secret_on_logs,
        "post_comment": False,
        "report_format": report_format,
    }
    if scope:
        kwargs["scope"] = scope
    if api_key:
        kwargs["api_key"] = api_key
    return _run_platform_scan(
        "slack_scan",
        kwargs,
        ctx,
        "scan_slack",
        {"workspace_url": workspace_url, "channel": channel, "since": since},
    )


def scan_asana(
    workspace_url: Optional[str] = None,
    project: Optional[str] = None,
    since: Optional[str] = None,
    *,
    scope: Optional[str] = None,
    api_key: Optional[str] = None,
    report_format: str = "n0s1",
    show_matched_secret_on_logs: bool = False,
    ctx: ToolContext,
) -> ScanResult:
    """Scan an Asana workspace for leaked secrets.

    Credentials are read from the ASANA_TOKEN env var, or may be passed
    directly via api_key for backwards compatibility.
    """
    effective_scope = scope or _search_scope(project)
    kwargs: dict = {
        "show_matched_secret_on_logs": show_matched_secret_on_logs,
        "post_comment": False,
        "report_format": report_format,
    }
    if effective_scope:
        kwargs["scope"] = effective_scope
    if api_key:
        kwargs["api_key"] = api_key
    return _run_platform_scan(
        "asana_scan",
        kwargs,
        ctx,
        "scan_asana",
        {"workspace_url": workspace_url, "project": project, "since": since},
    )


def scan_linear(
    workspace_url: Optional[str] = None,
    team: Optional[str] = None,
    since: Optional[str] = None,
    *,
    api_key: Optional[str] = None,
    report_format: str = "n0s1",
    show_matched_secret_on_logs: bool = False,
    ctx: ToolContext,
) -> ScanResult:
    """Scan a Linear workspace for leaked secrets.

    Credentials are read from the LINEAR_TOKEN env var, or may be passed
    directly via api_key for backwards compatibility.
    """
    scope = _search_scope(team)
    kwargs: dict = {
        "show_matched_secret_on_logs": show_matched_secret_on_logs,
        "post_comment": False,
        "report_format": report_format,
    }
    if scope:
        kwargs["scope"] = scope
    if api_key:
        kwargs["api_key"] = api_key
    return _run_platform_scan(
        "linear_scan",
        kwargs,
        ctx,
        "scan_linear",
        {"workspace_url": workspace_url, "team": team, "since": since},
    )


def scan_zendesk(
    workspace_url: str,
    since: Optional[str] = None,
    *,
    api_key: Optional[str] = None,
    email: Optional[str] = None,
    report_format: str = "n0s1",
    show_matched_secret_on_logs: bool = False,
    ctx: ToolContext,
) -> ScanResult:
    """Scan a Zendesk workspace for leaked secrets.

    Credentials are read from ZENDESK_TOKEN, ZENDESK_EMAIL, and
    ZENDESK_SERVER env vars.  workspace_url overrides ZENDESK_SERVER.
    api_key / email may be passed directly for backwards compatibility.
    """
    kwargs: dict = {
        "server": workspace_url,
        "show_matched_secret_on_logs": show_matched_secret_on_logs,
        "post_comment": False,
        "report_format": report_format,
    }
    if api_key:
        kwargs["api_key"] = api_key
    if email:
        kwargs["email"] = email
    return _run_platform_scan(
        "zendesk_scan",
        kwargs,
        ctx,
        "scan_zendesk",
        {"workspace_url": workspace_url, "since": since},
    )


def scan_wrike(
    workspace_url: Optional[str] = None,
    since: Optional[str] = None,
    *,
    scope: Optional[str] = None,
    api_key: Optional[str] = None,
    report_format: str = "n0s1",
    show_matched_secret_on_logs: bool = False,
    ctx: ToolContext,
) -> ScanResult:
    """Scan a Wrike workspace for leaked secrets.

    Credentials are read from the WRIKE_TOKEN env var, or may be passed
    directly via api_key for backwards compatibility.
    """
    kwargs: dict = {
        "show_matched_secret_on_logs": show_matched_secret_on_logs,
        "post_comment": False,
        "report_format": report_format,
    }
    if scope:
        kwargs["scope"] = scope
    if api_key:
        kwargs["api_key"] = api_key
    return _run_platform_scan(
        "wrike_scan",
        kwargs,
        ctx,
        "scan_wrike",
        {"workspace_url": workspace_url, "since": since},
    )


def scan_github(
    repo: str,
    since: Optional[str] = None,
    *,
    branch: Optional[str] = None,
    scope: Optional[str] = None,
    api_key: Optional[str] = None,
    report_format: str = "n0s1",
    show_matched_secret_on_logs: bool = False,
    ctx: ToolContext,
) -> ScanResult:
    """Scan a GitHub repository for leaked secrets.

    Args:
        repo: "owner/repo" or just "owner" to scan all repos for that owner.
        branch: specific branch to scan (optional).
        scope: raw search query e.g. "search:org:myorg" (optional).

    Credentials are read from the GITHUB_TOKEN env var, or may be passed
    directly via api_key for backwards compatibility.
    """
    parts = repo.split("/", 1)
    owner = parts[0] if len(parts) > 1 else repo
    repo_name = parts[1] if len(parts) > 1 else ""
    kwargs: dict = {
        "owner": owner,
        "repo": repo_name,
        "show_matched_secret_on_logs": show_matched_secret_on_logs,
        "post_comment": False,
        "report_format": report_format,
    }
    if branch:
        kwargs["branch"] = branch
    if scope:
        kwargs["scope"] = scope
    if api_key:
        kwargs["api_key"] = api_key
    return _run_platform_scan(
        "github_scan",
        kwargs,
        ctx,
        "scan_github",
        {"repo": repo, "since": since},
    )


def scan_gitlab(
    repo: str,
    since: Optional[str] = None,
    *,
    server: Optional[str] = None,
    branch: Optional[str] = None,
    scope: Optional[str] = None,
    api_key: Optional[str] = None,
    report_format: str = "n0s1",
    show_matched_secret_on_logs: bool = False,
    ctx: ToolContext,
) -> ScanResult:
    """Scan a GitLab project for leaked secrets.

    Args:
        repo: "group/project" or just "group" to scan all projects.
        server: GitLab server URL (default: https://gitlab.com).
        branch: specific branch to scan (optional).

    Credentials are read from GITLAB_TOKEN env var;
    server defaults to GITLAB_URL or https://gitlab.com.
    api_key may be passed directly for backwards compatibility.
    """
    parts = repo.split("/", 1)
    owner = parts[0] if len(parts) > 1 else repo
    project = parts[1] if len(parts) > 1 else ""
    kwargs: dict = {
        "owner": owner,
        "repo": project,
        "show_matched_secret_on_logs": show_matched_secret_on_logs,
        "post_comment": False,
        "report_format": report_format,
    }
    if server:
        kwargs["server"] = server
    if branch:
        kwargs["branch"] = branch
    if scope:
        kwargs["scope"] = scope
    if api_key:
        kwargs["api_key"] = api_key
    return _run_platform_scan(
        "gitlab_scan",
        kwargs,
        ctx,
        "scan_gitlab",
        {"repo": repo, "since": since},
    )


# ---------------------------------------------------------------------------
# Read-only tools (no on_scan_event)
# ---------------------------------------------------------------------------


def get_scan_status(report_uuid: str, *, ctx: ToolContext) -> Status:
    """Return the current status of an existing scan.

    Returns status="pending" if the report_uuid is not yet known.
    """
    with _store_lock:
        result = _scan_store.get(report_uuid)
        error = _error_store.get(report_uuid) if result and result.status == "failed" else None

    if result is None:
        return Status(report_uuid=report_uuid, status="pending")

    return Status(
        report_uuid=report_uuid,
        status=result.status,
        progress_pct=100.0 if result.status == "complete" else None,
        error=error,
    )


def get_scan_findings(
    report_uuid: str,
    page: Optional[str] = None,
    severity: Optional[Severity] = None,
    *,
    ctx: ToolContext,
) -> FindingsPage:
    """Return a page of findings for an existing scan.

    Args:
        report_uuid: UUID returned by the originating scan_* call.
        page:        Opaque cursor from a previous FindingsPage.next_cursor;
                     None for the first page.
        severity:    Optional filter — only return findings at this severity.

    Raises:
        KeyError: if report_uuid is not found in the scan store.
    """
    with _store_lock:
        result = _scan_store.get(report_uuid)

    if result is None:
        raise KeyError(f"No scan found with report_uuid={report_uuid!r}")

    all_findings: List[Finding] = result.findings or []
    if severity is not None:
        all_findings = [f for f in all_findings if f.severity == severity]

    cursor: dict = json.loads(page) if page else {"offset": 0, "page_size": _PAGE_SIZE}
    offset: int = cursor.get("offset", 0)
    page_size: int = cursor.get("page_size", _PAGE_SIZE)

    page_findings = all_findings[offset : offset + page_size]
    next_offset = offset + page_size
    next_cursor = (
        json.dumps({"offset": next_offset, "page_size": page_size})
        if next_offset < len(all_findings)
        else None
    )

    use = usage_block(
        [f.model_dump() for f in all_findings],
        [f.model_dump() for f in page_findings],
    )

    return FindingsPage(
        report_uuid=report_uuid,
        findings=page_findings,
        next_cursor=next_cursor,
        total=len(all_findings),
        usage=use,
    )
