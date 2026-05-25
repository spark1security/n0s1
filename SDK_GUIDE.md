# n0s1 SDK Guide

Complete guide for using n0s1 as a Python SDK/library in your applications.

## Table of Contents
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [SecretScanner Class](#secretscanner-class)
- [Platform-Specific Examples](#platform-specific-examples)
- [Advanced Usage](#advanced-usage)
- [MCP Tools Package](#mcp-tools-package)
- [API Reference](#api-reference)

## Installation

```bash
pip install n0s1
```

Or install from source:
```bash
git clone https://github.com/spark1security/n0s1.git
cd n0s1
pip install -r requirements.txt
```

## Quick Start

### Basic Example - Scan Jira

```python
try:
    import scanner
except:
    import n0s1.scanner as scanner

# Create scanner instance
scanner_instance = scanner.SecretScanner(
    target="jira_scan",
    server="https://yourcompany.atlassian.net",
    email="your-email@company.com",
    api_key="your-jira-api-token",
    debug=True
)

# Run the scan
result = scanner_instance.scan()

# Process results
print(f"Scan complete. Found {len(result.get('findings', {}))} potential secrets")
```

## Core Concepts

### 1. Import Pattern

The SDK uses a try/except pattern for imports to work both as a standalone module and as an installed package:

```python
try:
    import scanner
except:
    import n0s1.scanner as scanner
```

### 2. Scanner Lifecycle

1. **Create** - Instantiate `SecretScanner` with configuration
2. **Configure** (optional) - Use `set()` method to update settings
3. **Scan** - Call `scan()` method to execute
4. **Results** - Access findings via return value or `get_report()`

### 3. Target Platforms

The `target` parameter specifies which platform to scan:
- `local_scan` - Local filesystem
- `slack_scan` - Slack workspace
- `asana_scan` - Asana tasks
- `zendesk_scan` - Zendesk tickets
- `github_scan` - GitHub repositories
- `gitlab_scan` - GitLab repositories
- `wrike_scan` - Wrike tasks
- `linear_scan` - Linear issues
- `jira_scan` - Jira tickets
- `confluence_scan` - Confluence pages

## SecretScanner Class

### Constructor

```python
scanner.SecretScanner(
    # Required
    target=None,                    # Platform to scan (e.g., "jira_scan")
    
    # Platform-specific credentials
    api_key=None,                   # API token/key
    server=None,                    # Server URL (Jira, Confluence, etc.)
    email=None,                     # User email (Jira, Confluence, Zendesk)
    owner=None,                     # GitHub/GitLab owner/org
    repo=None,                      # Repository name
    branch=None,                    # Branch name
    scan_path=None,                 # Local filesystem path
    
    # Configuration files
    regex_file=None,                # Custom regex patterns file
    config_file=None,               # Configuration YAML file
    
    # Reporting
    report_file=None,               # Output file path
    report_format="n0s1",           # Format: "n0s1", "sarif", "gitlab"
    
    # Scanning behavior
    post_comment=False,             # Auto-post warning comments
    skip_comment=False,             # Skip scanning comments
    show_matched_secret_on_logs=False,  # Show actual secrets in reports and logs
    ai_analysis=False,              # Enable AI secret leak analysis
    private=False,                  # Enable private mode
    debug=False,                    # Enable debug mode
    
    # Customization
    secret_manager=None,            # Suggested secret manager name
    contact_help=None,              # Help contact info
    label=None,                     # Bot identifier label
    
    # Network & Performance
    timeout=None,                   # HTTP timeout in seconds
    limit=None,                     # Page limit per request
    insecure=False,                 # Ignore SSL verification
    
    # Scope
    map=None,                       # Mapping depth level
    map_file=None,                  # Map file path
    scope=None,                     # Search query/scope

    # AI analysis
    report_uuid=None,               # str: UUID of a previously uploaded report (for analyze())
    n0s1_token=None,                # str: n0s1 API key; overrides N0S1_TOKEN env var
)
```

### Methods

#### `scan()`
Execute the scan and return results.

```python
result = scanner_instance.scan()
# Returns: dict with findings, metadata, and scan info
```

#### `set(**kwargs)`
Update scanner configuration after instantiation.

```python
scanner_instance.set(
    debug=True,
    report_format="sarif",
    scope="jql:project = SEC"
)
```

#### `get_report()`
Get the current scan report.

```python
report = scanner_instance.get_report()
```

#### `set_logging_function(func)`
Set a custom logging function.

```python
def custom_logger(message, level):
    print(f"[{level}] {message}")

scanner_instance.set_logging_function(custom_logger)
```

#### `get_config()`
Get the current configuration.

```python
config = scanner_instance.get_config()
```

#### `get_scope_config()`
Get the scope configuration.

```python
scope_config = scanner_instance.get_scope_config()
```

#### `analyze()`
Submit a scan report for async AI analysis, or advance an in-progress analysis. Requires a valid n0s1 API key set via `n0s1_token` or the `N0S1_TOKEN` environment variable.

```python
# Submit by UUID (report already uploaded)
scanner_instance = scanner.SecretScanner(
    report_uuid="abc-123",
    n0s1_token=os.getenv("N0S1_TOKEN"),
)
status = scanner_instance.analyze()

# Submit by local report file
scanner_instance = scanner.SecretScanner(
    report_file="n0s1_report.json",
    n0s1_token=os.getenv("N0S1_TOKEN"),
)
status = scanner_instance.analyze()
```

`analyze()` returns a status string:

| Return value | Meaning |
|---|---|
| `"complete"` | Analysis finished; report file updated |
| `"submitted"` | First submission accepted; backend is queuing |
| `"pending"` / `"pending_step1_batch"` / `"pending_verdict"` | Backend still processing — call again later |
| `"failed"` | Unrecoverable AI analysis failure |
| `"error"` | Misconfiguration or HTTP error |

Re-call on any pending status until `"complete"` is returned.

#### `analyze_blocking(wait_seconds, poll_interval=30)`
Convenience wrapper around `analyze()` that polls internally until a terminal state or timeout. Useful in scripts and pipelines that cannot implement their own retry loop.

```python
analyzer = scanner.SecretScanner(
    report_uuid="abc-123",
    n0s1_token=os.getenv("N0S1_TOKEN"),
)
status = analyzer.analyze_blocking(wait_seconds=600)
if status == "complete":
    print("Done!")
elif status == "timeout":
    print("Still pending after 600 s — try again later")
else:
    print(f"Error: {status}")
```

`analyze_blocking()` returns the same status strings as `analyze()`, plus `"timeout"` when `wait_seconds` elapses without reaching a terminal state. It logs remaining time before each retry.

## Platform-Specific Examples

### Local Filesystem Scan

```python
scanner_instance = scanner.SecretScanner(
    target="local_scan",
    scan_path="/path/to/project",
    report_file="local_scan_results.json",
    debug=True,
    private=True
)
result = scanner_instance.scan()
```

### Slack Scan

```python
scanner_instance = scanner.SecretScanner(
    target="slack_scan",
    api_key="xoxb-your-slack-token",
    report_format="sarif"
)
result = scanner_instance.scan()
```

### Asana Scan

```python
scanner_instance = scanner.SecretScanner(
    target="asana_scan",
    api_key="1/1234567890abcdef",
    debug=True
)
result = scanner_instance.scan()
```

### Zendesk Scan

```python
scanner_instance = scanner.SecretScanner(
    target="zendesk_scan",
    server="mycompany",  # subdomain
    email="admin@company.com",
    api_key="your-zendesk-api-key"
)
result = scanner_instance.scan()
```

### GitHub Scan

```python
# Scan specific repository
scanner_instance = scanner.SecretScanner(
    target="github_scan",
    owner="myorg",
    repo="myrepo",
    branch="main",  # optional
    api_key="ghp_xxxxxxxxxxxx"
)
result = scanner_instance.scan()

# Scan all accessible repos with scope
scanner_instance = scanner.SecretScanner(
    target="github_scan",
    api_key="ghp_xxxxxxxxxxxx",
    scope="search:org:myorg action in:name"
)
result = scanner_instance.scan()
```

### GitLab Scan

```python
# Scan GitLab.com
scanner_instance = scanner.SecretScanner(
    target="gitlab_scan",
    server="https://gitlab.com",
    owner="mygroup",
    repo="myproject",
    api_key="glpat-xxxxxxxxxxxx"
)
result = scanner_instance.scan()

# Scan self-hosted GitLab
scanner_instance = scanner.SecretScanner(
    target="gitlab_scan",
    server="https://gitlab.mycompany.com",
    api_key="glpat-xxxxxxxxxxxx"
)
result = scanner_instance.scan()
```

### Wrike Scan

```python
scanner_instance = scanner.SecretScanner(
    target="wrike_scan",
    api_key="your-wrike-permanent-token"
)
result = scanner_instance.scan()
```

### Linear Scan

```python
scanner_instance = scanner.SecretScanner(
    target="linear_scan",
    api_key="lin_api_xxxxxxxxxxxx"
)
result = scanner_instance.scan()
```

### Jira Scan

```python
# Basic scan
scanner_instance = scanner.SecretScanner(
    target="jira_scan",
    server="https://yourcompany.atlassian.net",
    email="your-email@company.com",
    api_key="ATATT3xFfGF0xxxxxxxxxxxx",
    report_format="sarif"
)
result = scanner_instance.scan()

# Scan with JQL scope
scanner_instance = scanner.SecretScanner(
    target="jira_scan",
    server="https://yourcompany.atlassian.net",
    email="your-email@company.com",
    api_key="ATATT3xFfGF0xxxxxxxxxxxx",
    scope="jql:project = SEC AND status = Open"
)
result = scanner_instance.scan()
```

### Confluence Scan

```python
# Basic scan
scanner_instance = scanner.SecretScanner(
    target="confluence_scan",
    server="https://yourcompany.atlassian.net",
    email="your-email@company.com",
    api_key="ATATT3xFfGF0xxxxxxxxxxxx",
    report_format="sarif"
)
result = scanner_instance.scan()

# Scan specific space
scanner_instance = scanner.SecretScanner(
    target="confluence_scan",
    server="https://yourcompany.atlassian.net",
    email="your-email@company.com",
    api_key="ATATT3xFfGF0xxxxxxxxxxxx",
    scope="cql:space=SEC and type=page"
)
result = scanner_instance.scan()
```

## Advanced Usage

### Reducing False Positives with the Global Allowlist

The regex configuration file (`regex.yaml`) contains a top-level `allowlist` section that suppresses findings across **all** detection rules. This is the right place to add exclusions that apply project-wide — rather than duplicating them inside every individual rule.

The three sub-keys and how they are applied:

| Key | Checked against | Suppresses when |
|---|---|---|
| `regexes` | The full text of the field being scanned | Any pattern matches |
| `stopwords` | The matched secret string only | Any stopword is a substring (case-insensitive) |
| `paths` | The file path or URL being scanned | Any pattern matches |

**Example — custom `my-regex.yaml` with project-specific exclusions:**

```yaml
# my-regex.yaml — copy regex.yaml and add your exclusions here

allowlist:
  regexes:
    # Suppress placeholder / template values
    - (?i)^x{3,}$               # xxxxx, XXXXX, …
    - (?i)^changeme$
    - (?i)^your[_-].*here$
    - '^\$\{\{[ \t]*secrets\.[A-Za-z]\w+[ \t]*}}$'  # GitHub Actions refs
  stopwords:
    - placeholder
    - example_token
  paths:
    - '(?:^|/)node_modules(?:/.*)?$'
    - '(?:^|/)vendor(?:/.*)?$'

rules:
  # ... rest of detection rules unchanged ...
```

Pass the file via `regex_file`:

```python
scanner_instance = scanner.SecretScanner(
    target="jira_scan",
    server="https://yourcompany.atlassian.net",
    email="your-email@company.com",
    api_key=os.getenv("JIRA_TOKEN"),
    regex_file="./my-regex.yaml"
)
result = scanner_instance.scan()
```

You can also call `scan_text` directly against the low-level API if you want to verify that an allowlist entry works before running a full scan:

```python
import n0s1.scanner as scanner
import yaml

with open("my-regex.yaml") as f:
    regex_config = yaml.safe_load(f)

# Should return (False, {}) — suppressed by allowlist
matched, result = scanner.scan_text(regex_config, "changeme")
print("suppressed:", not matched)
```

### Custom Regex Patterns

```python
# Create custom regex file (custom_patterns.yaml)
# patterns:
#   - name: "Company API Key"
#     regex: "COMP-[A-Z0-9]{32}"
#     severity: "high"

scanner_instance = scanner.SecretScanner(
    target="jira_scan",
    server="https://yourcompany.atlassian.net",
    email="your-email@company.com",
    api_key="your-token",
    regex_file="./custom_patterns.yaml"
)
result = scanner_instance.scan()
```

### Custom Logging

```python
import logging

def custom_logger(message, level=logging.INFO):
    """Custom logging function"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    level_name = logging.getLevelName(level)
    print(f"[{timestamp}] [{level_name}] {message}")

    # Also write to file
    with open("scan.log", "a") as f:
        f.write(f"[{timestamp}] [{level_name}] {message}\n")

scanner_instance = scanner.SecretScanner(
    target="slack_scan",
    api_key="xoxb-your-token"
)
scanner_instance.set_logging_function(custom_logger)
result = scanner_instance.scan()
```

### Dynamic Configuration

```python
# Create scanner with minimal config
scanner_instance = scanner.SecretScanner(target="jira_scan")

# Configure dynamically
scanner_instance.set(
    server="https://yourcompany.atlassian.net",
    email="your-email@company.com",
    api_key="your-token",
    debug=True,
    report_format="sarif",
    scope="jql:project = SEC"
)

# Run scan
result = scanner_instance.scan()
```

### Processing Results

```python
scanner_instance = scanner.SecretScanner(
    target="jira_scan",
    server="https://yourcompany.atlassian.net",
    email="your-email@company.com",
    api_key="your-token"
)

result = scanner_instance.scan()

# Access scan metadata
tool_info = result.get("tool", {})
print(f"Scanner: {tool_info.get('name')} v{tool_info.get('version')}")

scan_date = result.get("scan_date", {})
print(f"Scan date: {scan_date.get('date_utc')}")

# Process findings
findings = result.get("findings", {})
print(f"Total findings: {len(findings)}")

for finding_id, finding in findings.items():
    ticket_data = finding.get("ticket_data", {})
    issue_id = ticket_data.get("issue_id")
    url = ticket_data.get("url")
    field = ticket_data.get("field")

    matches = finding.get("matches", [])
    for match in matches:
        pattern_name = match.get("pattern_name")
        sanitized = match.get("sanitized_secret")
        print(f"Found {pattern_name} in {issue_id} ({field}): {sanitized}")
        print(f"  URL: {url}")
```

### Auto-Comment on Findings

```python
scanner_instance = scanner.SecretScanner(
    target="jira_scan",
    server="https://yourcompany.atlassian.net",
    email="your-email@company.com",
    api_key="your-token",
    post_comment=True,
    label="security-bot-v1",
    secret_manager="HashiCorp Vault",
    contact_help="Contact security@company.com for assistance"
)

result = scanner_instance.scan()
# Will automatically post warning comments on tickets with secrets
```

### Scoped Scanning with Map Files

```python
# Create map file (scope_map.json)
# {
#  "projects": {
#   "AS": {},
#   "DLP": {},
#   "GTMS": {},
#   "IT": {},
#   "ITSAMPLE": {},
#   "MAR": {}
#  }
# }


scanner_instance = scanner.SecretScanner(
    target="jira_scan",
    server="https://yourcompany.atlassian.net",
    email="your-email@company.com",
    api_key="your-token",
    map_file="./scope_map.json",
    scope="1/2"  # Scan first half of map
)

result = scanner_instance.scan()
```

### Multiple Platform Scanning

```python
def scan_platform(target, **kwargs):
    """Generic platform scanner"""
    scanner_instance = scanner.SecretScanner(target=target, **kwargs)
    result = scanner_instance.scan()
    return result

# Scan multiple platforms
platforms = [
    ("jira_scan", {
        "server": "https://company.atlassian.net",
        "email": "user@company.com",
        "api_key": os.getenv("JIRA_TOKEN")
    }),
    ("confluence_scan", {
        "server": "https://company.atlassian.net",
        "email": "user@company.com",
        "api_key": os.getenv("JIRA_TOKEN")
    }),
    ("slack_scan", {
        "api_key": os.getenv("SLACK_TOKEN")
    }),
    ("github_scan", {
        "owner": "myorg",
        "api_key": os.getenv("GITHUB_TOKEN")
    })
]

all_results = {}
for platform_name, config in platforms:
    print(f"Scanning {platform_name}...")
    try:
        result = scan_platform(platform_name, **config)
        all_results[platform_name] = result
        findings_count = len(result.get("findings", {}))
        print(f"  Found {findings_count} potential secrets")
    except Exception as e:
        print(f"  Error: {e}")

# Consolidate results
total_findings = sum(len(r.get("findings", {})) for r in all_results.values())
print(f"\nTotal findings across all platforms: {total_findings}")
```

### AI Analysis

AI analysis validates discovered credentials by testing them against their target services. It is **async** — the scan uploads the report, the backend generates request templates, the client executes them with real credentials, and the backend writes verdicts.

**Workflow A: scan with `--ai-analysis` flag, then analyze (blocking)**

```python
import os

n0s1_token = os.getenv("N0S1_TOKEN")

# Step 1: scan and queue analysis
scanner_instance = scanner.SecretScanner(
    target="jira_scan",
    server=os.getenv("JIRA_SERVER"),
    email=os.getenv("JIRA_EMAIL"),
    api_key=os.getenv("JIRA_TOKEN"),
    n0s1_token=n0s1_token,
    ai_analysis=True,
    report_file="report.json",
)
result = scanner_instance.scan()
report_uuid = result.get("uuid")

# Step 2: wait for completion (polls every 30 s, up to 10 minutes)
analyzer = scanner.SecretScanner(
    report_uuid=report_uuid,
    report_file="report.json",
    n0s1_token=n0s1_token,
)
status = analyzer.analyze_blocking(wait_seconds=600)
if status != "complete":
    raise RuntimeError(f"AI analysis did not complete: {status}")
```

**Workflow A (manual retry): advance one step at a time**

```python
analyzer = scanner.SecretScanner(
    report_uuid=report_uuid,
    report_file="report.json",
    n0s1_token=n0s1_token,
)
status = analyzer.analyze()
# status is "pending*" / "submitted" → call again later
# status is "complete"             → done
# status is "error" / "failed"    → raise or handle
```

**Workflow B: analyze an existing report file**

```python
scanner_instance = scanner.SecretScanner(
    report_file="report.json",
    n0s1_token=os.getenv("N0S1_TOKEN"),
)
status = scanner_instance.analyze_blocking(wait_seconds=300)
# Logs the assigned UUID; blocks until complete or timeout
```

### Error Handling

```python
import logging

try:
    scanner_instance = scanner.SecretScanner(
        target="jira_scan",
        server="https://yourcompany.atlassian.net",
        email="your-email@company.com",
        api_key="your-token",
        timeout=60,
        debug=True
    )

    result = scanner_instance.scan()

    if result:
        print(f"Scan successful: {len(result.get('findings', {}))} findings")
    else:
        print("Scan completed with no results")

except ValueError as e:
    print(f"Configuration error: {e}")
except ConnectionError as e:
    print(f"Network error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
    logging.exception("Full traceback:")
```

## MCP Tools Package

`n0s1.mcp_tools` is a transport-agnostic Python library that wraps `SecretScanner` with structured Pydantic response schemas. It is the implementation layer behind the `n0s1-mcp` stdio server, and can be embedded directly in any custom MCP transport without importing stdio or HTTP modules.

### Installation

`n0s1.mcp_tools` is included with the standard `n0s1` package:

```bash
pip install n0s1
```

Token-usage estimation requires `tiktoken` (optional — falls back to a word-count heuristic if absent):

```bash
pip install n0s1 tiktoken
```

### Basic usage

```python
from n0s1.mcp_tools import scan_jira, get_scan_findings, ToolContext

ctx = ToolContext()  # runner="DOCKER" by default
result = scan_jira(workspace_url="https://myco.atlassian.net", project_key="SEC", ctx=ctx)

print(result.status)                     # "complete" | "failed"
print(result.summary.total_findings)     # int
for finding in result.findings:
    print(finding.type, finding.redacted_match)
```

### Available tool functions

| Function | Required args | Reads credentials from |
|---|---|---|
| `scan_jira` | `workspace_url` | `JIRA_TOKEN`, `JIRA_EMAIL` |
| `scan_confluence` | `workspace_url` | `JIRA_TOKEN`, `JIRA_EMAIL` |
| `scan_github` | `repo` (`"owner/repo"` or `"owner"`) | `GITHUB_TOKEN` |
| `scan_gitlab` | `repo` (`"group/project"` or `"group"`) | `GITLAB_TOKEN` |
| `scan_slack` | _(none)_ | `SLACK_TOKEN` |
| `scan_asana` | _(none)_ | `ASANA_TOKEN` |
| `scan_wrike` | _(none)_ | `WRIKE_TOKEN` |
| `scan_linear` | _(none)_ | `LINEAR_TOKEN` |
| `scan_zendesk` | `workspace_url` | `ZENDESK_TOKEN`, `ZENDESK_EMAIL` |
| `get_scan_status` | `report_uuid` | _(none)_ |
| `get_scan_findings` | `report_uuid` | _(none)_ |

All `scan_*` functions accept `api_key` / `email` as keyword overrides. Every function also takes `ctx: ToolContext` as a required keyword argument.

### ToolContext

`ToolContext` is a dataclass injected by the transport layer. For standalone use, the defaults are sufficient:

```python
from n0s1.mcp_tools import ToolContext

ctx = ToolContext(
    user_id=None,           # SaaS user id (unused in local/stdio transport)
    token_id=None,          # API token row id (unused in local/stdio transport)
    runner="DOCKER",        # execution environment
    on_scan_event=None,     # optional callback fired after each scan_* call
)
```

The `on_scan_event` callback receives a dict with `report_uuid`, `tool_name`, `tokens_in_estimate`, `tokens_out_actual`, and `tokens_saved_estimate`.

### Response schemas

Every `scan_*` call returns a `ScanResult`:

```python
from n0s1.mcp_tools.schemas import ScanResult, Finding, ScanSummary, Usage, Severity

result: ScanResult
result.report_uuid          # str — use with get_scan_status / get_scan_findings
result.status               # "pending" | "running" | "complete" | "failed"
result.summary.total_findings   # int
result.summary.by_severity      # Dict[Severity, int]
result.summary.by_type          # Dict[str, int]
result.findings             # List[Finding] | None
result.usage.tokens_saved_estimate  # int
result.usage.savings_pct    # float
```

Each `Finding`:

```python
finding.file            # str — URL or path where the secret was found
finding.line            # int | None — line number if available
finding.type            # str — regex rule id (e.g. "aws-access-key")
finding.severity        # Severity enum: info | low | medium | high | critical
finding.redacted_match  # str — e.g. "AKIA****MPLE" or "<REDACTED:kind>"
```

`get_scan_findings` returns a `FindingsPage` with pagination:

```python
page = get_scan_findings(result.report_uuid, ctx=ctx)
page.findings       # List[Finding] — up to 50 per page
page.next_cursor    # str | None — pass as page= for the next page
page.total          # int — total across all pages

# Iterate all pages
cursor = None
while True:
    page = get_scan_findings(result.report_uuid, page=cursor, ctx=ctx)
    for finding in page.findings:
        print(finding.type, finding.redacted_match)
    if page.next_cursor is None:
        break
    cursor = page.next_cursor
```

Filter by severity:

```python
from n0s1.mcp_tools.schemas import Severity

page = get_scan_findings(result.report_uuid, severity=Severity.high, ctx=ctx)
```

### Redaction

Secret values are never stored in `Finding` objects. The `redact_match` helper is exposed for transport-layer use:

```python
from n0s1.mcp_tools.redaction import redact_match

redact_match("AKIAIOSFODNN7EXAMPLE", "aws-access-key")  # "AKIA****MPLE"
redact_match("-----BEGIN RSA PRIVATE KEY-----", "rsa-key")  # "<REDACTED:rsa-key>"
```

Rules: alphanumeric strings ≥ 16 characters show first 4 + `****` + last 4; everything else becomes `<REDACTED:kind>`.

### Submodule reference

| Submodule | Contents |
|---|---|
| `n0s1.mcp_tools.tools` | 11 tool functions |
| `n0s1.mcp_tools.schemas` | Pydantic models: `ScanResult`, `Finding`, `FindingsPage`, `ScanSummary`, `Status`, `AnalysisStatus`, `Usage`, `Severity` |
| `n0s1.mcp_tools.context` | `ToolContext` dataclass |
| `n0s1.mcp_tools.redaction` | `redact_match(raw, kind)` |
| `n0s1.mcp_tools.usage` | `usage_block(input_data, output_payload)`, `estimate_tokens(text)` |

---

## API Reference

### Report Structure

The `scan()` method returns a dictionary with the following structure:

```python
{
    "tool": {
        "name": "n0s1",
        "version": "1.1.0",
        "author": "Spark 1 Security"
    },
    "scan_date": {
        "timestamp": 1234567890.123,
        "date_utc": "2024-01-15T10:30:00"
    },
    "regex_config": {
        # Regex patterns used for scanning
    },
    "findings": {
        "finding_id_1": {
            "ticket_data": {
                "issue_id": "PROJ-123",
                "url": "https://...",
                "platform": "jira_scan",
                "field": "description"
            },
            "matches": [
                {
                    "pattern_name": "AWS Access Key",
                    "sanitized_secret": "AKIA****",
                    "line_number": 5
                }
            ]
        }
    }
}
```

### Configuration Parameters

| Parameter                     | Type | Default | Description                      |
|-------------------------------|------|---------|----------------------------------|
| `target`                      | str | None | Platform to scan (required)      |
| `api_key`                     | str | None | API token/key                    |
| `server`                      | str | None | Server URL                       |
| `email`                       | str | None | User email                       |
| `owner`                       | str | None | GitHub/GitLab owner              |
| `repo`                        | str | None | Repository name                  |
| `branch`                      | str | None | Branch name                      |
| `scan_path`                   | str | None | Local path                       |
| `regex_file`                  | str | Default | Custom regex file                |
| `config_file`                 | str | Default | Config YAML file                 |
| `report_file`                 | str | "n0s1_report.json" | Output file                      |
| `report_format`               | str | "n0s1" | Report format                    |
| `post_comment`                | bool | False | Auto-post comments               |
| `skip_comment`                | bool | False | Skip comment scanning            |
| `show_matched_secret_on_logs` | bool | False | Show secrets in reports and logs |
| `ai_analysis`                 | bool | False | AI secret leak analysis          |
| `private`                     | bool | False | Private mode                     |
| `debug`                       | bool | False | Debug mode                       |
| `secret_manager`              | str | None | Suggested secret manager         |
| `contact_help`                | str | None | Help contact                     |
| `label`                       | str | None | Bot identifier                   |
| `timeout`                     | int | None | HTTP timeout (seconds)           |
| `limit`                       | int | None | Page limit                       |
| `insecure`                    | bool | False | Ignore SSL                       |
| `map`                         | str | None | Mapping depth                    |
| `map_file`                    | str | None | Map file path                    |
| `scope`                       | str | None | Search scope/query               |
| `report_uuid`                 | str | None | UUID of an uploaded report (for `analyze()`) |
| `n0s1_token`                  | str | None | n0s1 API key; overrides `N0S1_TOKEN` env var |

## Best Practices

1. **Secure Credentials**: Never hardcode API keys. Use environment variables or secret managers.

```python
import os

scanner_instance = scanner.SecretScanner(
    target="jira_scan",
    server=os.getenv("JIRA_SERVER"),
    email=os.getenv("JIRA_EMAIL"),
    api_key=os.getenv("JIRA_TOKEN")
)
```

2. **Error Handling**: Always wrap scans in try/except blocks.

3. **Custom Logging**: Implement custom logging for production use.

4. **Scope Wisely**: Use `scope` parameter to limit scan area and improve performance.

5. **Test First**: Start with `debug=True` and `post_comment=False` to verify behavior.

6. **Rate Limiting**: Use `timeout` and `limit` parameters to avoid API rate limits.

7. **Regular Scans**: Schedule periodic scans in your CI/CD pipeline.

## Examples Repository

See `src/n0s1/test/skd_tests.py` for comprehensive examples of all platform integrations.

## Support

- **GitHub Issues**: https://github.com/spark1security/n0s1/issues
- **Documentation**: https://spark1.us/n0s1doc
- **Website**: https://spark1.us/n0s1

## License

n0s1 is licensed under the Apache License 2.0. See LICENSE file for details.

