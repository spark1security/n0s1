# n0s1 — AI Agent Reference

> This document is optimized for AI agents. It is intentionally dense and structured.
> For human-oriented guides see: README.md, SDK_GUIDE.md, USER_MANUAL.md
> For tool-use/function-calling schema see: tool-schema.json
> For the GitHub Actions interface see: https://github.com/spark1security/n0s1-action/blob/main/docs/ai.md

---

## Identity

- **Name**: n0s1 (pronounced "nosy")
- **Purpose**: Secret scanner — detects leaked credentials, tokens, and private keys across collaboration platforms and source code.
- **License**: Apache 2.0
- **Install**: `pip install n0s1`
- **Package**: `n0s1.scanner` (Python SDK), `n0s1` (CLI entrypoint)

---

## Interfaces

n0s1 exposes the same functionality through four interfaces. Choose based on context:

| Context | Interface | Invocation pattern |
|---|---|---|
| Shell / CI pipeline | CLI | `n0s1 <command> [--flag value]` |
| Containerized / no install | Docker | `docker run spark1security/n0s1 <command> [--flag value]` |
| Python script / agent code | Python SDK | `scanner.SecretScanner(target=..., **params).scan()` |
| GitHub Actions workflow | GitHub Action | `uses: spark1security/n0s1-action@main` |
| Claude Code / any MCP host | MCP server | `claude mcp add --scope user n0s1 -- uvx n0s1-mcp` |

CLI and Docker share **identical parameters** — Docker is just a containerized CLI. The SDK uses `snake_case` equivalents of the CLI flags.

---

## Supported Platforms (Scan Targets)

| `target` value | Platform | Required credentials |
|---|---|---|
| `local_scan` | Local filesystem | _(none)_ |
| `slack_scan` | Slack | `api_key` |
| `jira_scan` | Jira | `server`, `email`, `api_key` |
| `confluence_scan` | Confluence | `server`, `email`, `api_key` |
| `github_scan` | GitHub | `api_key` |
| `gitlab_scan` | GitLab | `api_key` |
| `asana_scan` | Asana | `api_key` |
| `wrike_scan` | Wrike | `api_key` |
| `linear_scan` | Linear | `api_key` |
| `zendesk_scan` | Zendesk | `server`, `email`, `api_key` |

The `analyze` command is not a scan target — it is a separate command for async AI analysis (see below).

---

## Python SDK — Canonical Usage

```python
from n0s1 import scanner

result = scanner.SecretScanner(
    target="jira_scan",        # required: scan target (see table above)
    server="https://myco.atlassian.net",
    email="user@myco.com",
    api_key="ATATT3x...",
    scope="jql:project=SEC",   # optional: filter scope
    report_format="n0s1",      # optional: "n0s1" | "sarif" | "gitlab"
    debug=False,
    post_comment=False,
).scan()

findings = result.get("findings", {})  # dict keyed by finding ID
```

### Import pattern (works installed or from source)

```python
try:
    import scanner
except ImportError:
    import n0s1.scanner as scanner
```

### SecretScanner constructor — all parameters

```python
scanner.SecretScanner(
    # Routing (required)
    target=None,               # str: platform to scan

    # Credentials (platform-dependent, see table above)
    api_key=None,              # str
    server=None,               # str: full URL or subdomain depending on platform
    email=None,                # str: user email (Jira, Confluence, Zendesk)
    owner=None,                # str: org/group (GitHub, GitLab)
    repo=None,                 # str: repository name or project path (GitHub, GitLab)
    branch=None,               # str: single branch or comma-separated list (GitHub, GitLab)
    scan_path=None,            # str: filesystem path (local_scan only)

    # Detection
    regex_file=None,           # str: path to .yaml with custom regex patterns
                               #      default: built-in config/regex.yaml

    # Configuration
    config_file=None,          # str: path to YAML config file
                               #      default: built-in config/config.yaml

    # Output
    report_file="n0s1_report.json",  # str: output file path
    report_format="n0s1",            # str: "n0s1" | "sarif" | "SARIF" | "gitlab"

    # Behavior flags
    post_comment=False,        # bool: post warning comment on tickets with leaks
    skip_comment=False,        # bool: skip scanning ticket/issue comments
    show_matched_secret_on_logs=False,  # bool: log the actual secret and add it to the report
    ai_analysis=False,         # bool: queue async AI credential validation after upload
    private=False,             # bool: disable backend interaction
    debug=False,               # bool: verbose debug logging
    insecure=False,            # bool: skip SSL certificate verification

    # Comment customization (used when post_comment=True)
    secret_manager=None,       # str: name of secret manager to recommend (e.g. "Vault")
    contact_help=None,         # str: contact info for remediation help
    label=None,                # str: unique tag so the bot can detect repeat comments

    # Network
    timeout=None,              # int: HTTP request timeout in seconds
    limit=None,                # int: max pages per HTTP request

    # Scope (advanced)
    scope=None,                # str: platform query or map chunk (see Scope section)
    map=None,                  # int: mapping depth levels (generates map file, skips scan)
    map_file=None,             # str: path to existing map file to use as scan scope

    # AI analysis
    report_uuid=None,          # str: UUID of a previously uploaded report (used by analyze())
    n0s1_token=None,           # str: n0s1 API key; overrides N0S1_TOKEN env var
)
```

### Methods

| Method | Returns | Description |
|---|---|---|
| `.scan()` | `dict` | Execute scan; returns full report |
| `.analyze()` | `None` | Submit/advance async AI analysis for a report |
| `.set(**kwargs)` | `None` | Update any constructor parameter after instantiation |
| `.get_report()` | `dict` | Get current report without running scan |
| `.get_config()` | `dict` | Get resolved configuration |
| `.get_scope_config()` | `dict\|None` | Get parsed scope configuration |
| `.set_logging_function(fn)` | `None` | Replace default logger with `fn(message, level)` |
| `.save_report()` | `None` | Write report to `report_file` |

---

## Docker — Canonical Usage

The Docker image `spark1security/n0s1` is a drop-in replacement for the CLI. Every command, flag, and parameter is identical — only the invocation prefix differs.

```bash
# Pull (optional — docker run pulls automatically)
docker pull spark1security/n0s1

# General form
docker run spark1security/n0s1 <target> [--flag value] ...

# Examples
docker run spark1security/n0s1 jira_scan \
  --server https://myco.atlassian.net \
  --email user@myco.com \
  --api-key $JIRA_TOKEN \
  --scope "jql:project=SEC" \
  --report-format sarif

docker run spark1security/n0s1 github_scan --owner myorg --api-key $GITHUB_TOKEN
docker run spark1security/n0s1 slack_scan --api-key $SLACK_TOKEN
```

### Mounting files

Use `-v` to pass local files (regex patterns, config, map files) into the container:

```bash
docker run \
  -v $(pwd)/custom.yaml:/custom.yaml \
  -v $(pwd)/reports:/reports \
  spark1security/n0s1 jira_scan \
    --server https://myco.atlassian.net \
    --email user@myco.com \
    --api-key $JIRA_TOKEN \
    --regex-file /custom.yaml \
    --report-file /reports/results.sarif \
    --report-format sarif
```

### Passing secrets securely

Prefer environment variables over inline values:

```bash
docker run \
  -e JIRA_TOKEN \
  spark1security/n0s1 jira_scan \
    --server https://myco.atlassian.net \
    --email user@myco.com \
    --api-key $JIRA_TOKEN
```

### GitLab CI example

```yaml
jira-scan:
  stage: test
  image:
    name: spark1security/n0s1
    entrypoint: [""]
  script:
    - n0s1 jira_scan
        --server https://myco.atlassian.net
        --email $JIRA_EMAIL
        --api-key $JIRA_TOKEN
        --report-file gl-dast-report.json
        --report-format gitlab
  artifacts:
    reports:
      dast:
        - gl-dast-report.json
```

> **When to prefer Docker over CLI**: no Python environment available; reproducible pinned version; containerized CI (e.g. GitLab CI, Jenkins); air-gapped environments.

---

## CLI — Canonical Usage

```bash
# Install
pip install n0s1

# General form
n0s1 <target> [--flag value] ...

# Examples
n0s1 jira_scan \
  --server https://myco.atlassian.net \
  --email user@myco.com \
  --api-key $JIRA_TOKEN \
  --scope "jql:project=SEC" \
  --report-file results.json \
  --report-format sarif

n0s1 github_scan --owner myorg --api-key $GITHUB_TOKEN
n0s1 local_scan --path ./src --regex-file ./custom.yaml
```

### CLI flag → SDK parameter mapping

| CLI flag                        | SDK parameter                 | Notes |
|---------------------------------|-------------------------------|---|
| `--api-key`                     | `api_key`                     | |
| `--server`                      | `server`                      | |
| `--email`                       | `email`                       | |
| `--owner`                       | `owner`                       | |
| `--repo`                        | `repo`                        | |
| `--branch`                      | `branch`                      | |
| `--path`                        | `scan_path`                   | local_scan only |
| `--regex-file`                  | `regex_file`                  | |
| `--config-file`                 | `config_file`                 | |
| `--report-file`                 | `report_file`                 | |
| `--report-format`               | `report_format`               | |
| `--post-comment`                | `post_comment`                | boolean flag (no value) |
| `--skip-comment`                | `skip_comment`                | boolean flag (no value) |
| `--show-matched-secret-on-logs` | `show_matched_secret_on_logs` | boolean flag |
| `--ai-analysis`                 | `ai_analysis`                 | boolean flag |
| `--private`                     | `private`                     | boolean flag |
| `--debug`                       | `debug`                       | boolean flag |
| `--insecure`                    | `insecure`                    | boolean flag |
| `--secret-manager`              | `secret_manager`              | |
| `--contact-help`                | `contact_help`                | |
| `--label`                       | `label`                       | |
| `--timeout`                     | `timeout`                     | int as string in CLI |
| `--limit`                       | `limit`                       | int as string in CLI |
| `--scope`                       | `scope`                       | |
| `--map`                         | `map`                         | int as string in CLI |
| `--map-file`                    | `map_file`                    | |
| `--n0s1-api-key`                | `n0s1_token`                  | overrides `N0S1_TOKEN` env var |
| `--report-uuid`                 | `report_uuid`                 | `analyze` command only |

---

## Scope Query Language

The `scope` parameter filters what gets scanned. Prefix determines the query language:

| Prefix | Platform | Example |
|---|---|---|
| `jql:` | Jira | `jql:project=SEC AND status=Open` |
| `cql:` | Confluence | `cql:space=SEC and type=page` |
| `search:` | GitHub / GitLab | `search:org:myorg action in:name` |
| _(none / fraction)_ | Map file chunk | `3/4` (scan the third quarter of a map file) |

### Map-based scoping workflow

```python
# Step 1: generate a map of the platform's structure
scanner.SecretScanner(target="jira_scan", server=..., email=..., api_key=...,
                      map=2, map_file="n0s1_map.json").scan()
# → writes n0s1_map.json, does NOT scan

# Step 2: scan using a chunk of the map (useful for parallelism)
scanner.SecretScanner(target="jira_scan", server=..., email=..., api_key=...,
                      map_file="n0s1_map.json", scope="1/4").scan()  # first quarter
scanner.SecretScanner(target="jira_scan", server=..., email=..., api_key=...,
                      map_file="n0s1_map.json", scope="2/4").scan()  # second quarter
```

---

## Return Value Schema

`scan()` returns a `dict` with this structure:

```python
{
    "tool": {
        "name": "n0s1",
        "version": "1.x.x",
        "author": "Spark 1 Security"
    },
    "scan_date": {
        "timestamp": 1234567890.123,   # Unix timestamp (float)
        "date_utc": "2024-01-15T10:30:00"
    },
    "regex_config": { ... },           # Regex patterns used in this scan
    "findings": {
        "<finding_id>": {              # SHA-based unique ID per finding
            "ticket_data": {
                "issue_id": "PROJ-123",
                "url": "https://...",
                "platform": "jira_scan",
                "field": "description"  # where the leak was found
            },
            "matches": [
                {
                    "pattern_name": "AWS Access Key",
                    "sanitized_secret": "AKIA****EXAMPLE",  # redacted by default
                    "line_number": 5
                }
            ]
        }
    }
}
```

### Accessing findings

```python
result = scanner_instance.scan()
findings = result.get("findings", {})        # dict
finding_count = len(findings)                # int

for finding_id, finding in findings.items():
    issue_id  = finding["ticket_data"]["issue_id"]
    url       = finding["ticket_data"]["url"]
    field     = finding["ticket_data"]["field"]
    for match in finding["matches"]:
        pattern = match["pattern_name"]
        secret  = match["sanitized_secret"]
```

---

## What n0s1 Detects (Default Patterns)

Defined in `src/n0s1/config/regex.yaml` / `regex.toml`. Built-in patterns include:

- GitHub Personal Access Tokens
- GitLab Personal Access Tokens
- AWS Access Keys / Secret Keys
- RSA / SSH / PKCS8 private keys
- npm access tokens

Custom patterns can be added via `--regex-file` / `regex_file` using the same YAML/TOML format.

---

## Platform-Specific Notes

### Jira / Confluence (Atlassian Cloud)
- `server`: full URL, e.g. `https://mycompany.atlassian.net`
- `api_key`: Atlassian API token (same token works for both Jira and Confluence)
- Jira scope uses JQL: `jql:project=SEC AND status != Done`
- Confluence scope uses CQL: `cql:space=ENG and type=page`

### GitHub
- `branch`: accepts comma-separated list, e.g. `"main,develop,release"`
- `owner` + `repo` are optional; omitting scans all accessible repos
- `scope` supports GitHub search syntax: `search:org:myorg language:python`

### GitLab
- `server`: defaults to `https://gitlab.com`; set for self-hosted instances
- `repo`: accepts project ID (integer) or path with namespace (`group/project`)
- `scope`: `search:<query>` prefix

### Zendesk
- `server`: subdomain only (e.g. `"mycompany"` → `mycompany.zendesk.com`)

### Local filesystem
- SDK parameter is `scan_path`; CLI flag is `--path`

---

## Common Agent Workflows

### 1. Scan and report findings

```python
from n0s1 import scanner, os

result = scanner.SecretScanner(
    target="jira_scan",
    server=os.getenv("JIRA_SERVER"),
    email=os.getenv("JIRA_EMAIL"),
    api_key=os.getenv("JIRA_TOKEN"),
).scan()

for fid, f in result.get("findings", {}).items():
    print(f"{f['ticket_data']['issue_id']} — {f['matches'][0]['pattern_name']}")
```

### 2. Scan and auto-comment on leaks

```python
scanner.SecretScanner(
    target="jira_scan",
    server=os.getenv("JIRA_SERVER"),
    email=os.getenv("JIRA_EMAIL"),
    api_key=os.getenv("JIRA_TOKEN"),
    post_comment=True,
    label="security-bot-v1",           # prevents duplicate comments
    secret_manager="HashiCorp Vault",
    contact_help="security@myco.com",
).scan()
```

### 3. Scan multiple platforms

```python
platforms = [
    dict(target="jira_scan", server=os.getenv("JIRA_SERVER"),
         email=os.getenv("JIRA_EMAIL"), api_key=os.getenv("JIRA_TOKEN")),
    dict(target="slack_scan", api_key=os.getenv("SLACK_TOKEN")),
    dict(target="github_scan", owner="myorg", api_key=os.getenv("GITHUB_TOKEN")),
]

all_findings = {}
for params in platforms:
    result = scanner.SecretScanner(**params).scan()
    all_findings.update(result.get("findings", {}))

print(f"Total: {len(all_findings)} findings")
```

### 4. Save report in SARIF format (for CI integration)

```python
scanner.SecretScanner(
    target="github_scan",
    owner="myorg",
    api_key=os.getenv("GITHUB_TOKEN"),
    report_file="results.sarif",
    report_format="sarif",
).scan()
```

### 5. AI credential validation

```python
import os
from n0s1 import scanner

n0s1_token = os.getenv("N0S1_TOKEN")

# Step 1: scan and queue AI analysis
s = scanner.SecretScanner(
    target="jira_scan",
    server=os.getenv("JIRA_SERVER"),
    email=os.getenv("JIRA_EMAIL"),
    api_key=os.getenv("JIRA_TOKEN"),
    n0s1_token=n0s1_token,
    ai_analysis=True,
    report_file="report.json",
)
result = s.scan()
report_uuid = result.get("uuid")
# Logs: "AI analysis queued. Run: n0s1 analyze --report-uuid <uuid>"

# Step 2: advance analysis — re-run until log prints "AI analysis complete"
analyzer = scanner.SecretScanner(
    report_uuid=report_uuid,
    report_file="report.json",
    n0s1_token=n0s1_token,
)
analyzer.analyze()
```

The `analyze()` call is idempotent — the state machine advances exactly one step per call:
- `pending` → waits (backend generating request templates)
- `waiting_client` → executes HTTP validators, re-uploads, exits
- `pending_verdict` → waits (backend computing verdicts)
- `complete` → saves updated report to `report_file` and logs completion
- `failed` → logs failure

### 6. Parallel scanning using map files

```python
import json, subprocess

# Generate map
scanner.SecretScanner(
    target="jira_scan", server=..., email=..., api_key=...,
    map=2, map_file="map.json"
).scan()

# Scan in parallel chunks (e.g., spawn 4 processes)
for i in range(1, 5):
    scanner.SecretScanner(
        target="jira_scan", server=..., email=..., api_key=...,
        map_file="map.json", scope=f"{i}/4"
    ).scan()
```

---

## Environment Variables (Conventional)

The SDK does not read env vars automatically for platform credentials. Load them explicitly. `N0S1_TOKEN` is the one exception — it is read automatically by `analyze()` and during Professional-mode scan uploads when `n0s1_token` is not set on the instance.

| Variable | Used for |
|---|---|
| `N0S1_TOKEN` | n0s1 API key — Professional mode uploads and AI analysis |
| `JIRA_TOKEN` | Jira / Confluence API key |
| `JIRA_SERVER` | Jira / Confluence server URL |
| `JIRA_EMAIL` | Jira / Confluence user email |
| `SLACK_TOKEN` | Slack OAuth token |
| `GITHUB_TOKEN` | GitHub access token |
| `GITLAB_TOKEN` | GitLab personal access token |
| `ASANA_TOKEN` | Asana personal access token |
| `LINEAR_TOKEN` | Linear API key |
| `WRIKE_TOKEN` | Wrike permanent token |
| `ZENDESK_TOKEN` | Zendesk API key |
| `ZENDESK_EMAIL` | Zendesk user email |
| `ZENDESK_SERVER` | Zendesk subdomain |

---

## GitHub Actions Interface

n0s1 is also available as a GitHub Action at `spark1security/n0s1-action`.
Full AI-optimized documentation: https://github.com/spark1security/n0s1-action/blob/main/docs/ai.md

### When to use it
Choose the GitHub Actions interface when the agent is generating `.github/workflows/*.yml` files or integrating n0s1 into a CI/CD pipeline. For scripting or programmatic use, prefer the CLI or Python SDK.

### Minimal workflow example

```yaml
jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: spark1security/n0s1-action@main
        env:
          JIRA_TOKEN: ${{ secrets.JIRA_TOKEN }}
        with:
          scan-target: jira_scan
          password-key: ${{ secrets.JIRA_TOKEN }}
          platform-url: https://mycompany.atlassian.net
          user-email: service@mycompany.com
```

### Input → CLI/SDK parameter mapping (key differences)

| Action input | CLI flag | SDK parameter |
|---|---|---|
| `scan-target` | _(subcommand)_ | `target` |
| `password-key` | `--api-key` | `api_key` |
| `platform-url` | `--server` | `server` |
| `user-email` | `--email` | `email` |
| `post-comment` | `--post-comment` | `post_comment` |
| `skip-comment` | `--skip-comment` | `skip_comment` |
| `report-format` | `--report-format` | `report_format` |
| `show-matched-secret-on-logs` | `--show-matched-secret-on-logs` | `show_matched_secret_on_logs` |

All other inputs (`regex-file`, `config-file`, `report-file`, `secret-manager`, `contact-help`, `label`, `timeout`, `limit`, `insecure`, `map`, `map-file`, `scope`, `owner`, `repo`, `branch`) match their CLI equivalents exactly.

**Required inputs**: `scan-target`, `password-key`

---

## MCP Server

n0s1 is available as an MCP (Model Context Protocol) server, letting any MCP-compatible host (Claude Code, Claude Desktop, etc.) invoke scans as native tool calls — no CLI knowledge required.

The MCP implementation is split into two layers:
- **`n0s1.mcp_tools`** — transport-agnostic Python package with all 12 tool functions and Pydantic response schemas. Can be embedded directly in any Python MCP transport.
- **`n0s1-mcp`** — stdio transport that exposes the tools to Claude Code / Claude Desktop.

### Register with Claude Code

```bash
claude mcp add --scope user n0s1 -- uvx n0s1-mcp
```

This registers the server at user scope so it is available across all projects. Replace `--scope user` with `--scope project` to restrict it to the current project.

### Credentials

Tools read credentials from environment variables by default. Passing `api_key` / `email` directly is supported for backwards compatibility but env vars are preferred.

| Env var | Used by |
|---|---|
| `JIRA_TOKEN` | `scan_jira`, `scan_confluence` |
| `JIRA_EMAIL` | `scan_jira`, `scan_confluence` |
| `SLACK_TOKEN` | `scan_slack` |
| `GITHUB_TOKEN` | `scan_github` |
| `GITLAB_TOKEN` | `scan_gitlab` |
| `ASANA_TOKEN` | `scan_asana` |
| `WRIKE_TOKEN` | `scan_wrike` |
| `LINEAR_TOKEN` | `scan_linear` |
| `ZENDESK_TOKEN` | `scan_zendesk` |
| `ZENDESK_EMAIL` | `scan_zendesk` |

### Available tools

| Tool | Required parameters | Description |
|---|---|---|
| `scan_jira` | `workspace_url` | Scan a Jira workspace for leaked secrets |
| `scan_confluence` | `workspace_url` | Scan a Confluence workspace for leaked secrets |
| `scan_github` | `repo` (`"owner/repo"` or `"owner"`) | Scan a GitHub repository or all repos for an org |
| `scan_gitlab` | `repo` (`"group/project"` or `"group"`) | Scan a GitLab project or all projects in a group |
| `scan_slack` | _(none — uses `SLACK_TOKEN`)_ | Scan a Slack workspace for leaked secrets |
| `scan_asana` | _(none — uses `ASANA_TOKEN`)_ | Scan an Asana workspace for leaked secrets |
| `scan_wrike` | _(none — uses `WRIKE_TOKEN`)_ | Scan a Wrike workspace for leaked secrets |
| `scan_linear` | _(none — uses `LINEAR_TOKEN`)_ | Scan a Linear workspace for leaked secrets |
| `scan_zendesk` | `workspace_url` | Scan a Zendesk workspace for leaked secrets |
| `get_scan_status` | `report_uuid` | Check the status of a previous scan (includes `ai_analysis_status`) |
| `get_scan_findings` | `report_uuid` | Retrieve paginated findings for a completed scan |
| `analyze_report` | `report_uuid` | Submit or advance async AI analysis for an uploaded report |

### Common optional parameters (all `scan_*` tools)

| Parameter | Type | Default | Description |
|---|---|---|---|
| `report_format` | `"n0s1"` \| `"sarif"` \| `"gitlab"` | `"n0s1"` | Output format |
| `show_matched_secret_on_logs` | bool | `false` | Include raw secret values in output |
| `since` | str | — | ISO date; restrict scan to content created after this date |
| `api_key` | str | — | Override the env-var credential |
| `ai_analysis` | bool | `false` | Queue async AI credential validation after upload (requires `n0s1_token`) |
| `n0s1_token` | str | — | n0s1 API key; overrides `N0S1_TOKEN` env var |

### Per-tool optional parameters

| Tool | Optional parameters |
|---|---|
| `scan_jira` | `project_key` (filter by project), `since`, `scope` (raw JQL, e.g. `jql:project=SEC AND status=Open`) |
| `scan_confluence` | `space_key` (filter by space), `since`, `scope` (raw CQL, e.g. `cql:space=SEC and type=page`) |
| `scan_github` | `branch`, `scope` (GitHub search syntax, e.g. `search:org:myorg`) |
| `scan_gitlab` | `server` (default: `https://gitlab.com`), `branch`, `scope` |
| `scan_slack` | `workspace_url` (traceability only), `channel` (filter by channel name), `since` |
| `scan_asana` | `workspace_url` (traceability only), `project` (filter), `since`, `scope` |
| `scan_wrike` | `workspace_url` (traceability only), `since`, `scope` |
| `scan_linear` | `workspace_url` (traceability only), `team` (filter by team name), `since` |
| `scan_zendesk` | `since`, `email` (override env var) |
| `get_scan_findings` | `page` (opaque cursor from previous `FindingsPage.next_cursor`), `severity` (filter: `info`\|`low`\|`medium`\|`high`\|`critical`) |

### Return value schema

Every `scan_*` tool returns a `ScanResult`:

```python
{
    "report_uuid": "3f8a...",          # use with get_scan_status / get_scan_findings
    "status": "complete",              # "pending" | "running" | "complete" | "failed"
    "summary": {
        "total_findings": 3,
        "by_severity": {"high": 3},
        "by_type": {"aws-access-key": 2, "github-pat": 1}
    },
    "findings": [                      # first page of results
        {
            "file": "https://...",     # URL or path where the secret was found
            "line": 42,                # line number (null if not applicable)
            "type": "aws-access-key",  # regex rule id
            "severity": "high",
            "redacted_match": "AKIA****MPLE"  # first 4 + last 4 chars; or <REDACTED:kind>
        }
    ],
    "usage": {
        "tokens_in_estimate": 5000,
        "tokens_out_actual": 200,
        "tokens_saved_estimate": 4800,
        "savings_pct": 96.0
    }
}
```

`get_scan_status` returns a lightweight `Status`:

```python
{"report_uuid": "...", "status": "complete", "progress_pct": 100.0, "error": null}
```

`get_scan_findings` returns a `FindingsPage` (paginated, 50 findings per page):

```python
{
    "report_uuid": "...",
    "findings": [...],
    "next_cursor": "<opaque string>",  # null when on the last page
    "total": 150,
    "usage": {...}
}
```

### Python package (`n0s1.mcp_tools`)

The `mcp_tools` package is transport-agnostic and can be embedded in any Python MCP transport without importing the stdio or HTTP layers:

```python
from n0s1.mcp_tools import scan_jira, get_scan_findings, ToolContext

ctx = ToolContext()  # runner="DOCKER" by default
result = scan_jira(workspace_url="https://myco.atlassian.net", project_key="SEC", ctx=ctx)
page = get_scan_findings(result.report_uuid, ctx=ctx)
for finding in page.findings:
    print(finding.type, finding.redacted_match)
```

Key submodules:

| Submodule | Contents |
|---|---|
| `n0s1.mcp_tools.tools` | 12 tool functions |
| `n0s1.mcp_tools.schemas` | Pydantic models: `ScanResult`, `Finding`, `FindingsPage`, `ScanSummary`, `Status`, `AnalysisStatus`, `Usage`, `Severity` |
| `n0s1.mcp_tools.context` | `ToolContext` dataclass (injected by transport layer) |
| `n0s1.mcp_tools.redaction` | `redact_match(raw, kind)` — produces `AKIA****MPLE` or `<REDACTED:kind>` |
| `n0s1.mcp_tools.usage` | `usage_block(input_data, output_payload)` — token-savings estimation via cl100k_base |

### When to use MCP over other interfaces

- You are already inside an MCP-enabled host (Claude Code, Claude Desktop) and want to trigger scans without leaving the conversation.
- You want the host model to decide which platforms to scan and interpret results directly.
- You are building an agentic workflow where scan results feed into downstream tool calls in the same session.

For scripted or automated use (CI, cron jobs, batch pipelines) prefer the CLI or Python SDK — they give finer-grained control over output files, parallelism, and error handling.

---

## Machine-Readable Schema

A complete tool-use / function-calling schema (compatible with Anthropic and OpenAI APIs) is available at:

```
tool-schema.json
```

Load it to give an AI agent the ability to invoke n0s1 scans as structured tool calls:

```python
import anthropic, json

with open("tool-schema.json") as f:
    tools = json.load(f)["tools"]

client = anthropic.Anthropic()
response = client.messages.create(
    model="claude-opus-4-6",
    tools=tools,
    messages=[{"role": "user", "content": "Scan my Jira for leaked secrets"}]
)
```

---

## Key Files

| File | Purpose |
|---|---|
| `src/n0s1/scanner.py` | Python SDK — `SecretScanner` class |
| `src/n0s1/n0s1.py` | CLI entrypoint — `init_argparse()`, `main()` |
| `src/n0s1/config/regex.yaml` | Default secret detection patterns |
| `src/n0s1/config/config.yaml` | Default configuration |
| `tests/integration/skd_tests.py` | SDK integration tests for all platforms and the `analyze` command |
| `src/n0s1/mcp_tools/__init__.py` | MCP tools package — public API surface |
| `src/n0s1/mcp_tools/tools.py` | 11 transport-agnostic tool functions |
| `src/n0s1/mcp_tools/schemas.py` | Pydantic models for all MCP responses |
| `src/n0s1/mcp_tools/context.py` | `ToolContext` dataclass |
| `src/n0s1/mcp_tools/redaction.py` | Secret redaction helpers |
| `src/n0s1/mcp_tools/usage.py` | Token-usage estimation (cl100k_base) |
| `tool-schema.json` | Tool-use schema for AI agents |
| `SDK_GUIDE.md` | Human-oriented SDK documentation |
| `USER_MANUAL.md` | Human-oriented CLI documentation |
