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
    ai_analysis=False,         # bool: Allow AI agent to verify leaks
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
)
```

### Methods

| Method | Returns | Description |
|---|---|---|
| `.scan()` | `dict` | Execute scan; returns full report |
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

### 5. Parallel scanning using map files

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

The SDK does not read env vars automatically. Load them explicitly:

| Variable | Used for |
|---|---|
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

### Register with Claude Code

```bash
claude mcp add --scope user n0s1 -- uvx n0s1-mcp
```

This registers the server at user scope so it is available across all projects. Replace `--scope user` with `--scope project` to restrict it to the current project.

### Available tools

| Tool | Platform | Required parameters |
|---|---|---|
| `scan_jira` | Jira | `server`, `email`, `api_key` |
| `scan_confluence` | Confluence | `server`, `email`, `api_key` |
| `scan_github` | GitHub | `api_key`, `owner` |
| `scan_gitlab` | GitLab | `api_key`, `owner` |
| `scan_slack` | Slack | `api_key` |
| `scan_asana` | Asana | `api_key` |
| `scan_wrike` | Wrike | `api_key` |
| `scan_linear` | Linear | `api_key` |
| `scan_zendesk` | Zendesk | `server`, `email`, `api_key` |
| `scan_local` | Local filesystem | `scan_path` |

### Common parameters (all tools)

| Parameter | Type | Default | Description |
|---|---|---|---|
| `report_format` | `"n0s1"` \| `"sarif"` \| `"gitlab"` | `"n0s1"` | Output format |
| `show_matched_secret_on_logs` | bool | `false` | Include raw secret values in output |

### Per-tool optional parameters

| Tool | Optional parameters |
|---|---|
| `scan_jira` | `scope` (JQL, e.g. `jql:project=SEC`), `post_comment` |
| `scan_confluence` | `scope` (CQL, e.g. `cql:space=SEC and type=page`) |
| `scan_github` | `repo`, `branch`, `scope` (GitHub search syntax) |
| `scan_gitlab` | `server` (default: `https://gitlab.com`), `repo`, `branch` |
| `scan_asana` | `scope` (workspace or project filter) |
| `scan_wrike` | `scope` (folder or space filter) |
| `scan_local` | `regex_file` (path to custom YAML pattern file) |

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
| `src/n0s1/test/skd_tests.py` | SDK usage examples for all platforms |
| `tool-schema.json` | Tool-use schema for AI agents |
| `SDK_GUIDE.md` | Human-oriented SDK documentation |
| `USER_MANUAL.md` | Human-oriented CLI documentation |
