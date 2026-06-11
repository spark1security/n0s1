# n0s1 User Manual

Complete guide for using the n0s1 secret scanner tool.

## Table of Contents
- [Overview](#overview)
- [Basic Usage](#basic-usage)
- [Global Options](#global-options)
- [Platform Commands](#platform-commands)
- [AI Analysis](#ai-analysis)
- [Advanced Features](#advanced-features)
  - [Reducing False Positives](#reducing-false-positives)
  - [MCP Server](#mcp-server)
    - [Available MCP Tools](#available-mcp-tools)
    - [analyze_report tool reference](#analyze_report-tool-reference)
    - [AI analysis workflow via MCP](#ai-analysis-workflow-via-mcp)
- [Examples](#examples)

## Overview

n0s1 is a command-line tool for scanning various platforms for leaked secrets. The basic syntax is:

```bash
n0s1 [GLOBAL_OPTIONS] COMMAND [COMMAND_OPTIONS]
```

To display version information:
```bash
n0s1 --version
```

n0s1 is also available as an **MCP server** for Claude Code and Claude Desktop users, letting you trigger scans directly from a conversation without touching the CLI. See [MCP Server](#mcp-server) in Advanced Features.

## Basic Usage

All commands follow this pattern:
```bash
n0s1 [global options] <platform>_scan [platform-specific options]
```

## Global Options

These options work with all scan commands and should be specified **before** the command name.

### Configuration Files

**`--regex-file <path>`**
- Specify a custom .yaml or .toml file containing regex patterns for secret detection
- Use this to customize what patterns are considered secrets
- Example: `--regex-file /path/to/custom-regex.yaml`

**`--config-file <path>`**
- Specify a YAML configuration file for the scanner
- Example: `--config-file /path/to/config.yaml`

### Report Generation

**`--report-file <path>`**
- Specify where to save the scan results
- Example: `--report-file ./scan-results.json`

**`--report-format <format>`**
- Choose output format: `n0s1`, `SARIF`, or `gitlab`
- Default: n0s1 format
- Example: `--report-format SARIF`

**`--report-uuid <uuid>`**
- Assign a specific UUID to the scan report. When set, this value is written to the `uuid` field in the report JSON instead of the auto-generated one.
- Also used with the `analyze` command to identify a previously uploaded report for AI analysis.
- Example: `--report-uuid 3f8a1b2c-4d5e-6f7a-8b9c-0d1e2f3a4b5c`

### Scanning Behavior

**`--post-comment`**
- Automatically post warning comments on tickets/issues with detected secrets
- Default: only flags secrets without posting comments
- ⚠️ Use carefully as this modifies the target platform

**`--skip-comment`**
- Skip scanning comments, only scan titles and descriptions
- Default: scans titles, descriptions, AND comments
- Useful for faster scans when comments are not a concern

**`--show-matched-secret-on-logs`**
- Display actual secret values in logs instead of sanitized versions
- ⚠️ **DANGER**: This may expose secrets in your logs - use with extreme caution
- Default: shows sanitized versions only

**`--ai-analysis`**
- Queue AI analysis after the scan completes. The AI agent validates each leaked credential and updates the report with a verdict: live (authentication succeeded), unable to test, or invalid.
- Analysis is **asynchronous** by default — the scan exits after uploading the report and prints the UUID. Run `n0s1 analyze --report-uuid <uuid>` to advance the analysis, or add `--wait` to block until completion.
- ⚠️ The leaked credentials identified by the scanner will be tested live. If you are not authorized to test the credentials, do not enable this mode.
- Requires a valid n0s1 API key (see `--n0s1-api-key`). Only supported in Professional mode.

**`--allow-secret-upload`**
- Allow encrypted secrets to be uploaded to the n0s1 backend during AI analysis.
- Default: disabled. When disabled, credentials stay on the client and are injected locally during the `waiting_client` step (requires `--report-file`).
- When enabled, the encrypted credentials are sent to the backend so the `analyze` command can operate with `--report-uuid` alone (no local report file needed).
- ⚠️ Even when enabled, secrets are encrypted before upload. Enable only if your security policy permits sending encrypted credentials to a third-party service.

**`--wait [MINUTES]`**
- When used with `--ai-analysis`, block until AI analysis completes or `MINUTES` elapse (default 30 when `--wait` is given without a value).
- Polls the backend every 30 seconds and logs progress. Useful for CI/CD pipelines that cannot implement their own retry loop.
- Exits 0 on success, 1 on error/timeout, 2 if still pending.

**`--n0s1-api-key <key>`**
- n0s1 API key for Professional mode (uploading reports, running AI analysis).
- Overrides the `N0S1_TOKEN` environment variable when both are set.
- Visit [n0s1.spark1.us](https://n0s1.spark1.us) to issue a token.

**`--private`**
- Enable private mode to disable all interaction with the n0s1 backend service
- ⚠️ Authentication required for Professional mode is turned off when Private mode is enabled
- Only Community mode is supported in this configuration

**`--debug`**
- Enable debug mode for verbose logging
- ⚠️ May expose sensitive data in logs
- Useful for troubleshooting

### Customization Options

**`--secret-manager <name>`**
- Specify a secret manager tool name to suggest in warnings
- Example: `--secret-manager "HashiCorp Vault"`
- Helps guide users to proper secret storage solutions

**`--contact-help <info>`**
- Provide contact information for security team or help desk
- Example: `--contact-help "security@company.com"`
- Displayed when secrets are detected

**`--label <identifier>`**
- Unique identifier for n0s1 bot comments
- Helps the tool recognize previously flagged secrets
- Example: `--label "n0s1-bot-v1"`

### Network & Performance

**`--timeout <seconds>`**
- Set HTTP request timeout in seconds
- Example: `--timeout 30`
- Useful for slow networks or large datasets

**`--limit <number>`**
- Limit the number of pages returned per HTTP request
- Example: `--limit 100`
- Helps control API rate limits

**`--insecure`**
- Disable SSL certificate verification
- ⚠️ **SECURITY RISK**: Only use in controlled environments
- Useful for self-signed certificates in testing

### Scope & Mapping

**`--map <levels>`**
- Enable mapping mode and specify depth levels
- Example: `--map 3`
- Default: Disabled

**`--map-file <path>`**
- Path to a map file (e.g., n0s1_map.json) for custom scan scope
- Example: `--map-file ./scope-map.json`
- Allows fine-grained control over what gets scanned

**`--scope <query>`**
- Define search query to limit scan scope
- Platform-specific syntax:
  - **GitHub**: `"search:org:myorg action in:name"`
  - **Jira**: `"jql:project != IT"`
  - **With --map-file**: Chunk specification like `"3/4"` (scans third quarter of map)
- Example: `--scope "jql:project = SECURITY"`

## Platform Commands

### 1. Local Filesystem Scan

Scan local files and directories for secrets.

```bash
n0s1 local_scan --path <path>
```

**Options:**
- `--path <path>` - Path to file or directory to scan

**Example:**
```bash
n0s1 local_scan --path /home/user/projects --report-file local-scan.json
```

### 2. Slack Scan

Scan Slack workspace messages for leaked secrets.

```bash
n0s1 slack_scan --api-key <token>
```

**Options:**
- `--api-key <token>` - Slack OAuth token with scopes: `search:read`, `users:read`, `chat:write`

**Getting API Key:**
- Visit: https://api.slack.com/tutorials/tracks/getting-a-token
- Create an app and request required OAuth scopes

**Example:**
```bash
n0s1 slack_scan --api-key xoxb-your-token-here --report-file slack-results.json
```

### 3. Asana Scan

Scan Asana tasks and projects for secrets.

```bash
n0s1 asana_scan --api-key <token>
```

**Options:**
- `--api-key <token>` - Asana Personal Access Token (PAT)

**Getting API Key:**
- Visit: https://developers.asana.com/docs/personal-access-token#generating-a-pat
- Generate a Personal Access Token from your Asana account settings

**Example:**
```bash
n0s1 asana_scan --api-key 1/1234567890abcdef --report-file asana-results.json
```

### 4. Zendesk Scan

Scan Zendesk support tickets for leaked secrets.

```bash
n0s1 zendesk_scan --server <subdomain> --email <email> --api-key <key>
```

**Options:**
- `--server <subdomain>` - Your Zendesk subdomain (e.g., `mycompany` for mycompany.zendesk.com)
- `--email <email>` - Zendesk user email address
- `--api-key <key>` - Zendesk API key

**Getting API Key:**
- Visit: https://developer.zendesk.com/api-reference/integration-services/connections/api_key_connections
- Generate API key from Admin Center → Apps and integrations → APIs → Zendesk API

**Example:**
```bash
n0s1 zendesk_scan --server mycompany --email admin@company.com --api-key abc123xyz --report-file zendesk-results.json
```

### 5. GitHub Scan

Scan GitHub repositories for secrets in code, issues, and pull requests.

```bash
n0s1 github_scan --owner <org> --repo <repository> --api-key <token>
```

**Options:**
- `--owner <org>` - GitHub organization or user name (not case-sensitive)
- `--repo <repository>` - Repository name without .git extension (not case-sensitive)
- `--branch <branch>` - Specific branch to scan (optional; scans all branches if omitted)
- `--api-key <token>` - GitHub Personal Access Token or App token

**Getting API Key:**
- Visit: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app
- Or create a classic Personal Access Token with appropriate scopes

**Examples:**
```bash
# Scan specific repository
n0s1 github_scan --owner myorg --repo myrepo --api-key ghp_xxxxxxxxxxxx

# Scan specific branch
n0s1 github_scan --owner myorg --repo myrepo --branch main --api-key ghp_xxxxxxxxxxxx

# Scan with scope filter
n0s1 github_scan --api-key ghp_xxxxxxxxxxxx --scope "search:org:myorg action in:name"
```

### 6. GitLab Scan

Scan GitLab repositories for secrets.

```bash
n0s1 gitlab_scan --server <url> --owner <group> --repo <project> --api-key <token>
```

**Options:**
- `--server <url>` - GitLab instance URL (defaults to https://gitlab.com)
- `--owner <group>` - GitLab group name (optional; scans all accessible projects if omitted)
- `--repo <project>` - Project ID or path with namespace (optional)
- `--branch <branch>` - Specific branch to scan (optional; scans all branches if omitted)
- `--api-key <token>` - GitLab Personal Access Token

**Getting API Key:**
- Visit: https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html
- Create a Personal Access Token with `read_api` and `read_repository` scopes

**Examples:**
```bash
# Scan GitLab.com repository
n0s1 gitlab_scan --owner mygroup --repo myproject --api-key glpat-xxxxxxxxxxxx

# Scan self-hosted GitLab
n0s1 gitlab_scan --server https://gitlab.mycompany.com --owner mygroup --api-key glpat-xxxxxxxxxxxx

# Scan all accessible projects
n0s1 gitlab_scan --api-key glpat-xxxxxxxxxxxx
```

### 7. Wrike Scan

Scan Wrike tasks and projects for secrets.

```bash
n0s1 wrike_scan --api-key <token>
```

**Options:**
- `--api-key <token>` - Wrike permanent access token

**Getting API Key:**
- Visit: https://help.wrike.com/hc/en-us/articles/210409445-Wrike-API
- Generate a permanent token from Apps & Integrations → API → Create token

**Example:**
```bash
n0s1 wrike_scan --api-key your-wrike-token --report-file wrike-results.json
```

### 8. Linear Scan

Scan Linear issues and projects for secrets.

```bash
n0s1 linear_scan --api-key <token>
```

**Options:**
- `--api-key <token>` - Linear API key

**Getting API Key:**
- Visit: https://developers.linear.app/docs/graphql/working-with-the-graphql-api#personal-api-keys
- Generate a Personal API Key from Settings → API

**Example:**
```bash
n0s1 linear_scan --api-key lin_api_xxxxxxxxxxxx --report-file linear-results.json
```

### 9. Jira Scan

Scan Jira tickets and comments for leaked secrets.

```bash
n0s1 jira_scan --server <url> --email <email> --api-key <token>
```

**Options:**
- `--server <url>` - Jira server URL (e.g., https://mycompany.atlassian.net)
- `--email <email>` - Jira user email address
- `--api-key <token>` - Jira API token

**Getting API Key:**
- Visit your Atlassian account settings
- Create an API token from Security → API tokens

**Examples:**
```bash
# Basic Jira scan
n0s1 jira_scan --server https://mycompany.atlassian.net --email admin@company.com --api-key ATATTxxxxxxxxxxxx

# Scan with JQL scope
n0s1 jira_scan --server https://mycompany.atlassian.net --email admin@company.com --api-key ATATTxxxxxxxxxxxx --scope "jql:project = SEC"

# Skip comments for faster scan
n0s1 jira_scan --server https://mycompany.atlassian.net --email admin@company.com --api-key ATATTxxxxxxxxxxxx --skip-comment
```

### 10. Confluence Scan

Scan Confluence pages and comments for secrets.

```bash
n0s1 confluence_scan --server <url> --email <email> --api-key <token>
```

**Options:**
- `--server <url>` - Confluence base URL (e.g., https://mycompany.atlassian.net)
- `--email <email>` - Confluence user email address
- `--api-key <token>` - Confluence API token

**Getting API Key:**
- Same as Jira - use Atlassian API token
- Visit your Atlassian account settings → Security → API tokens

**Example:**
```bash
n0s1 confluence_scan --server https://mycompany.atlassian.net --email admin@company.com --api-key ATATTxxxxxxxxxxxx --report-file confluence-results.json
```

## AI Analysis

AI analysis validates discovered credentials by attempting authentication against the target service. Each finding receives a verdict: **live** (credential works), **invalid** (credential rejected), or **unable to test** (could not reach the service).

Analysis is **async** and driven by a state machine split between the client and the n0s1 backend:

```
Scan ──► backend queues analysis ──► backend generates HTTP request templates
      ──► client executes requests with real credentials ──► backend computes verdicts
```

A valid n0s1 API key is required. Set it via `--n0s1-api-key` or the `N0S1_TOKEN` environment variable.

### Workflow A: Scan + AI analysis in one go

```bash
# Step 1: scan and queue analysis
n0s1 jira_scan \
  --server https://myco.atlassian.net \
  --email user@myco.com \
  --api-key $JIRA_TOKEN \
  --n0s1-api-key $N0S1_TOKEN \
  --ai-analysis \
  --report-file report.json
# Prints: "AI analysis queued. Run: n0s1 analyze --report-uuid <uuid>"

# Step 2: advance analysis (run a few minutes later; repeat until complete)
n0s1 analyze \
  --n0s1-api-key $N0S1_TOKEN \
  --report-uuid <uuid> \
  --report-file report.json
```

### Workflow B: Analyze an existing report file

```bash
# Submit a previously saved report for analysis
n0s1 analyze --n0s1-api-key $N0S1_TOKEN --report-file report.json

# Check status / advance (re-run until status is "complete")
n0s1 analyze --n0s1-api-key $N0S1_TOKEN --report-uuid <uuid> --report-file report.json
```

### `analyze` command reference

```bash
n0s1 analyze [global options] [--report-uuid <uuid>] [--report-file <path>] [--wait [MINUTES]]
```

**Options:**

- `--report-uuid <uuid>` — UUID of the report to analyze. If the backend is waiting for the client to execute HTTP validators, this triggers that step automatically. (This is a global option — when passed to a scan command it also assigns that UUID to the newly created report.)
- `--report-file <path>` — Path to a local report JSON file. Used to read the UUID and to inject real credentials during step 2. Also updated in-place when analysis completes.
- `--n0s1-api-key <key>` — n0s1 API key (or set `N0S1_TOKEN`).
- `--wait [MINUTES]` — Block until analysis completes or `MINUTES` elapse (default 30 when `--wait` is given without a value). Polls the backend every 30 seconds and logs progress. Useful for CI/CD pipelines that cannot implement their own retry loop.

**Status values printed during the workflow:**

| Status | Meaning |
|---|---|
| `pending` | Queued; backend is generating request templates |
| `waiting_client` | Templates ready; `analyze` will execute them automatically |
| `pending_verdict` | Client responses uploaded; backend is computing verdicts |
| `complete` | Verdicts written; report file updated |
| `failed` | Unrecoverable error |

**Exit codes:**

| Exit code | Meaning |
|---|---|
| `0` | Analysis complete (or successfully submitted/advanced) |
| `1` | Real error — misconfiguration, HTTP failure, AI analysis `failed`, or `--wait` timeout elapsed |
| `2` | Analysis still pending — backend not ready yet; call again to retry |

Exit code `2` is the machine-readable signal for "not ready yet." Automated workflows can branch on it without parsing log output.

### Automating `analyze` in CI/CD

**Option 1 — Blocking mode (simplest):**

Let `n0s1` poll internally. The step blocks until analysis finishes or the timeout expires.

```yaml
- name: Wait for AI analysis
  run: n0s1 analyze --n0s1-api-key ${{ secrets.N0S1_TOKEN }} --report-uuid $REPORT_UUID --wait 10
  # exits 0 on complete, 1 on error/timeout after 10 minutes
```

**Option 2 — External retry loop:**

Use exit code `2` to drive a workflow-level retry. This gives you full control over retry cadence, notifications, and maximum attempts.

```yaml
- name: Advance AI analysis
  id: analyze
  run: |
    n0s1 analyze --n0s1-api-key ${{ secrets.N0S1_TOKEN }} --report-uuid $REPORT_UUID
    echo "status=$?" >> $GITHUB_OUTPUT
  continue-on-error: true

- name: Retry if still pending
  if: steps.analyze.outputs.status == '2'
  run: echo "Analysis not ready — re-queue this job or add a wait step"
```

## Advanced Features

### Reducing False Positives

n0s1 ships with a global allowlist in `regex.yaml` that suppresses findings across all detection rules. Use it — or your own copy via `--regex-file` — instead of editing individual rules when you need to silence recurring false positives.

The top-level `allowlist` section supports three filter types:

```yaml
allowlist:
  description: global allow lists

  # Suppress any finding whose full text matches one of these patterns.
  # Useful for placeholder or template values that look like secrets.
  regexes:
    - (?i)^true|false|null$
    - >-
      ^(?i:a+|b+|c+|...x+...)$   # single-repeated-character strings
    - '^\$\{\{[ \t]*secrets\.[A-Za-z]\w+[ \t]*}}$'  # GitHub Actions secret refs

  # Suppress any finding where the matched secret contains one of these words
  # (case-insensitive substring match).
  stopwords:
    - abcdefghijklmnopqrstuvwxyz
    - placeholder
    - example

  # Skip file or URL paths that match these patterns (local and GitHub/GitLab scans).
  paths:
    - '(?i)\.(?:bmp|gif|jpe?g|png|svg)$'
    - '(?:^|/)node_modules(?:/.*)?$'
    - '(?:^|/)vendor(?:/.*)?$'
```

**How each filter works:**

| Key | Applied to | Effect |
|---|---|---|
| `regexes` | The full text of the field being scanned | If any pattern matches, the finding is suppressed |
| `stopwords` | The matched secret string only | If any stopword is a substring, the finding is suppressed |
| `paths` | File path or URL of the item being scanned | If any pattern matches, the item is skipped entirely |

**Common use case — silencing placeholder values:**

If your project uses values like `xxxxx`, `changeme`, or `YOUR_TOKEN_HERE` in documentation or tests, add them to `regexes`:

```yaml
allowlist:
  regexes:
    - (?i)^x{3,}$          # xxxxx, XXXXX, etc.
    - (?i)^changeme$
    - (?i)^your[_-].*here$
```

Pass your customized file with `--regex-file`:

```bash
n0s1 jira_scan \
  --regex-file ./my-regex.yaml \
  --server https://mycompany.atlassian.net \
  --email user@mycompany.com \
  --api-key $JIRA_TOKEN
```

Per-rule `allowlists` entries (inside individual rules in the `rules:` list) work the same way but apply only to that rule. The global `allowlist` is a convenient alternative when the same exclusion applies across many rules.

### Using Custom Regex Patterns

Create a custom regex file to detect organization-specific secrets:

```yaml
# custom-regex.yaml
patterns:
  - name: "Company API Key"
    regex: "COMP-[A-Z0-9]{32}"
    severity: "high"
  - name: "Internal Token"
    regex: "INT_TOK_[a-f0-9]{40}"
    severity: "critical"
```

Use it with:
```bash
n0s1 jira_scan --regex-file custom-regex.yaml --server https://company.atlassian.net --email user@company.com --api-key TOKEN
```

### Scoped Scanning with Map Files

Create a map file to define specific scan targets:

```bash
n0s1 jira_scan --server https://company.atlassian.net --email user@company.com --api-key TOKEN --map 1 --map-file scope.json
cat scope.json
```

```json
{
  "projects": {
    "AS": {},
    "DLP": {},
    "GTMS": {},
    "IT": {},
    "ITSAMPLE": {},
    "MAR": {}
  }
}
```

Use it with:
```bash
n0s1 jira_scan --map-file scope.json --scope "1/2" --server URL --email EMAIL --api-key TOKEN
```

### Automated Comment Posting

Automatically warn users about detected secrets:

```bash
n0s1 jira_scan --post-comment --label "security-bot-v1" --contact-help "security@company.com" --secret-manager "HashiCorp Vault" --server URL --email EMAIL --api-key TOKEN
```

This will:
- Post comments on tickets with detected secrets
- Include contact information for help
- Suggest using the specified secret manager
- Use the label to avoid duplicate comments

### MCP Server

If you use Claude Code or Claude Desktop, you can register n0s1 as an MCP server and run scans directly from the chat interface — no CLI commands needed.

**Register once:**
```bash
claude mcp add --scope user n0s1 -- uvx n0s1-mcp
```

After registration, you can ask Claude things like:
- *"Scan my Jira project SEC for leaked secrets"*
- *"Check my GitHub org myorg for exposed credentials"*
- *"Scan the ./src directory for secrets"*

Claude will call the appropriate n0s1 tool, pass your credentials, and summarize the findings inline.

Use `--scope project` instead of `--scope user` to limit the server to the current project only.

#### Available MCP Tools

| Tool | Description |
|---|---|
| `scan_jira` | Scan Jira tickets for leaked secrets |
| `scan_confluence` | Scan Confluence pages for leaked secrets |
| `scan_slack` | Scan Slack channels for leaked secrets |
| `scan_github` | Scan GitHub repositories for leaked secrets |
| `scan_gitlab` | Scan GitLab projects for leaked secrets |
| `scan_zendesk` | Scan Zendesk tickets for leaked secrets |
| `scan_linear` | Scan Linear issues for leaked secrets |
| `scan_asana` | Scan Asana tasks for leaked secrets |
| `scan_wrike` | Scan Wrike tasks for leaked secrets |
| `scan_local` | Scan a local filesystem path for leaked secrets |
| `get_scan_status` | Return the current status of a previously started scan |
| `get_scan_findings` | Return a paginated list of findings for a completed scan |
| `analyze_report` | Submit or advance async AI analysis for a previously uploaded report |

All platform `scan_*` tools accept these optional parameters for AI analysis:

| Parameter | Description |
|---|---|
| `ai_analysis` | Set to `true` to queue async AI credential validation after the scan (requires n0s1 Pro) |
| `n0s1_api_key` | n0s1 API key; overrides the `N0S1_TOKEN` environment variable |
| `allow_secret_upload` | Set to `true` to allow encrypted secrets to be uploaded to the n0s1 backend. Default `false` — credentials stay local and are injected during the `waiting_client` step |

#### `analyze_report` tool reference

Submit a report for AI analysis, or advance an in-progress analysis to the next step. Call once to queue, then call again periodically until `ai_analysis_status` is `"complete"` or `"failed"`.

**Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `report_uuid` | Yes | UUID returned by a `scan_*` tool or a previous `analyze_report` call |
| `n0s1_api_key` | No | n0s1 API key; overrides `N0S1_TOKEN` env var |
| `report_file` | No | Path to local report JSON file — required when status is `"waiting_client"` so real credentials can be injected into HTTP validator requests |
| `wait_minutes` | No | Block until analysis completes or this many minutes elapse (default 30 when provided without a value). Returns `ai_analysis_status="timeout"` if the deadline is reached |

**Returned `ai_analysis_status` values:**

| Status | Meaning |
|---|---|
| `pending` | Queued; backend is generating request templates |
| `waiting_client` | Templates ready; call again with `report_file` to execute HTTP validators |
| `pending_verdict` | Client responses uploaded; backend is computing verdicts |
| `complete` | Verdicts written to report |
| `failed` | Unrecoverable error |

#### AI analysis workflow via MCP

**Option A — queue analysis during the scan:**

Ask Claude: *"Scan Jira at https://myco.atlassian.net for secrets and queue AI analysis. My Jira token is `$JIRA_TOKEN`, email is `user@myco.com`, and n0s1 key is `$N0S1_TOKEN`."*

Claude will call `scan_jira` with `ai_analysis=true` and return a `report_uuid`. A few minutes later, ask:

*"Advance AI analysis for report UUID `<uuid>`. The report file is at `./report.json`."*

Claude will call `analyze_report` with the UUID and `report_file`, execute the HTTP validator requests, and re-upload the enriched report. Call again once more to retrieve the final verdicts.

**Option B — analyze an existing report file:**

Ask Claude: *"Submit `./report.json` for AI analysis using n0s1 key `$N0S1_TOKEN`."*

Claude will call `analyze_report` with the UUID extracted from the file. Repeat as above until complete.

### CI/CD Integration

#### GitHub Actions Example
```yaml
- name: Scan Jira for Secrets
  run: |
    n0s1 jira_scan \
      --server ${{ secrets.JIRA_URL }} \
      --email ${{ secrets.JIRA_EMAIL }} \
      --api-key ${{ secrets.JIRA_TOKEN }} \
      --report-file jira-scan.json \
      --report-format SARIF
```

#### GitLab CI Example
```yaml
jira-scan:
  script:
    - n0s1 jira_scan --server $JIRA_URL --email $JIRA_EMAIL --api-key $JIRA_TOKEN --report-file gl-report.json --report-format gitlab
  artifacts:
    reports:
      dast: gl-report.json
```

## Examples

### Example 1: Quick Local Scan
```bash
n0s1 local_scan --path ./my-project
```

### Example 2: Comprehensive Jira Scan with Reporting
```bash
n0s1 jira_scan \
  --server https://company.atlassian.net \
  --email security@company.com \
  --api-key ATATT3xFfGF0xxxxxxxxxxxx \
  --report-file jira-secrets-2024.json \
  --report-format SARIF \
  --timeout 60 \
  --limit 100
```

### Example 3: GitHub Scan with Custom Patterns
```bash
n0s1 github_scan \
  --owner myorg \
  --repo sensitive-repo \
  --branch production \
  --api-key ghp_xxxxxxxxxxxx \
  --regex-file ./custom-patterns.yaml \
  --report-file github-scan.json
```

### Example 4: Slack Scan with Auto-Comment
```bash
n0s1 slack_scan \
  --api-key xoxb-your-token \
  --post-comment \
  --label "n0s1-security-bot" \
  --contact-help "Contact #security-team for help" \
  --secret-manager "AWS Secrets Manager"
```

### Example 5: Multi-Platform Scan Script
```bash
#!/bin/bash
# Scan multiple platforms and consolidate results

n0s1 jira_scan --server $JIRA_URL --email $EMAIL --api-key $JIRA_TOKEN --report-file jira.json
n0s1 confluence_scan --server $CONF_URL --email $EMAIL --api-key $CONF_TOKEN --report-file confluence.json
n0s1 slack_scan --api-key $SLACK_TOKEN --report-file slack.json
n0s1 github_scan --owner myorg --api-key $GITHUB_TOKEN --report-file github.json

echo "All scans complete. Review report files."
```

## Best Practices

1. **Store the n0s1 API key securely**: Use `N0S1_TOKEN` env var instead of passing `--n0s1-api-key` inline
2. **Start with read-only scans**: Don't use `--post-comment` until you've verified the scanner works correctly
2. **Use custom regex carefully**: Test patterns thoroughly to avoid false positives
3. **Protect API keys**: Store tokens in environment variables or secret managers, never in code
4. **Regular scanning**: Schedule scans in CI/CD pipelines for continuous monitoring
5. **Review reports**: Always review scan results before taking action
6. **Scope appropriately**: Use `--scope` and `--map-file` to focus on relevant areas
7. **Monitor performance**: Use `--timeout` and `--limit` to prevent API rate limiting
8. **Debug wisely**: Avoid `--debug` and `--show-matched-secret-on-logs` in production

## Troubleshooting

### Common Issues

**Authentication Errors**
- Verify API keys are valid and not expired
- Check that tokens have required scopes/permissions
- Ensure email addresses match the account

**Timeout Errors**
- Increase timeout: `--timeout 120`
- Reduce page limit: `--limit 50`
- Use scope filters to scan less data

**SSL Certificate Errors**
- For self-signed certificates in test environments: `--insecure` (not recommended for production)
- Ensure system certificates are up to date

**No Results Found**
- Verify you have access to the resources being scanned
- Check that the scope/query is not too restrictive
- Use `--debug` to see detailed scanning progress

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/spark1security/n0s1/issues
- Documentation: https://spark1.us/n0s1doc
- Website: https://spark1.us/n0s1

