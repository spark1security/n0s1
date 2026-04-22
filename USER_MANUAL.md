# n0s1 User Manual

Complete guide for using the n0s1 secret scanner tool.

## Table of Contents
- [Overview](#overview)
- [Basic Usage](#basic-usage)
- [Global Options](#global-options)
- [Platform Commands](#platform-commands)
- [Advanced Features](#advanced-features)
  - [MCP Server](#mcp-server)
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

ai_analysis_default_value
**`--ai-analysis`**
- Send scan results to an AI agent to validate leaked credentials. The agent will update the report with each credential’s status: live (authentication succeeded), unable to test, or invalid.
- ⚠️ The leaked credentials identified by the scanner will be tested live. If you are not authorized to test the credentials, do not enable this mode
- Only supported when using Professional mode 
- 
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

## Advanced Features

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

1. **Start with read-only scans**: Don't use `--post-comment` until you've verified the scanner works correctly
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

