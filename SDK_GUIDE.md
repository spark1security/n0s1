# n0s1 SDK Guide

Complete guide for using n0s1 as a Python SDK/library in your applications.

## Table of Contents
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [SecretScanner Class](#secretscanner-class)
- [Platform-Specific Examples](#platform-specific-examples)
- [Advanced Usage](#advanced-usage)
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
    scope=None                      # Search query/scope
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

