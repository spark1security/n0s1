# n0s1 SDK Tests

Comprehensive test suite for all n0s1 scanner platforms.

## Overview

The `skd_tests.py` file contains tests for all 10 supported platforms:
- Local filesystem
- Slack
- Asana
- Zendesk
- GitHub
- GitLab
- Wrike
- Linear
- Jira
- Confluence

## Usage

### Run All Tests

```bash
python src/n0s1/test/skd_tests.py
```

This will run tests for all platforms. Tests will be skipped if required environment variables are not set.

### Run Single Platform Test

```bash
python src/n0s1/test/skd_tests.py <platform>
```

Available platforms:
- `local`
- `slack`
- `asana`
- `zendesk`
- `github`
- `gitlab`
- `wrike`
- `linear`
- `jira`
- `confluence`

**Examples:**
```bash
python src/n0s1/test/skd_tests.py jira
python src/n0s1/test/skd_tests.py confluence
python src/n0s1/test/skd_tests.py github
```

## Environment Variables

Each platform requires specific environment variables to be set. Tests will be **SKIPPED** if required variables are missing.

### Local Scan
- `LOCAL_SCAN_PATH` (optional, defaults to `./`)

### Slack
- `SLACK_TOKEN` (required) - Slack OAuth token

### Asana
- `ASANA_TOKEN` (required) - Asana Personal Access Token

### Zendesk
- `ZENDESK_TOKEN` (required) - Zendesk API key
- `ZENDESK_EMAIL` (required) - Zendesk user email
- `ZENDESK_SERVER` (required) - Zendesk subdomain

### GitHub
- `GITHUB_TOKEN` (required) - GitHub Personal Access Token
- `GITHUB_OWNER` (optional) - GitHub organization/user
- `GITHUB_REPO` (optional) - Repository name
- `GITHUB_BRANCH` (optional) - Branch to scan

### GitLab
- `GITLAB_TOKEN` (required) - GitLab Personal Access Token
- `GITLAB_SERVER` (optional, defaults to `https://gitlab.com`)
- `GITLAB_OWNER` (optional) - GitLab group
- `GITLAB_REPO` (optional) - Project ID or path
- `GITLAB_BRANCH` (optional) - Branch to scan

### Wrike
- `WRIKE_TOKEN` (required) - Wrike permanent token

### Linear
- `LINEAR_TOKEN` (required) - Linear API key

### Jira
- `JIRA_TOKEN` (required) - Jira API token
- `JIRA_EMAIL` (optional, defaults to `marcelo.sacchetin@webflow.com`)
- `JIRA_SERVER` (optional, defaults to `https://webflow.atlassian.net`)
- `JIRA_SCOPE` (optional) - JQL query for scoping

### Confluence
- `CONFLUENCE_TOKEN` (required, falls back to `JIRA_TOKEN`)
- `CONFLUENCE_EMAIL` (optional, falls back to `JIRA_EMAIL`)
- `CONFLUENCE_SERVER` (optional, falls back to `JIRA_SERVER`)
- `CONFLUENCE_SCOPE` (optional, defaults to `cql:space=SEC and type=page`)

## Example: Setting Environment Variables

### Linux/macOS
```bash
export JIRA_TOKEN="your-jira-token"
export JIRA_EMAIL="your-email@company.com"
export JIRA_SERVER="https://yourcompany.atlassian.net"
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
export SLACK_TOKEN="xoxb-xxxxxxxxxxxx"

# Run all tests
python src/n0s1/test/skd_tests.py

# Run specific test
python src/n0s1/test/skd_tests.py jira
```

### Windows (PowerShell)
```powershell
$env:JIRA_TOKEN="your-jira-token"
$env:JIRA_EMAIL="your-email@company.com"
$env:JIRA_SERVER="https://yourcompany.atlassian.net"

python src/n0s1/test/skd_tests.py jira
```

### Using .env file (recommended)

Create a `.env` file in the project root:
```bash
# .env
JIRA_TOKEN=your-jira-token
JIRA_EMAIL=your-email@company.com
JIRA_SERVER=https://yourcompany.atlassian.net
GITHUB_TOKEN=ghp_xxxxxxxxxxxx
SLACK_TOKEN=xoxb-xxxxxxxxxxxx
GITLAB_TOKEN=glpat-xxxxxxxxxxxx
```

Then load it before running tests:
```bash
# Linux/macOS
export $(cat .env | xargs)
python src/n0s1/test/skd_tests.py
```

## Test Output

### Successful Test
```
============================================================
Testing JIRA_SCAN
============================================================
[Scanner output...]
Result: {...}
```

### Skipped Test
```
============================================================
Testing SLACK_SCAN
============================================================
SKIPPED: SLACK_TOKEN environment variable not set
```

### Test Summary
After running all tests, you'll see a summary:
```
============================================================
TEST SUMMARY
============================================================
Local Scan          : PASSED
Slack Scan          : SKIPPED
Asana Scan          : SKIPPED
Zendesk Scan        : SKIPPED
GitHub Scan         : PASSED
GitLab Scan         : SKIPPED
Wrike Scan          : SKIPPED
Linear Scan         : SKIPPED
Jira Scan           : PASSED
Confluence Scan     : PASSED
============================================================
```

## Notes

- Tests run with `debug=True` for verbose output
- Jira and Confluence tests use SARIF format by default
- Other tests use n0s1 format by default
- Tests are designed to be non-destructive (read-only scans)

