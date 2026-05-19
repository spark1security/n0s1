# n0s1 Integration Tests

Live integration tests that connect to real SaaS platforms. Tests are
skipped automatically if the required environment variables are not set,
so it is safe to run the full suite with only the credentials you have.

## Usage

Run from the repo root:

```bash
# All platforms
python tests/integration/skd_tests.py

# Single platform
python tests/integration/skd_tests.py <platform>
```

Available platforms: `local`, `slack`, `asana`, `zendesk`, `github`,
`gitlab`, `wrike`, `linear`, `jira`, `confluence`, `analyze_uuid`, `analyze_file`.

```bash
python tests/integration/skd_tests.py jira
python tests/integration/skd_tests.py confluence
python tests/integration/skd_tests.py github
python tests/integration/skd_tests.py analyze_uuid
python tests/integration/skd_tests.py analyze_file
```

## Environment Variables

Each platform requires specific environment variables. Tests are
**skipped** if required variables are missing.

| Platform | Required | Optional |
|---|---|---|
| Local | — | `LOCAL_SCAN_PATH` (default `./`) |
| Slack | `SLACK_TOKEN` | — |
| Asana | `ASANA_TOKEN` | — |
| Zendesk | `ZENDESK_TOKEN`, `ZENDESK_EMAIL`, `ZENDESK_SERVER` | — |
| GitHub | `GITHUB_TOKEN` | `GITHUB_OWNER`, `GITHUB_REPO`, `GITHUB_BRANCH` |
| GitLab | `GITLAB_TOKEN` | `GITLAB_SERVER`, `GITLAB_OWNER`, `GITLAB_REPO`, `GITLAB_BRANCH` |
| Wrike | `WRIKE_TOKEN` | — |
| Linear | `LINEAR_TOKEN` | — |
| Jira | `JIRA_TOKEN` | `JIRA_EMAIL`, `JIRA_SERVER`, `JIRA_SCOPE` |
| Confluence | `CONFLUENCE_TOKEN` (falls back to `JIRA_TOKEN`) | `CONFLUENCE_EMAIL`, `CONFLUENCE_SERVER`, `CONFLUENCE_SCOPE` |
| Analyze (UUID) | `N0S1_TOKEN`, `N0S1_REPORT_UUID` | — |
| Analyze (File) | `N0S1_TOKEN`, `N0S1_REPORT_FILE` | — |

## Notes

- All scans run with `debug=True` for verbose output.
- Jira and Confluence use SARIF output format; all others use n0s1 format.
- These are read-only scans — no comments are posted.
