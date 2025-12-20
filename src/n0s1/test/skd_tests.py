import logging
import os
import sys

try:
    import scanner
except:
    import n0s1.scanner as scanner


def test_local_scan():
    """Test local filesystem scanning"""
    print("\n" + "="*60)
    print("Testing LOCAL_SCAN")
    print("="*60)

    scan_path = os.getenv("LOCAL_SCAN_PATH", "./")

    scanner_instance = scanner.SecretScanner(
        target="local_scan",
        scan_path=scan_path,
        debug=True,
        report_format="n0s1"
    )
    result = scanner_instance.scan()
    print(f"Result: {result}")
    return result


def test_slack_scan():
    """Test Slack scanning"""
    print("\n" + "="*60)
    print("Testing SLACK_SCAN")
    print("="*60)

    api_key = os.getenv("SLACK_TOKEN")
    if not api_key:
        print("SKIPPED: SLACK_TOKEN environment variable not set")
        return None

    scanner_instance = scanner.SecretScanner(
        target="slack_scan",
        api_key=api_key,
        debug=True,
        report_format="n0s1"
    )
    result = scanner_instance.scan()
    print(f"Result: {result}")
    return result


def test_asana_scan():
    """Test Asana scanning"""
    print("\n" + "="*60)
    print("Testing ASANA_SCAN")
    print("="*60)

    api_key = os.getenv("ASANA_TOKEN")
    if not api_key:
        print("SKIPPED: ASANA_TOKEN environment variable not set")
        return None

    scanner_instance = scanner.SecretScanner(
        target="asana_scan",
        api_key=api_key,
        debug=True,
        report_format="n0s1"
    )
    result = scanner_instance.scan()
    print(f"Result: {result}")
    return result


def test_zendesk_scan():
    """Test Zendesk scanning"""
    print("\n" + "="*60)
    print("Testing ZENDESK_SCAN")
    print("="*60)

    api_key = os.getenv("ZENDESK_TOKEN")
    email = os.getenv("ZENDESK_EMAIL", "marcelo@spark1.us")
    server = os.getenv("ZENDESK_SERVER", "spark1help")

    if not all([api_key, email, server]):
        print("SKIPPED: ZENDESK_TOKEN, ZENDESK_EMAIL, or ZENDESK_SERVER environment variable not set")
        return None

    scanner_instance = scanner.SecretScanner(
        target="zendesk_scan",
        server=server,
        email=email,
        api_key=api_key,
        debug=True,
        report_format="n0s1"
    )
    result = scanner_instance.scan()
    print(f"Result: {result}")
    return result


def test_github_scan():
    """Test GitHub scanning"""
    print("\n" + "="*60)
    print("Testing GITHUB_SCAN")
    print("="*60)

    api_key = os.getenv("GITHUB_TOKEN")
    owner = os.getenv("GITHUB_OWNER")
    repo = os.getenv("GITHUB_REPO", "n0s1")
    branch = os.getenv("GITHUB_BRANCH", "main,ciconfig")  # Optional

    if not api_key:
        print("SKIPPED: GITHUB_TOKEN environment variable not set")
        return None

    scanner_instance = scanner.SecretScanner(
        target="github_scan",
        owner=owner,
        repo=repo,
        branch=branch,
        api_key=api_key,
        debug=True,
        report_format="n0s1"
    )
    result = scanner_instance.scan()
    print(f"Result: {result}")
    return result


def test_gitlab_scan():
    """Test GitLab scanning"""
    print("\n" + "="*60)
    print("Testing GITLAB_SCAN")
    print("="*60)

    api_key = os.getenv("GITLAB_TOKEN")
    server = os.getenv("GITLAB_SERVER", "https://gitlab.com")
    owner = os.getenv("GITLAB_OWNER", "spark1.us")  # Optional
    repo = os.getenv("GITLAB_REPO")    # Optional
    branch = os.getenv("GITLAB_BRANCH", "dolores-sit-quos-explicabo-ut")  # Optional
    scope = "search:qe-python"

    if not api_key:
        print("SKIPPED: GITLAB_TOKEN environment variable not set")
        return None

    scanner_instance = scanner.SecretScanner(
        target="gitlab_scan",
        server=server,
        owner=owner,
        repo=repo,
        branch=branch,
        api_key=api_key,
        debug=True,
        report_format="n0s1",
        scope=scope
    )
    result = scanner_instance.scan()
    print(f"Result: {result}")
    return result


def test_wrike_scan():
    """Test Wrike scanning"""
    print("\n" + "="*60)
    print("Testing WRIKE_SCAN")
    print("="*60)

    api_key = os.getenv("WRIKE_TOKEN")
    if not api_key:
        print("SKIPPED: WRIKE_TOKEN environment variable not set")
        return None

    scanner_instance = scanner.SecretScanner(
        target="wrike_scan",
        api_key=api_key,
        debug=True,
        report_format="n0s1"
    )
    result = scanner_instance.scan()
    print(f"Result: {result}")
    return result


def test_linear_scan():
    """Test Linear scanning"""
    print("\n" + "="*60)
    print("Testing LINEAR_SCAN")
    print("="*60)

    api_key = os.getenv("LINEAR_TOKEN")
    if not api_key:
        print("SKIPPED: LINEAR_TOKEN environment variable not set")
        return None

    scanner_instance = scanner.SecretScanner(
        target="linear_scan",
        api_key=api_key,
        debug=True,
        report_format="n0s1"
    )
    result = scanner_instance.scan()
    print(f"Result: {result}")
    return result


def test_jira_scan():
    """Test Jira scanning"""
    print("\n" + "="*60)
    print("Testing JIRA_SCAN")
    print("="*60)

    api_key = os.getenv("JIRA_TOKEN")
    email = os.getenv("JIRA_EMAIL", "marcelo@spark1.us")
    server = os.getenv("JIRA_SERVER", "https://spark1us.atlassian.net")
    scope = os.getenv("JIRA_SCOPE", "jql:project=MAR OR project=\"Auto Service\"")


    if not api_key:
        print("SKIPPED: JIRA_TOKEN environment variable not set")
        return None

    scanner_instance = scanner.SecretScanner(
        target="jira_scan",
        server=server,
        email=email,
        api_key=api_key,
        scope=scope,
        debug=True,
        report_format="sarif"
    )
    result = scanner_instance.scan()
    print(f"Result: {result}")
    return result


def test_confluence_scan():
    """Test Confluence scanning"""
    print("\n" + "="*60)
    print("Testing CONFLUENCE_SCAN")
    print("="*60)

    api_key = os.getenv("CONFLUENCE_TOKEN", os.getenv("JIRA_TOKEN"))
    email = os.getenv("CONFLUENCE_EMAIL", "marcelo@spark1.us")
    server = os.getenv("CONFLUENCE_SERVER", "https://spark1us.atlassian.net")
    scope = os.getenv("CONFLUENCE_SCOPE", "cql:space=SEC and type=page")

    if not api_key:
        print("SKIPPED: CONFLUENCE_TOKEN or JIRA_TOKEN environment variable not set")
        return None

    scanner_instance = scanner.SecretScanner(
        target="confluence_scan",
        server=server,
        email=email,
        api_key=api_key,
        scope=scope,
        debug=True,
        report_format="sarif"
    )
    result = scanner_instance.scan()
    print(f"Result: {result}")
    return result


def run_all_tests():
    """Run all platform tests"""
    print("\n" + "="*60)
    print("N0S1 SCANNER - COMPREHENSIVE PLATFORM TESTS")
    print("="*60)

    tests = [
        ("Local Scan", test_local_scan),
        ("Slack Scan", test_slack_scan),
        ("Asana Scan", test_asana_scan),
        ("Zendesk Scan", test_zendesk_scan),
        ("GitHub Scan", test_github_scan),
        ("GitLab Scan", test_gitlab_scan),
        ("Wrike Scan", test_wrike_scan),
        ("Linear Scan", test_linear_scan),
        ("Jira Scan", test_jira_scan),
        ("Confluence Scan", test_confluence_scan),
    ]

    results = {}
    for test_name, test_func in tests:
        try:
            result = test_func()
            results[test_name] = f"PASSED | Total findings: [{len(result.get("findings", []))}]" if result is not None else "SKIPPED"
        except Exception as e:
            print(f"ERROR in {test_name}: {str(e)}")
            results[test_name] = f"FAILED: {str(e)}"

    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    for test_name, status in results.items():
        print(f"{test_name:20s}: {status}")
    print("="*60)

    return results


def run_single_test(platform):
    """Run a single platform test"""
    test_map = {
        "local": test_local_scan,
        "slack": test_slack_scan,
        "asana": test_asana_scan,
        "zendesk": test_zendesk_scan,
        "github": test_github_scan,
        "gitlab": test_gitlab_scan,
        "wrike": test_wrike_scan,
        "linear": test_linear_scan,
        "jira": test_jira_scan,
        "confluence": test_confluence_scan,
    }

    platform_lower = platform.lower()
    if platform_lower in test_map:
        return test_map[platform_lower]()
    else:
        print(f"Unknown platform: {platform}")
        print(f"Available platforms: {', '.join(test_map.keys())}")
        return None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) > 1:
        # Run specific test
        platform = sys.argv[1]
        run_single_test(platform)
    else:
        # Run all tests
        run_all_tests()