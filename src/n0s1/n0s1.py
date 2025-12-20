import argparse
import logging
import json
import pprint
import sys

try:
    import scanner
except:
    import n0s1.scanner as scanner


def init_argparse() -> argparse.ArgumentParser:
    """Adds arguements that can be called from the command line

    Returns:
        argparse.ArgumentParser: A parser that contains the command line options
    """
    parser = argparse.ArgumentParser(
        prog="n0s1",
        description="""Secret scanner for Slack, Jira, Confluence, Asana, Wrike, Zendesk and Linear.
        """,
    )

    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + scanner.n0s1_version)

    # Create parent subparser. Note `add_help=False` and creation via `argparse.`
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--regex-file",
        dest="regex_file",
        nargs="?",
        default=scanner.regex_file_default_value,
        type=str,
        help="Custom .yaml or .toml with a list of regexes to be matched."
    )
    parent_parser.add_argument(
        "--config-file",
        dest="config_file",
        nargs="?",
        default=scanner.config_file_default_value,
        type=str,
        help="Configuration file (YAML format) to be used."
    )
    parent_parser.add_argument(
        "--report-file",
        dest="report_file",
        nargs="?",
        default=scanner.report_file_default_value,
        type=str,
        help="Output report file for the leaked secrets."
    )
    parent_parser.add_argument(
        "--report-format",
        dest="report_format",
        nargs="?",
        default=scanner.report_format_default_value,
        type=str,
        help="Output report format. Supported formats: n0s1, SARIF, gitlab."
    )
    parent_parser.add_argument(
        "--post-comment",
        dest="post_comment",
        action="store_true",
        help="By default, scans only flag leaked secrets; this adds a warning comment to every ticket with a potential secret leak",
    )
    parent_parser.add_argument(
        "--skip-comment",
        dest="skip_comment",
        action="store_true",
        help="By default, scans check the ticket title, description and comments; this flag disables ticket comment scanning",
    )
    parent_parser.add_argument(
        "--show-matched-secret-on-logs",
        dest="show_matched_secret_on_logs",
        action="store_true",
        help="By default, only a sanitized version of the leak is shown on logs. This flag makes the actual leaked secret to be displayed on logs. Be extra careful when enabling this flag because you might make the leak worst by sending sensitive info to logs.",
    )
    parent_parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        help="Debug mode. Warning it may further expose sensitive data.",
    )
    parent_parser.add_argument(
        "--secret-manager",
        dest="secret_manager",
        nargs="?",
        default=scanner.secret_manager_default_value,
        type=str,
        help="Secret manager tool name to be suggested when leaks are found."
    )
    parent_parser.add_argument(
        "--contact-help",
        dest="contact_help",
        nargs="?",
        default=scanner.contact_help_default_value,
        type=str,
        help="Contact information for assistance when leaks are detected."
    )
    parent_parser.add_argument(
        "--label",
        dest="label",
        nargs="?",
        default=scanner.label_default_value,
        type=str,
        help="Unique identifier to be added to the comments so that the n0s1 bot can recognize if the leak has been previously flagged."
    )
    parent_parser.add_argument(
        "--timeout",
        dest="timeout",
        nargs="?",
        default="",
        type=str,
        help="HTTP request timeout in seconds"
    )
    parent_parser.add_argument(
        "--limit",
        dest="limit",
        nargs="?",
        default="",
        type=str,
        help="The limit of the number of pages to return per HTTP request"
    )
    parent_parser.add_argument(
        "--insecure",
        dest="insecure",
        action="store_true",
        help="Insecure mode. Ignore SSL certificate verification",
    )
    parent_parser.add_argument(
        "--map",
        dest="map",
        nargs="?",
        default="Disabled",
        type=str,
        help="Enable mapping mode and define how many levels for the mapping."
    )
    parent_parser.add_argument(
        "--map-file",
        dest="map_file",
        nargs="?",
        type=str,
        help="Path to map file (e.g. n0s1_map.json). Use it for customizing the scope of the scan."
    )
    parent_parser.add_argument(
        "--scope",
        dest="scope",
        nargs="?",
        default="Disabled",
        type=str,
        help="Define a search query Ex: \"search:org:spark1security action in:name\" for GitHub or \"jql:project != IT\" for Jira. If using with --map-file, it defines a chunk of the map file to be scanned. Ex: 3/4 (will scan the third quarter of the map)."
    )
    subparsers = parser.add_subparsers(
        help="Subcommands", dest="command", metavar="COMMAND"
    )

    local_scan_parser = subparsers.add_parser(
        "local_scan", help="Scan local filesystem", parents=[parent_parser]
    )
    local_scan_parser.add_argument(
        "--path",
        dest="path",
        nargs="?",
        type=str,
        help="Path to the local file or folder to be scanned"
    )

    slack_scan_parser = subparsers.add_parser(
        "slack_scan", help="Scan Slack messages", parents=[parent_parser]
    )
    slack_scan_parser.add_argument(
        "--api-key",
        dest="api_key",
        nargs="?",
        type=str,
        help="Slack token with OAuth scope: search:read, users:read, chat:write. Ref: https://api.slack.com/tutorials/tracks/getting-a-token"
    )

    asana_scan_parser = subparsers.add_parser(
        "asana_scan", help="Scan Asana tasks", parents=[parent_parser]
    )
    asana_scan_parser.add_argument(
        "--api-key",
        dest="api_key",
        nargs="?",
        type=str,
        help="Asana API key. Ref: https://developers.asana.com/docs/personal-access-token#generating-a-pat"
    )

    zendesk_scan_parser = subparsers.add_parser(
        "zendesk_scan", help="Scan Zendesk tickets", parents=[parent_parser]
    )
    zendesk_scan_parser.add_argument(
        "--server",
        dest="server",
        nargs="?",
        type=str,
        help="Zendesk server subdomain."
    )
    zendesk_scan_parser.add_argument(
        "--email",
        dest="email",
        nargs="?",
        type=str,
        help="Zendesk user email."
    )
    zendesk_scan_parser.add_argument(
        "--api-key",
        dest="api_key",
        nargs="?",
        type=str,
        help="Zendesk API key. Ref: https://developer.zendesk.com/api-reference/integration-services/connections/api_key_connections"
    )

    github_scan_parser = subparsers.add_parser(
        "github_scan", help="Scan GitHub repos", parents=[parent_parser]
    )
    github_scan_parser.add_argument(
        "--owner",
        dest="owner",
        nargs="?",
        type=str,
        help="The GitHub account owner (a.k.a org) of the repository. The name is not case sensitive."
    )
    github_scan_parser.add_argument(
        "--repo",
        dest="repo",
        nargs="?",
        type=str,
        help="The name of the repository without the .git extension. The name is not case sensitive."
    )
    github_scan_parser.add_argument(
        "--branch",
        dest="branch",
        nargs="?",
        type=str,
        help="The repo branch to scan. If not provided, all accessible branches will be scanned."
    )
    github_scan_parser.add_argument(
        "--api-key",
        dest="api_key",
        nargs="?",
        type=str,
        help="GitHub access token. Ref: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app"
    )

    gitlab_scan_parser = subparsers.add_parser(
        "gitlab_scan", help="Scan GitLab repos", parents=[parent_parser]
    )
    gitlab_scan_parser.add_argument(
        "--server",
        dest="server",
        nargs="?",
        type=str,
        help="GitLab instance URL (defaults to https://gitlab.com)"
    )
    gitlab_scan_parser.add_argument(
        "--owner",
        dest="owner",
        nargs="?",
        type=str,
        help="The GitLab group to scan. If not provided, all accessible projects will be scanned."
    )
    gitlab_scan_parser.add_argument(
        "--repo",
        dest="repo",
        nargs="?",
        type=str,
        help="The GitLab project ID or path with namespace to scan. If not provided, all accessible projects will be scanned."
    )
    gitlab_scan_parser.add_argument(
        "--branch",
        dest="branch",
        nargs="?",
        type=str,
        help="The repo branch to scan. If not provided, all accessible branches will be scanned."
    )
    gitlab_scan_parser.add_argument(
        "--api-key",
        dest="api_key",
        nargs="?",
        type=str,
        help="GitLab personal access token. Ref: https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html"
    )

    wrike_scan_parser = subparsers.add_parser(
        "wrike_scan", help="Scan Wrike tasks", parents=[parent_parser]
    )
    wrike_scan_parser.add_argument(
        "--api-key",
        dest="api_key",
        nargs="?",
        type=str,
        help="Wrike permanent token. Ref: https://help.wrike.com/hc/en-us/articles/210409445-Wrike-API#UUID-a1b0051a-0537-2215-c542-3b04d7205f4b_section-idm232163770698441"
    )

    linear_scan_parser = subparsers.add_parser(
        "linear_scan", help="Scan Linear issues", parents=[parent_parser]
    )
    linear_scan_parser.add_argument(
        "--api-key",
        dest="api_key",
        nargs="?",
        type=str,
        help="Linear API key. Ref: https://developers.linear.app/docs/graphql/working-with-the-graphql-api#personal-api-keys"
    )

    jira_scan_parser = subparsers.add_parser(
        "jira_scan", help="Scan Jira tickets", parents=[parent_parser]
    )
    jira_scan_parser.add_argument(
        "--server",
        dest="server",
        nargs="?",
        type=str,
        help="Jira server uri."
    )
    jira_scan_parser.add_argument(
        "--email",
        dest="email",
        nargs="?",
        type=str,
        help="Jira user email."
    )
    jira_scan_parser.add_argument(
        "--api-key",
        dest="api_key",
        nargs="?",
        type=str,
        help="Jira API key."
    )

    confluence_scan_parser = subparsers.add_parser(
        "confluence_scan", help="Scan Confluence pages", parents=[parent_parser]
    )
    confluence_scan_parser.add_argument(
        "--server",
        dest="server",
        nargs="?",
        type=str,
        help="Confluence base URL (e.g. https://yourcompany.atlassian.net)."
    )
    confluence_scan_parser.add_argument(
        "--email",
        dest="email",
        nargs="?",
        type=str,
        help="Confluence user email."
    )
    confluence_scan_parser.add_argument(
        "--api-key",
        dest="api_key",
        nargs="?",
        type=str,
        help="Confluence API key."
    )
    return parser


def main():
    secret_scanner = scanner.SecretScanner()

    logging.basicConfig(level=logging.INFO)
    parser = init_argparse()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    secret_scanner.set(debug=args.debug)
    secret_scanner.set(regex_file=args.regex_file)
    secret_scanner.set(config_file=args.config_file)

    if not args.map:
        args.map = "-1"

    secret_scanner.set(scope=args.scope)
    secret_scanner.set(map=args.map)
    secret_scanner.set(map_file=args.map_file)

    scope_config = secret_scanner.get_scope_config()
    if scope_config:
        if args.map_file:
            scanner.log_message(f"Running scoped scan using map file [{args.map_file}]. Scan scope:", level=logging.INFO)
        else:
            scanner.log_message(f"Running scoped scan using search query:", level=logging.INFO)
        pprint.pprint(scope_config)


    report_file = args.report_file

    command = args.command
    secret_scanner.set(target=command)

    cfg = secret_scanner.get_config()

    if args.timeout and len(args.timeout) > 0:
        timeout = int(args.timeout)
    else:
        timeout = cfg.get("general_params", {}).get("timeout", None)

    if args.limit and len(args.limit) > 0:
        limit = int(args.limit)
    else:
        limit = cfg.get("general_params", {}).get("limit", None)

    if args.insecure:
        insecure = bool(args.insecure)
    else:
        insecure = cfg.get("general_params", {}).get("insecure", False)

    secret_scanner.set(report_file=report_file)
    secret_scanner.set(timeout=timeout)
    secret_scanner.set(limit=limit)
    secret_scanner.set(insecure=insecure)

    commands = ["local_scan", "linear_scan", "slack_scan", "asana_scan", "zendesk_scan", "github_scan", "gitlab_scan", "wrike_scan", "jira_scan", "confluence_scan"]
    extended_commands = []
    for c in commands:
        short_c = c.replace("_scan", "")
        extended_commands.append(c)
        extended_commands.append(short_c)
    if command not in extended_commands:
        parser.print_help()
        return

    if command == "local_scan":
        secret_scanner.set(scan_path=args.path)
    else:
        secret_scanner.set(api_key=args.api_key)

    if command == "jira_scan" or command == "confluence_scan" or command == "zendesk_scan" or command == "gitlab_scan":
        secret_scanner.set(server=args.server)
    if command == "jira_scan" or command == "confluence_scan" or command == "zendesk_scan":
        secret_scanner.set(email=args.email)
    if command == "github_scan" or command == "gitlab_scan":
        secret_scanner.set(owner=args.owner)
        secret_scanner.set(repo=args.repo)
        secret_scanner.set(branch=args.branch)

    date_utc = secret_scanner.get_report().get("scan_date", {}).get("date_utc", "")
    message = f"n0s1 secret scanner version [{scanner.n0s1_version}] - Scan date: {date_utc}"
    scanner.log_message(message)
    if args.debug:
        message = f"Args: {args}"
        scanner.log_message(message)

    if args.post_comment:
        post_comment = args.post_comment
    else:
        post_comment = cfg.get("general_params", {}).get("post_comment", False)

    if args.skip_comment:
        skip_comment = args.skip_comment
    else:
        skip_comment = cfg.get("general_params", {}).get("skip_comment", False)

    if args.secret_manager:
        secret_manager = args.secret_manager
    else:
        secret_manager = cfg.get("comment_params", {}).get("secret_manager", False)

    if args.contact_help:
        contact_help = args.contact_help
    else:
        contact_help = cfg.get("comment_params", {}).get("contact_help", False)

    if args.label:
        label = args.label
    else:
        label = cfg.get("comment_params", {}).get("label", False)

    if args.show_matched_secret_on_logs:
        show_matched_secret_on_logs = args.show_matched_secret_on_logs
    else:
        show_matched_secret_on_logs = cfg.get("general_params", {}).get("show_matched_secret_on_logs", False)

    if args.report_format:
        report_format = args.report_format
    else:
        report_format = cfg.get("general_params", {}).get("report_format", "n0s1")

    secret_scanner.set(post_comment=post_comment)
    secret_scanner.set(skip_comment=skip_comment)
    secret_scanner.set(secret_manager=secret_manager)
    secret_scanner.set(contact_help=contact_help)
    secret_scanner.set(label=label)
    secret_scanner.set(show_matched_secret_on_logs=show_matched_secret_on_logs)
    secret_scanner.set(report_format=report_format)

    if args.map and args.map.lower() != "Disabled".lower():
        levels = int(args.map)
        map_data = secret_scanner.get_controller_mapping(levels)
        map_file_path = args.map_file
        if not map_file_path:
            map_file_path = "n0s1_map.json"
        with open(map_file_path, "w") as f:
            json.dump(map_data, f)
            scanner.log_message(f"Scan scope saved to map file: {map_file_path}")
        return True

    try:
        secret_scanner.scan()
    except KeyboardInterrupt:
        scanner.log_message("Keyboard interrupt detected. Saving findings and exiting...")
        sys.exit(130)
    except Exception as e:
        scanner.log_message("Execution interrupted by an exception. Saving partial report and exiting...")
        scanner.log_message(e)
        sys.exit(1)
    finally:
        secret_scanner.save_report()
        scanner.log_message("Done!")



if __name__ == "__main__":
    main()
