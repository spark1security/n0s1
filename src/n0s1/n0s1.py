import argparse
import logging
import json
import math
import os
import pathlib
import pprint
import re
import sys
from datetime import datetime, timezone

try:
    import controllers.spark1 as spark1
except:
    import n0s1.controllers.spark1 as spark1

try:
    import controllers.platform_controller as platform_controller
except:
    import n0s1.controllers.platform_controller as platform_controller

try:
    import reporting.report_sarif as report_sarif
except:
    import n0s1.reporting.report_sarif as report_sarif

try:
    import reporting.report_gitlab as report_gitlab
except:
    import n0s1.reporting.report_gitlab as report_gitlab

try:
    import secret_scan
except:
    import n0s1.secret_scan as secret_scan


try:
    import utils
except:
    import n0s1.utils as utils

global n0s1_version, report_json, report_file, cfg, DEBUG







def init_argparse() -> argparse.ArgumentParser:
    global n0s1_version
    """Adds arguements that can be called from the command line

    Returns:
        argparse.ArgumentParser: A parser that contains the command line options
    """
    install_path = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        prog="n0s1",
        description="""Secret scanner for Slack, Jira, Confluence, Asana, Wrike, Zendesk and Linear.
        """,
    )

    try:
        here = pathlib.Path(__file__).parent.resolve()
        init_file = pathlib.Path(here / "__init__.py")
        n0s1_version = re.search(r'^__version__ = [\'"]([^\'"]*)[\'"]', init_file.read_text(), re.M).group(1)
    except Exception:
        n0s1_version = "0.0.1"
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + n0s1_version)

    # Create parent subparser. Note `add_help=False` and creation via `argparse.`
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--regex-file",
        dest="regex_file",
        nargs="?",
        default=f"{install_path}/config/regex.yaml",
        type=str,
        help="Custom .yaml or .toml with a list of regexes to be matched."
    )
    parent_parser.add_argument(
        "--config-file",
        dest="config_file",
        nargs="?",
        default=f"{install_path}/config/config.yaml",
        type=str,
        help="Configuration file (YAML format) to be used."
    )
    parent_parser.add_argument(
        "--report-file",
        dest="report_file",
        nargs="?",
        default="n0s1_report.json",
        type=str,
        help="Output report file for the leaked secrets."
    )
    parent_parser.add_argument(
        "--report-format",
        dest="report_format",
        nargs="?",
        default="n0s1",
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
        default="a secret manager tool",
        type=str,
        help="Secret manager tool name to be suggested when leaks are found."
    )
    parent_parser.add_argument(
        "--contact-help",
        dest="contact_help",
        nargs="?",
        default="contact@spark1.us",
        type=str,
        help="Contact information for assistance when leaks are detected."
    )
    parent_parser.add_argument(
        "--label",
        dest="label",
        nargs="?",
        default="n0s1bot_auto_comment_e869dd5fa15ca0749a350aac758c7f56f56ad9be1",
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





def _save_report(report_format=""):
    global report_json, report_file

    try:
        if report_format.lower().find("sarif".lower()) != -1:
            github_report = report_sarif.n0s1_report_to_sarif_report(report_json)
            github_report.write_report(report_file)
            return True
        elif report_format.lower().find("gitlab".lower()) != -1:
            gitlab_report = report_gitlab.n0s1_report_to_gitlab_report(report_json)
            gitlab_report.write_report(report_file)
            return True
        else:
            with open(report_file, "w") as f:
                json.dump(report_json, f)
                return True
    except Exception as e:
        utils.log_message(str(e), level=logging.ERROR)

    return False











def main(callback=None):
    global n0s1_version, report_json, report_file, cfg, DEBUG

    logging.basicConfig(level=logging.INFO)
    parser = init_argparse()
    args = parser.parse_args()

    DEBUG = False

    regex_config = None
    scan_scope = ""
    cfg = {}

    if not args.command:
        parser.print_help()
        return

    DEBUG = args.debug

    regex_config = utils.load_regex_config(args.regex_file)
    cfg = utils.load_n0s1_config(args.config_file)

    if not args.map:
        args.map = "-1"

    scope_config = get_scope_config(args)
    if scope_config:
        if args.map_file:
            utils.log_message(f"Running scoped scan using map file [{args.map_file}]. Scan scope:", level=logging.INFO)
        else:
            utils.log_message(f"Running scoped scan using search query:", level=logging.INFO)
        pprint.pprint(scope_config)

    datetime_now_obj = datetime.now(timezone.utc)
    date_utc = datetime_now_obj.strftime("%Y-%m-%dT%H:%M:%S")

    report_json = {"tool": {"name": "n0s1", "version": n0s1_version, "author": "Spark 1 Security"},
                   "scan_date": {"timestamp": datetime_now_obj.timestamp(), "date_utc": date_utc},
                   "regex_config": regex_config, "findings": {}}
    report_file = args.report_file

    command = args.command
    controller_factory = platform_controller.factory
    controller = controller_factory.get_platform(command)
    controller.set_log_message_callback(callback)

    controller_config = {}

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

    controller_config["timeout"] = timeout
    controller_config["limit"] = limit
    controller_config["insecure"] = insecure
    controller_config["scan_scope"] = scope_config

    TOKEN = None
    SERVER = None
    EMAIL = None
    if command == "linear_scan":
        TOKEN = os.getenv("LINEAR_TOKEN")
        if args.api_key and len(args.api_key) > 0:
            TOKEN = args.api_key
        controller_config["token"] = TOKEN

    elif command == "slack_scan":
        TOKEN = os.getenv("SLACK_TOKEN")
        if args.api_key and len(args.api_key) > 0:
            TOKEN = args.api_key
        controller_config["token"] = TOKEN

    elif command == "asana_scan":
        TOKEN = os.getenv("ASANA_TOKEN")
        if args.api_key and len(args.api_key) > 0:
            TOKEN = args.api_key
        controller_config["token"] = TOKEN

    elif command == "zendesk_scan":
        SERVER = os.getenv("ZENDESK_SERVER")
        EMAIL = os.getenv("ZENDESK_EMAIL")
        TOKEN = os.getenv("ZENDESK_TOKEN")
        if args.server and len(args.server) > 0:
            SERVER = args.server
        if args.email and len(args.email) > 0:
            EMAIL = args.email
        if args.api_key and len(args.api_key) > 0:
            TOKEN = args.api_key
        controller_config["server"] = SERVER
        controller_config["email"] = EMAIL
        controller_config["token"] = TOKEN

    elif command == "github_scan":
        OWNER = os.getenv("GITHUB_ORG")
        REPO = os.getenv("GITHUB_REPO")
        BRANCH = os.getenv("GIT_BRANCH")
        TOKEN = os.getenv("GITHUB_TOKEN")
        if args.owner and len(args.owner) > 0:
            OWNER = args.owner
        if args.repo and len(args.repo) > 0:
            REPO = args.repo
        if args.branch and len(args.branch) > 0:
            BRANCH = args.branch
        if args.api_key and len(args.api_key) > 0:
            TOKEN = args.api_key
        controller_config["owner"] = OWNER
        controller_config["repo"] = REPO
        controller_config["branch"] = BRANCH
        controller_config["token"] = TOKEN

    elif command == "gitlab_scan":
        URL = os.getenv("GITLAB_URL", "https://gitlab.com")
        GROUP = os.getenv("GITLAB_GROUP")
        PROJECT = os.getenv("GITLAB_PROJECT")
        BRANCH = os.getenv("GIT_BRANCH")
        TOKEN = os.getenv("GITLAB_TOKEN")
        if args.server and len(args.server) > 0:
            URL = args.server
        if args.owner and len(args.owner) > 0:
            GROUP = args.owner
        if args.repo and len(args.repo) > 0:
            PROJECT = args.repo
        if args.branch and len(args.branch) > 0:
            BRANCH = args.branch
        if args.api_key and len(args.api_key) > 0:
            TOKEN = args.api_key
        controller_config["url"] = URL
        controller_config["group"] = GROUP
        controller_config["project"] = PROJECT
        controller_config["branch"] = BRANCH
        controller_config["token"] = TOKEN

    elif command == "wrike_scan":
        TOKEN = os.getenv("WRIKE_TOKEN")
        if args.api_key and len(args.api_key) > 0:
            TOKEN = args.api_key
        controller_config["token"] = TOKEN

    elif command == "jira_scan":
        SERVER = os.getenv("JIRA_SERVER")
        EMAIL = os.getenv("JIRA_EMAIL")
        TOKEN = os.getenv("JIRA_TOKEN")
        if args.server and len(args.server) > 0:
            SERVER = args.server
        if args.email and len(args.email) > 0:
            EMAIL = args.email
        if args.api_key and len(args.api_key) > 0:
            TOKEN = args.api_key
        controller_config["server"] = SERVER
        controller_config["email"] = EMAIL
        controller_config["token"] = TOKEN

    elif command == "confluence_scan":
        SERVER = os.getenv("CONFLUENCE_SERVER")
        if not SERVER:
            SERVER = os.getenv("JIRA_SERVER")
        EMAIL = os.getenv("CONFLUENCE_EMAIL")
        if not EMAIL:
            EMAIL = os.getenv("JIRA_EMAIL")
        TOKEN = os.getenv("CONFLUENCE_TOKEN")
        if not TOKEN:
            TOKEN = os.getenv("JIRA_TOKEN")
        if args.server and len(args.server) > 0:
            SERVER = args.server
        if args.email and len(args.email) > 0:
            EMAIL = args.email
        if args.api_key and len(args.api_key) > 0:
            TOKEN = args.api_key
        controller_config["server"] = SERVER
        controller_config["email"] = EMAIL
        controller_config["token"] = TOKEN
    else:
        parser.print_help()
        return

    message = f"n0s1 secret scanner version [{n0s1_version}] - Scan date: {date_utc}"
    utils.log_message(message)
    if DEBUG:
        message = f"Args: {args}"
        utils.log_message(message)
        message = f"Controller settings: {SERVER} {EMAIL}"
        if args.show_matched_secret_on_logs:
            message += f" {TOKEN}"
        utils.log_message(message)

    if not controller.set_config(controller_config):
        sys.exit(-1)

    if args.post_comment:
        post_comment = args.post_comment
    else:
        post_comment = cfg.get("general_params", {}).get("post_comment", False)

    if args.skip_comment:
        skip_comment = args.skip_comment
    else:
        skip_comment = cfg.get("general_params", {}).get("skip_comment", False)
    scan_comment = not skip_comment

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

    scan_arguments = {"scan_comment": scan_comment, "post_comment": post_comment, "secret_manager": secret_manager,
                      "contact_help": contact_help, "label": label, "report_format": report_format, "debug": DEBUG,
                      "show_matched_secret_on_logs": show_matched_secret_on_logs, "scan_target": command,
                      "timeout": timeout, "limit": limit, "scan_scope": scan_scope}
    report_json["tool"]["scan_arguments"] = scan_arguments

    N0S1_TOKEN = os.getenv("N0S1_TOKEN")
    n0s1_pro = spark1.Spark1(token_auth=N0S1_TOKEN)
    mode = "community"
    if n0s1_pro.is_connected(scan_arguments):
        mode = "professional"
    message = f"Starting scan in {mode} mode..."
    utils.log_message(message)

    if args.map and args.map.lower() != "Disabled".lower():
        levels = int(args.map)
        map_data = controller.get_mapping(levels)
        map_file_path = args.map_file
        if not map_file_path:
            map_file_path = "n0s1_map.json"
        with open(map_file_path, "w") as f:
            json.dump(map_data, f)
            utils.log_message(f"Scan scope saved to map file: {map_file_path}")
        return True

    try:
        # Set global variables in the secret_scan module
        secret_scan.set_globals(DEBUG, cfg, report_json)
        secret_scan.scan(regex_config, controller, scan_arguments)
    except KeyboardInterrupt:
        utils.log_message("Keyboard interrupt detected. Saving findings and exiting...")
        sys.exit(130)
    except Exception as e:
        utils.log_message("Execution interrupted by an exception. Saving partial report and exiting...")
        utils.log_message(e)
        sys.exit(1)
    finally:
        _save_report(report_format)
        utils.log_message("Done!")


def get_scope_config(args):
    scope_config = None
    if args.scope:
        scope_terms = ["jql", "cql", "search", "query"]
        for t in scope_terms:
            query_index = args.scope.lower().replace(" ", "").find(f"{t}:".lower())
            if query_index == 0:
                query = args.scope[len(t)+1:]
                scope_config = {t: query}
                return scope_config

    if args.map and args.map.lower() != "Disabled".lower():
        # New mapping. Skipp loading old mapped scope
        return scope_config
    if args.map_file:
        map_file = args.map_file
        if os.path.exists(map_file):
            with open(map_file, "r") as f:
                scope_config = json.load(f)
            if args.scope and scope_config:
                fields = str(args.scope).split("/")
                if len(fields) > 1:
                    from langchain_text_splitters import RecursiveJsonSplitter
                    json_str = json.dumps(scope_config)
                    max_size = len(json_str)
                    chunk_index = int(fields[0]) - 1
                    chunks = int(fields[1])

                    chunk_max = max_size - 1
                    chunk_min = 1
                    chunk_size = int((chunk_min+chunk_max) / 2)

                    max_attempts = int(math.sqrt(max_size) + 5)

                    counter = 0
                    done = False
                    while not done:
                        counter += 1
                        if counter >= max_attempts:
                            break
                        splitter = RecursiveJsonSplitter(max_chunk_size=chunk_size)
                        json_chunks = splitter.split_json(json_data=scope_config)

                        if len(json_chunks) == chunks:
                            done = True
                        else:
                            if DEBUG:
                                message = f"Search counter: [{counter}]/[{max_attempts}] | Split nodes: {len(json_chunks)} | Binary search: {chunk_min}  < [chunk_size:{chunk_size}] < {chunk_max}"
                                utils.log_message(message,level=logging.WARNING)

                            if len(json_chunks) < chunks:
                                # chunk_size too big
                                chunk_max = chunk_size
                            else:
                                # chunk_size too small
                                chunk_min = chunk_size

                            chunk_size = int((chunk_min+chunk_max) / 2)

                    if len(json_chunks) > chunk_index:
                        scope_config = json_chunks[chunk_index]
        else:
            utils.log_message(f"Map file [{map_file}] not found!", level=logging.WARNING)

    return scope_config


if __name__ == "__main__":
    main(utils.log_message)
