import argparse
import hashlib
import logging
import json
import os
import pathlib
import re
import sys
import toml
import yaml
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

global n0s1_version, report_json, report_file, cfg, DEBUG


def log_message(message, level=logging.INFO):
    global DEBUG
    debug_file = "n0s1_debug.log"

    if level == logging.NOTSET or level == logging.DEBUG:
        logging.debug(message)
    if level == logging.INFO:
        logging.info(message)
    if level == logging.WARNING:
        logging.warning(message)
    if level == logging.ERROR:
        logging.error(message)
    if level == logging.CRITICAL:
        logging.critical(message)

    if DEBUG:
        with open(debug_file, "a") as f:
            if f.tell() == 0:
                f.write("Debug logging message for n0s1\n")
            f.write(f"{message}\n")


def init_argparse() -> argparse.ArgumentParser:
    global n0s1_version
    """Adds arguements that can be called from the command line

    Returns:
        argparse.ArgumentParser: A parser that contains the command line options
    """
    install_path = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        prog="n0s1",
        description="""Secret scanner for Slack, Jira, Confluence, Asana, Wrike and Linear.
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


def _sanitize_text(text, begin, end):
    text_len = len(text)
    s_begin = max(begin - 20, 0)
    s_end = min(end + 20, text_len)
    sanitized_text = f"{text[s_begin:begin]}<REDACTED>{text[end:s_end]}"
    snippet_text = text[s_begin:s_end]
    return sanitized_text, snippet_text


def _sha1_hash(to_hash):
    try:
        message_digest = hashlib.sha256()
        string_m = str(to_hash)
        byte_m = bytes(string_m, encoding='utf')
        message_digest.update(byte_m)
        return message_digest.hexdigest()
    except TypeError as e:
        raise "Unable to generate SHA-256 hash for input string" from e


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
        log_message(str(e), level=logging.ERROR)

    return False


def _safe_re_search(regex_str, text):
    global DEBUG
    m = None
    try:
        m = re.search(regex_str, text)
    except Exception:
        try:
            regex_str = regex_str.replace("(?i)", "")
            m = re.search(regex_str, text, re.IGNORECASE)
        except Exception as e:
            if DEBUG:
                log_message(str(e))
    return m


def match_regex(regex_config, text):
    for c in regex_config["rules"]:
        regex_str = c["regex"]
        if m := _safe_re_search(regex_str, text):
            begin = m.regs[0][0]
            end = m.regs[0][1]
            matched_text = text[begin:end]
            sanitized_text, snippet_text = _sanitize_text(text, begin, end)
            return c, matched_text, sanitized_text, snippet_text
    return None, None, None, None


def report_leaked_secret(scan_text_result, controller):
    global report_json, cfg
    snippet_text = scan_text_result.get("snippet_text", "")
    sanitized_secret = scan_text_result.get("sanitized_secret", "")
    matched = scan_text_result.get("matched_regex_config", {})
    regex_id = matched.get("id", "")
    regex_description = matched.get("description", "")
    regex = matched.get("regex", "")
    platform = scan_text_result.get("ticket_data", {}).get("platform", "")
    field = scan_text_result.get("ticket_data", {}).get("field", "")
    url = scan_text_result.get("ticket_data", {}).get("url", "")
    issue_id = scan_text_result.get("ticket_data", {}).get("issue_id", "")
    post_comment = scan_text_result.get("scan_arguments", {}).get("post_comment", False)
    show_matched_secret_on_logs = scan_text_result.get("scan_arguments", {}).get("show_matched_secret_on_logs", False)

    finding_info = "Platform:[{platform}] Field:[{field}] ID:[{regex_config_id}] Description:[{regex_config_description}] Regex: {regex}\n############## Sanitized Secret Leak ##############\n {leak}\n############## Sanitized Secret Leak ##############"
    finding_info = finding_info.format(regex_config_id=regex_id, regex_config_description=regex_description,
                                       regex=regex, platform=platform, field=field, leak=sanitized_secret)

    log_message("\nPotential secret leak regex match!")
    log_message(finding_info)
    if show_matched_secret_on_logs:
        log_message(
            f"\n##################### Secret  #####################\n{snippet_text}\n##################### Secret  #####################")
    log_message(f"\nLeak source: {url}")
    log_message("\n\n")
    finding_id = f"{url}_{sanitized_secret}"
    finding_id = _sha1_hash(finding_id)
    new_finding = {"id": finding_id, "url": url, "secret": sanitized_secret,
                   "details": {"matched_regex_config": scan_text_result["matched_regex_config"], "platform": platform,
                               "ticket_field": field}}
    if finding_id not in report_json["findings"]:
        report_json["findings"][finding_id] = new_finding
    if post_comment:
        comment_template = cfg.get("comment_params", {}).get("message_template", "")
        bot_name = cfg.get("comment_params", {}).get("bot_name", "bot")
        secret_manager = scan_text_result.get("scan_arguments", {}).get("secret_manager", "")
        contact_help = scan_text_result.get("scan_arguments", {}).get("contact_help", "")
        label = scan_text_result.get("scan_arguments", {}).get("label", "")
        format_variables = ["finding_info", "bot_name", "secret_manager", "contact_help", "label"]
        for variable in format_variables:
            if comment_template.find(variable) == -1:
                comment_template += f"\n{variable}: {{{variable}}}"
        comment = comment_template.format(finding_info=finding_info, bot_name=bot_name, secret_manager=secret_manager,
                                          contact_help=contact_help, label=label)
        if controller.get_name().lower() == "Slack".lower():
            comment = comment + f"\nLeak source: {url}"

        return controller.post_comment(issue_id, comment)
    return True


def scan_text(regex_config, text):
    global DEBUG
    match = False
    scan_text_result = {}
    try:
        matched_regex_config, secret, sanitized_secret, snippet_text = match_regex(regex_config, str(text))
        scan_text_result = {"matched_regex_config": matched_regex_config, "secret": secret,
                            "sanitized_secret": sanitized_secret, "snippet_text": snippet_text}
        if matched_regex_config:
            match = True
    except Exception as e:
        if DEBUG:
            log_message(str(e), level=logging.WARNING)
    return match, scan_text_result


def scan(regex_config, controller, scan_arguments):
    global DEBUG
    if not regex_config or not controller:
        return
    scan_comment = scan_arguments.get("scan_comment", False)
    post_comment = scan_arguments.get("post_comment", False)
    limit = scan_arguments.get("limit", None)

    for ticket in controller.get_data(scan_comment, limit):
        issue_id = ticket.get("issue_id")
        url = ticket.get("url")
        if DEBUG:
            log_message(f"Scanning [{issue_id}]: {url}")

        comments = ticket.get("ticket", {}).get("comments", {}).get("data", [])
        label = cfg.get("comment_params", {}).get("label", "")
        post_comment_for_this_issue = post_comment
        if post_comment_for_this_issue:
            for comment in comments:
                if comment.lower().find(label.lower()) != -1:
                    # Comment with leak warning has been already posted. Skip
                    # posting a new comment again
                    post_comment_for_this_issue = False
                    break
        scan_arguments["post_comment"] = post_comment_for_this_issue

        for key in ticket.get("ticket", {}):
            item = ticket.get("ticket", {}).get(key, {})
            name = item.get("name", "")
            data = item.get("data", None)
            data_type = item.get("data_type", None)
            if data_type and data_type.lower() == "str".lower():
                if data and data.lower().find(label.lower()) == -1:
                    scan_text_and_report_leaks(controller, data, name, regex_config, scan_arguments, ticket)
            elif data_type:
                for item_data in data:
                    if item_data and item_data.lower().find(label.lower()) == -1:
                        scan_text_and_report_leaks(controller, item_data, name, regex_config, scan_arguments, ticket)


def scan_text_and_report_leaks(controller, data, name, regex_config, scan_arguments, ticket):
    secret_found, scan_text_result = scan_text(regex_config, data)
    scan_text_result["ticket_data"] = ticket
    scan_text_result["ticket_data"]["field"] = name
    scan_text_result["ticket_data"]["platform"] = controller.get_name()
    scan_text_result["scan_arguments"] = scan_arguments
    if secret_found:
        report_leaked_secret(scan_text_result, controller)


def main(callback=None):
    global n0s1_version, report_json, report_file, cfg, DEBUG

    logging.basicConfig(level=logging.INFO)
    parser = init_argparse()
    args = parser.parse_args()

    regex_config = None
    cfg = {}

    if not args.command:
        parser.print_help()
        return

    if os.path.exists(args.regex_file):
        with open(args.regex_file, "r") as f:
            extension = os.path.splitext(args.regex_file)[1]
            if extension.lower() == ".yaml".lower():
                regex_config = yaml.load(f, Loader=yaml.FullLoader)
            else:
                regex_config = toml.load(f)
    else:
        log_message(f"Regex file [{args.regex_file}] not found!", level=logging.WARNING)

    if os.path.exists(args.config_file):
        with open(args.config_file, "r") as f:
            cfg = yaml.load(f, Loader=yaml.FullLoader)
    else:
        log_message(f"Config file [{args.config_file}] not found!", level=logging.WARNING)

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

    DEBUG = args.debug

    message = f"n0s1 secret scanner version [{n0s1_version}] - Scan date: {date_utc}"
    log_message(message)
    if DEBUG:
        message = f"Args: {args}"
        log_message(message)
        message = f"Controller settings: {SERVER} {EMAIL}"
        if args.show_matched_secret_on_logs:
            message += f" {TOKEN}"
        log_message(message)

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
                      "timeout": timeout, "limit": limit}
    report_json["tool"]["scan_arguments"] = scan_arguments

    N0S1_TOKEN = os.getenv("N0S1_TOKEN")
    n0s1_pro = spark1.Spark1(token_auth=N0S1_TOKEN)
    mode = "community"
    if n0s1_pro.is_connected(scan_arguments):
        mode = "professional"
    message = f"Starting scan in {mode} mode..."
    log_message(message)

    try:
        scan(regex_config, controller, scan_arguments)
    except KeyboardInterrupt:
        log_message("Keyboard interrupt detected. Saving findings and exiting...")
        sys.exit(130)
    except Exception as e:
        log_message("Execution interrupted by an exception. Saving partial report and exiting...")
        log_message(e)
        sys.exit(1)
    finally:
        _save_report(report_format)
        log_message("Done!")


if __name__ == "__main__":
    main(log_message)
