import argparse
import hashlib
import logging
import json
import os
import re
import sys
import toml
import yaml
from datetime import datetime, timezone

try:
    import controllers.platform_controller as platform_controller
except:
    import n0s1.controllers.platform_controller as platform_controller


global report_json, report_file, cfg


def init_argparse() -> argparse.ArgumentParser:
    """Adds arguements that can be called from the command line

    Returns:
        argparse.ArgumentParser: A parser that contains the command line options
    """
    install_path = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        prog="n0s1",
        description="""Secret scanner for Project Management platforms such as Jira, Linear and Servicenow.
        """,
    )
    parser.add_argument(
        "--regex-file",
        dest="regex_file",
        nargs="?",
        default=f"{install_path}/config/regex.toml",
        type=str,
        help="Custom .toml with a list of regexes to be matched."
    )
    parser.add_argument(
        "--config-file",
        dest="config_file",
        nargs="?",
        default=f"{install_path}/config/config.yaml",
        type=str,
        help="Configuration file (YAML format) to be used."
    )
    parser.add_argument(
        "--report-file",
        dest="report_file",
        nargs="?",
        default="n0s1_report.json",
        type=str,
        help="Output report file for the leaked secrets."
    )
    parser.add_argument(
        "--post-comment",
        dest="post_comment",
        action="store_true",
        help="By default, scans only flag leaked secrets; this adds a warning comment to every ticket with a potential secret leak",
    )
    parser.add_argument(
        "--skip-comment",
        dest="skip_comment",
        action="store_true",
        help="By default, scans check the ticket title, description and comments; this flag disables ticket comment scanning",
    )
    subparsers = parser.add_subparsers(
        help="Subcommands", dest="command", metavar="COMMAND"
    )

    linear_scan_parser = subparsers.add_parser(
        "linear_scan", help="Scan Linear tickets",
    )
    linear_scan_parser.add_argument(
        "--api-key",
        dest="api_key",
        nargs="?",
        type=str,
        help="Linear API key. Ref: https://developers.linear.app/docs/graphql/working-with-the-graphql-api#personal-api-keys"
    )

    jira_scan_parser = subparsers.add_parser(
        "jira_scan", help="Scan Jira tickets",
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
    return parser


def _sanitize_text(text, begin, end):
    text_len = len(text)
    s_begin = max(begin-20, 0)
    s_end = min(end+20, text_len)
    sanitized_text = text[s_begin:begin] + "<REDACTED>" + text[end:s_end]
    snippet_text = text[s_begin:s_end]
    return sanitized_text, snippet_text


def _sha1_hash(to_hash):
    try:
        message_digest = hashlib.sha1()
        string_m = str(to_hash)
        byte_m = bytes(string_m, encoding='utf')
        message_digest.update(byte_m)
        return message_digest.hexdigest()
    except TypeError:
        raise "Unable to generate SHA-1 hash for input string"


def _save_report():
    global report_json, report_file

    try:
        with open(report_file, "w") as f:
            json.dump(report_json, f)
            return True
    except Exception as e:
        logging.error(e)

    return False


def match_regex(regex_config, text):
    for c in regex_config["rules"]:
        regex_str = c["regex"]
        m = re.search(regex_str, text)
        if m:
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
    logging.info(f"\n\nMATCH! id: {regex_id}, description: [{regex_description}]\nRegex: {regex}. Platform: {platform}. Field: ticket {field}")
    logging.info(f"\n############### Secret ###############\n{snippet_text}\n############### Secret ###############")
    logging.info(f"\n########## Secret sanitized ##########\n{sanitized_secret}\n########## Secret sanitized ##########")
    logging.info(url)
    logging.info("\n\n")
    finding_id = url + "_" + sanitized_secret
    finding_id = _sha1_hash(finding_id)
    new_finding = {"id": finding_id, "url": url, "secret": sanitized_secret,
                   "details": {"matched_regex_config": scan_text_result["matched_regex_config"], "platform": platform, "ticket_field": field}}
    if finding_id not in report_json["findings"]:
        report_json["findings"][finding_id] = new_finding
        _save_report()
    if post_comment:
        comment_template = cfg.get("comment_params", {}).get("message_template", "")
        bot_name = cfg.get("comment_params", {}).get("bot_name", "bot")
        secret_manager = cfg.get("comment_params", {}).get("secret_manager", "")
        contact_help = cfg.get("comment_params", {}).get("contact_help", "")
        label = cfg.get("comment_params", {}).get("label", "")
        comment = comment_template.format(bot_name=bot_name, regex_config_id=regex_id, regex_config_description=regex_description,
                                          regex=regex, platform=platform, field=field, leak=sanitized_secret,
                                          secret_manager=secret_manager, contact_help=contact_help, label=label)
        return controller.post_comment(issue_id, comment)
    return True


def scan_text(regex_config, text):
    match = False
    scan_text_result = {}
    try:
        matched_regex_config, secret, sanitized_secret, snippet_text = match_regex(regex_config, str(text))
        scan_text_result = {"matched_regex_config": matched_regex_config, "secret": secret,
                            "sanitized_secret": sanitized_secret, "snippet_text": snippet_text}
        if matched_regex_config:
            match = True
    except Exception as e:
        logging.warning(e)

    return match, scan_text_result


def scan(regex_config, controller, scan_comment, post_comment):
    if not regex_config or not controller:
        return
    for title, description, comments, url, issue_id in controller.get_data(scan_comment):
        ticket_data = {"title": title, "description": description, "comments": comments, "url": url, "issue_id": issue_id}
        label = cfg.get("comment_params", {}).get("label", "")
        post_comment_for_this_issue = post_comment
        if post_comment_for_this_issue:
            for comment in comments:
                if comment.lower().find(label.lower()) != -1:
                    # Comment with leak warning has been already posted. Skip
                    # posting a new comment again
                    post_comment_for_this_issue = False
                    break
        scan_arguments = {"scan_comment": scan_comment, "post_comment": post_comment_for_this_issue}

        secret_found, scan_text_result = scan_text(regex_config, title)
        scan_text_result["ticket_data"] = ticket_data
        scan_text_result["ticket_data"]["field"] = "title"
        scan_text_result["ticket_data"]["platform"] = controller.get_name()
        scan_text_result["scan_arguments"] = scan_arguments
        if secret_found:
            report_leaked_secret(scan_text_result, controller)

        secret_found, scan_text_result = scan_text(regex_config, description)
        scan_text_result["ticket_data"] = ticket_data
        scan_text_result["ticket_data"]["field"] = "description"
        scan_text_result["ticket_data"]["platform"] = controller.get_name()
        scan_text_result["scan_arguments"] = scan_arguments
        if secret_found:
            report_leaked_secret(scan_text_result, controller)

        for comment in comments:
            secret_found, scan_text_result = scan_text(regex_config, comment)
            scan_text_result["ticket_data"] = ticket_data
            scan_text_result["ticket_data"]["field"] = "comment"
            scan_text_result["ticket_data"]["platform"] = controller.get_name()
            scan_text_result["scan_arguments"] = scan_arguments
            if secret_found:
                report_leaked_secret(scan_text_result, controller)


def main():
    global report_json, report_file, cfg

    logging.basicConfig(level=logging.INFO)
    parser = init_argparse()
    args = parser.parse_args()

    regex_config = None
    cfg = {}

    if os.path.exists(args.regex_file):
        with open(args.regex_file, "r") as f:
            regex_config = toml.load(f)
    else:
        logging.warning(f"Regex file [{args.regex_file}] not found!")

    if os.path.exists(args.config_file):
        with open(args.config_file, "r") as f:
            cfg = yaml.load(f, Loader=yaml.FullLoader)
    else:
        logging.warning(f"Config file [{args.config_file}] not found!")

    datetime_now_obj = datetime.now(timezone.utc)
    date_utc = datetime_now_obj.strftime("%Y-%m-%d %H:%M:%S")
    report_json = {"tool": "n0s1",
                   "scan_date": {"timestamp": datetime_now_obj.timestamp(),"date_utc": date_utc},
                   "regex_config": regex_config, "findings": {}}
    report_file = args.report_file

    command = args.command
    controller_factory = platform_controller.factory
    controller = controller_factory.get_platform(command)

    if command == "linear_scan":
        TOKEN = os.getenv("LINEAR_TOKEN")
        if args.api_key and len(args.api_key) > 0:
            TOKEN = args.api_key
        controler_config = {"token": TOKEN}

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
        controler_config = {"server": SERVER, "email": EMAIL, "token": TOKEN}
    else:
        parser.print_help()
        sys.exit(0)

    if not controller.set_config(controler_config):
        sys.exit(-1)

    post_comment = False
    if args.post_comment:
        post_comment = args.post_comment
    else:
        post_comment = cfg.get("general_params", {}).get("post_comment", False)
    scan_comment = not args.skip_comment

    scan(regex_config, controller, scan_comment, post_comment)

    logging.info("Done!")


if __name__ == "__main__":
    main()
