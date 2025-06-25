import hashlib
import logging
import re

# Global variables that will be set by the main module
DEBUG = False
cfg = {}
report_json = {}


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
        modifiers = ["(?i)", "(?m)", "(?s)", "(?x)", "(?g)", "(?u)", "(?A)", "(?L)", "(?U)", ]
        for modifier in modifiers:
            if regex_str.find(modifier) > 0:
                regex_str = regex_str.replace(modifier, "")
                regex_str = modifier + regex_str
        if m := _safe_re_search(regex_str, text):
            begin = m.regs[0][0]
            end = m.regs[0][1]
            matched_text = text[begin:end]
            sanitized_text, snippet_text = _sanitize_text(text, begin, end)
            tmp = text[:begin]
            lines = tmp.split("\n")
            line_number = len(lines)
            return c, matched_text, sanitized_text, snippet_text, line_number
    return None, None, None, None, None


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
    line_number = scan_text_result.get("line_number", -1)

    finding_info = "Platform:[{platform}] Field:[{field}] ID:[{regex_config_id}] Description:[{regex_config_description}] Regex: {regex}\n############## Sanitized Secret Leak ##############\n {leak}\n############## Sanitized Secret Leak ##############"
    finding_info = finding_info.format(regex_config_id=regex_id, regex_config_description=regex_description,
                                       regex=regex, platform=platform, field=field, leak=sanitized_secret)

    log_message("\nPotential secret leak regex match!")
    log_message(finding_info)
    if show_matched_secret_on_logs:
        log_message(
            f"\n##################### Secret  #####################\n{snippet_text}\n##################### Secret  #####################")

    leak_url = url
    url_with_line_number = False
    if line_number > 0 and (controller.get_name().lower() == "GitHub".lower() or controller.get_name().lower() == "GitLab".lower()) :
        url_with_line_number = True
        leak_url = f"{url}#L{line_number}"
    log_message(f"\nLeak source: {leak_url}")

    log_message("\n\n")
    finding_id = f"{url}_{sanitized_secret}"
    finding_id = _sha1_hash(finding_id)
    new_finding = {"id": finding_id, "url": url, "secret": sanitized_secret,
                   "details": {"matched_regex_config": scan_text_result["matched_regex_config"], "platform": platform,
                               "ticket_field": field}}

    if url_with_line_number:
        new_finding["url"] = leak_url

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
        matched_regex_config, secret, sanitized_secret, snippet_text, line_number = match_regex(regex_config, str(text))
        scan_text_result = {"matched_regex_config": matched_regex_config, "secret": secret, "sanitized_secret": sanitized_secret,
                            "snippet_text": snippet_text, "line_number": line_number}
        if matched_regex_config:
            match = True
    except Exception as e:
        if DEBUG:
            log_message(str(e), level=logging.WARNING)
    return match, scan_text_result


def scan_text_and_report_leaks(controller, data, name, regex_config, scan_arguments, ticket):
    secret_found, scan_text_result = scan_text(regex_config, data)
    scan_text_result["ticket_data"] = ticket
    scan_text_result["ticket_data"]["field"] = name
    scan_text_result["ticket_data"]["platform"] = controller.get_name()
    scan_text_result["scan_arguments"] = scan_arguments
    if secret_found:
        report_leaked_secret(scan_text_result, controller)


def scan(regex_config, controller, scan_arguments):
    global DEBUG, cfg
    if not regex_config or not controller:
        raise ValueError("No regex configuration provided to the scanner")
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


def set_globals(debug_flag, config_dict, report_dict):
    """Set global variables from the main module"""
    global DEBUG, cfg, report_json
    DEBUG = debug_flag
    cfg = config_dict
    report_json = report_dict
