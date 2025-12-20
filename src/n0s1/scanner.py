import hashlib
import logging
import json
import math
import os
import pathlib
import re
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

global n0s1_version, DEBUG

try:
    here = pathlib.Path(__file__).parent.resolve()
    init_file = pathlib.Path(here / "__init__.py")
    n0s1_version = re.search(r'^__version__ = [\'"]([^\'"]*)[\'"]', init_file.read_text(), re.M).group(1)
except Exception:
    n0s1_version = "0.0.1"

install_path = os.path.dirname(os.path.abspath(__file__))

regex_file_default_value = f"{install_path}/config/regex.yaml"
config_file_default_value = f"{install_path}/config/config.yaml"
report_file_default_value = "n0s1_report.json"
report_format_default_value = "n0s1"
post_comment_default_value = False
skip_comment_default_value = False
show_matched_secret_on_logs_default_value = False
debug_default_value = False
secret_manager_default_value = "a secret manager tool"
contact_help_default_value = "contact@spark1.us"
label_default_value = "n0s1bot_auto_comment_e869dd5fa15ca0749a350aac758c7f56f56ad9be1"
timeout_default_value = None
limit_default_value = None
insecure_default_value = False
map_default_value = None
map_file_default_value = None
scope_default_value = None
api_key_default_value = None
server_default_value = None
email_default_value = None
owner_default_value = None
repo_default_value = None
branch_default_value = None
scan_path_default_value = None

class SecretScanner():
    def __init__(self, target=None, regex_file=regex_file_default_value, config_file=config_file_default_value,
                 report_file=report_file_default_value, report_format=report_format_default_value,
                 post_comment=post_comment_default_value, skip_comment=skip_comment_default_value,
                 show_matched_secret_on_logs=show_matched_secret_on_logs_default_value, debug=debug_default_value,
                 secret_manager=secret_manager_default_value, contact_help=contact_help_default_value,
                 label=label_default_value, timeout=timeout_default_value, limit=limit_default_value,
                 insecure=insecure_default_value, map=map_default_value, map_file=map_file_default_value,
                 scope=scope_default_value, api_key=api_key_default_value, server=server_default_value,
                 email=email_default_value, owner=owner_default_value, repo=repo_default_value,
                 branch=branch_default_value, scan_path=scan_path_default_value):
        global n0s1_version
        self.logging_function = log_message

        self.target = None
        self.regex_file = None
        self.config_file = None
        self.report_file = None
        self.report_format = None
        self.post_comment = None
        self.skip_comment = None
        self.show_matched_secret_on_logs = None
        self.debug = None
        self.secret_manager = None
        self.contact_help = None
        self.label = None
        self.timeout = None
        self.limit = None
        self.insecure = None
        self.map = None
        self.map_file = None
        self.scope = None
        self.api_key = None
        self.server = None
        self.email = None
        self.owner = None
        self.repo = None
        self.branch = None
        self.scan_path = None

        self.regex_config = None
        self.cfg = None
        self.controller = None
        self.scan_arguments = None
        self.scope_config = None
        self.report_json = None

        datetime_now_obj = datetime.now(timezone.utc)
        date_utc = datetime_now_obj.strftime("%Y-%m-%dT%H:%M:%S")

        self.report_json = {"tool": {"name": "n0s1", "version": n0s1_version, "author": "Spark 1 Security"},
                       "scan_date": {"timestamp": datetime_now_obj.timestamp(), "date_utc": date_utc},
                       "regex_config": {}, "findings": {}}

        self.set(target=target, regex_file=regex_file, config_file=config_file, report_file=report_file, report_format=report_format, post_comment=post_comment, skip_comment=skip_comment, show_matched_secret_on_logs=show_matched_secret_on_logs, debug=debug, secret_manager=secret_manager, contact_help=contact_help, label=label, timeout=timeout, limit=limit, insecure=insecure, map=map, map_file=map_file, scope=scope, api_key=api_key, server=server, email=email, owner=owner, repo=repo, branch=branch, scan_path=scan_path)


    def set(self, target=None, regex_file=None, config_file=None, report_file=None, report_format=None, post_comment=None,
            skip_comment=None, show_matched_secret_on_logs=None, debug=None, secret_manager=None, contact_help=None,
            label=None, timeout=None, limit=None, insecure=None, map=None, map_file=None, scope=None, api_key=None,
            server=None, email=None, owner=None, repo=None, branch=None, scan_path=None):
        global DEBUG
        if target is not None:
            self.target = target
            self._setup_target()
        if regex_file is not None:
            self.regex_file = regex_file
            self._setup_regex_config()
        if config_file is not None:
            self.config_file = config_file
            self._setup_cfg()
        if report_file is not None:
            self.report_file = report_file
        if report_format is not None:
            self.report_format = report_format
        if post_comment is not None:
            self.post_comment = post_comment
        if skip_comment is not None:
            self.skip_comment = skip_comment
        if show_matched_secret_on_logs is not None:
            self.show_matched_secret_on_logs = show_matched_secret_on_logs
        if debug is not None:
            self.debug = debug
        if secret_manager is not None:
            self.secret_manager = secret_manager
        if contact_help is not None:
            self.contact_help = contact_help
        if label is not None:
            self.label = label
        if timeout is not None:
            self.timeout = timeout
        if limit is not None:
            self.limit = limit
        if insecure is not None:
            self.insecure = insecure
        if map is not None:
            self.map = map
            self.scope_config = self.get_scope_config()
        if map_file is not None:
            self.map_file = map_file
            self.scope_config = self.get_scope_config()
        if scope is not None:
            self.scope = scope
            self.scope_config = self.get_scope_config()
        if api_key is not None:
            self.api_key = api_key
        if server is not None:
            self.server = server
        if email is not None:
            self.email = email
        if owner is not None:
            self.owner = owner
        if repo is not None:
            self.repo = repo
        if branch is not None:
            self.branch = branch
        if scan_path is not None:
            self.scan_path = scan_path

        DEBUG = self.debug

        self.scan_arguments = {"scan_comment": not self.skip_comment, "post_comment": self.post_comment, "secret_manager": self.secret_manager,
                          "contact_help": self.contact_help, "label": self.label, "report_format": self.report_format, "debug": self.debug,
                          "show_matched_secret_on_logs": self.show_matched_secret_on_logs, "scan_target": self.target,
                          "timeout": self.timeout, "limit": self.limit, "scan_scope": self.get_scope_config()}
        self.report_json["tool"]["scan_arguments"] = self.scan_arguments

    def _setup_target(self):
        command = self.target

        if command.find("_scan") == -1:
            command += "_scan"

        controller_factory = platform_controller.factory
        self.controller = controller_factory.get_platform(command)
        self.set_logging_function(self.logging_function)

    def set_logging_function(self, logging_function):
        self.logging_function = logging_function
        if self.controller:
            self.controller.set_log_message_callback(self.logging_function)

    def log_message(self, message, level=logging.INFO):
        self.logging_function(message, level)

    def get_controller_mapping(self, levels=-1, limit=None):
        self._set_controller_config()
        return self.controller.get_mapping(levels=levels, limit=limit)

    def _set_controller_config(self):
        controller_config = self.controller.get_config()
        TOKEN = None
        SERVER = None
        EMAIL = None
        if self.target.lower() == "local_scan" or self.target.lower() == "local":
            controller_config["scan_path"] = self.scan_path

        elif self.target.lower() == "linear_scan" or self.target.lower() == "linear":
            TOKEN = os.getenv("LINEAR_TOKEN")
            if self.api_key and len(self.api_key) > 0:
                TOKEN = self.api_key
            controller_config["token"] = TOKEN

        elif self.target.lower() == "slack_scan" or self.target.lower() == "slack":
            TOKEN = os.getenv("SLACK_TOKEN")
            if self.api_key and len(self.api_key) > 0:
                TOKEN = self.api_key
            controller_config["token"] = TOKEN

        elif self.target.lower() == "asana_scan" or self.target.lower() == "asana":
            TOKEN = os.getenv("ASANA_TOKEN")
            if self.api_key and len(self.api_key) > 0:
                TOKEN = self.api_key
            controller_config["token"] = TOKEN

        elif self.target.lower() == "zendesk_scan" or self.target.lower() == "zendesk":
            SERVER = os.getenv("ZENDESK_SERVER")
            EMAIL = os.getenv("ZENDESK_EMAIL")
            TOKEN = os.getenv("ZENDESK_TOKEN")
            if self.server and len(self.server) > 0:
                SERVER = self.server
            if self.email and len(self.email) > 0:
                EMAIL = self.email
            if self.api_key and len(self.api_key) > 0:
                TOKEN = self.api_key
            controller_config["server"] = SERVER
            controller_config["email"] = EMAIL
            controller_config["token"] = TOKEN

        elif self.target.lower() == "github_scan" or self.target.lower() == "github":
            OWNER = os.getenv("GITHUB_ORG")
            REPO = os.getenv("GITHUB_REPO")
            BRANCH = os.getenv("GIT_BRANCH")
            TOKEN = os.getenv("GITHUB_TOKEN")
            if self.owner and len(self.owner) > 0:
                OWNER = self.owner
            if self.repo and len(self.repo) > 0:
                REPO = self.repo
            if self.branch and len(self.branch) > 0:
                BRANCH = self.branch
            if self.api_key and len(self.api_key) > 0:
                TOKEN = self.api_key
            controller_config["owner"] = OWNER
            controller_config["repo"] = REPO
            controller_config["branch"] = BRANCH
            controller_config["token"] = TOKEN

        elif self.target.lower() == "gitlab_scan" or self.target.lower() == "gitlab":
            URL = os.getenv("GITLAB_URL", "https://gitlab.com")
            GROUP = os.getenv("GITLAB_GROUP")
            PROJECT = os.getenv("GITLAB_PROJECT")
            BRANCH = os.getenv("GIT_BRANCH")
            TOKEN = os.getenv("GITLAB_TOKEN")
            if self.server and len(self.server) > 0:
                URL = self.server
            if self.owner and len(self.owner) > 0:
                GROUP = self.owner
            if self.repo and len(self.repo) > 0:
                PROJECT = self.repo
            if self.branch and len(self.branch) > 0:
                BRANCH = self.branch
            if self.api_key and len(self.api_key) > 0:
                TOKEN = self.api_key
            controller_config["url"] = URL
            controller_config["group"] = GROUP
            controller_config["project"] = PROJECT
            controller_config["branch"] = BRANCH
            controller_config["token"] = TOKEN

        elif self.target.lower() == "wrike_scan" or self.target.lower() == "wrike":
            TOKEN = os.getenv("WRIKE_TOKEN")
            if self.api_key and len(self.api_key) > 0:
                TOKEN = self.api_key
            controller_config["token"] = TOKEN

        elif self.target.lower() == "jira_scan" or self.target.lower() == "jira":
            SERVER = os.getenv("JIRA_SERVER")
            EMAIL = os.getenv("JIRA_EMAIL")
            TOKEN = os.getenv("JIRA_TOKEN")
            if self.server and len(self.server) > 0:
                SERVER = self.server
            if self.email and len(self.email) > 0:
                EMAIL = self.email
            if self.api_key and len(self.api_key) > 0:
                TOKEN = self.api_key
            controller_config["server"] = SERVER
            controller_config["email"] = EMAIL
            controller_config["token"] = TOKEN

        elif self.target.lower() == "confluence_scan" or self.target.lower() == "confluence":
            SERVER = os.getenv("CONFLUENCE_SERVER")
            if not SERVER:
                SERVER = os.getenv("JIRA_SERVER")
            EMAIL = os.getenv("CONFLUENCE_EMAIL")
            if not EMAIL:
                EMAIL = os.getenv("JIRA_EMAIL")
            TOKEN = os.getenv("CONFLUENCE_TOKEN")
            if not TOKEN:
                TOKEN = os.getenv("JIRA_TOKEN")
            if self.server and len(self.server) > 0:
                SERVER = self.server
            if self.email and len(self.email) > 0:
                EMAIL = self.email
            if self.api_key and len(self.api_key) > 0:
                TOKEN = self.api_key
            controller_config["server"] = SERVER
            controller_config["email"] = EMAIL
            controller_config["token"] = TOKEN
        else:
            return

        controller_config["timeout"] = self.timeout
        controller_config["limit"] = self.limit
        controller_config["insecure"] = self.insecure
        controller_config["scan_scope"] = self.scope_config

        self.controller.set_config(controller_config)

    def _setup_regex_config(self):
        if os.path.exists(self.regex_file):
            with open(self.regex_file, "r") as f:
                extension = os.path.splitext(self.regex_file)[1]
                if extension.lower() == ".yaml".lower():
                    self.regex_config = yaml.load(f, Loader=yaml.FullLoader)
                else:
                    self.regex_config = toml.load(f)
        else:
            self.log_message(f"Regex file [{self.regex_file}] not found!", level=logging.WARNING)
        self.report_json["regex_config"] = self.regex_config

    def _setup_cfg(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, "r") as f:
                self.cfg = yaml.load(f, Loader=yaml.FullLoader)
        else:
            self.log_message(f"Config file [{self.config_file}] not found!", level=logging.WARNING)

    def save_report(self, report_format=""):
        if len(report_format) <=0:
            report_format = self.report_format
        try:
            if report_format.lower().find("sarif".lower()) != -1:
                github_report = report_sarif.n0s1_report_to_sarif_report(self.report_json)
                github_report.write_report(self.report_file)
                return True
            elif report_format.lower().find("gitlab".lower()) != -1:
                gitlab_report = report_gitlab.n0s1_report_to_gitlab_report(self.report_json)
                gitlab_report.write_report(self.report_file)
                return True
            else:
                with open(self.report_file, "w") as f:
                    json.dump(self.report_json, f)
                    return True
        except Exception as e:
            self.log_message(str(e), level=logging.ERROR)

        return False

    def get_report(self):
        if self.report_json is not None:
            return self.report_json
        return {}

    def report_leaked_secret(self, scan_text_result):
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
        show_matched_secret_on_logs = scan_text_result.get("scan_arguments", {}).get("show_matched_secret_on_logs",
                                                                                     False)
        line_number = scan_text_result.get("line_number", -1)

        finding_info = "Platform:[{platform}] Field:[{field}] ID:[{regex_config_id}] Description:[{regex_config_description}] Regex: {regex}\n############## Sanitized Secret Leak ##############\n {leak}\n############## Sanitized Secret Leak ##############"
        finding_info = finding_info.format(regex_config_id=regex_id, regex_config_description=regex_description,
                                           regex=regex, platform=platform, field=field, leak=sanitized_secret)

        self.log_message("\nPotential secret leak regex match!")
        self.log_message(finding_info)
        if show_matched_secret_on_logs:
            self.log_message(
                f"\n##################### Secret  #####################\n{snippet_text}\n##################### Secret  #####################")

        leak_url = url
        url_with_line_number = False
        if line_number > 0 and (
                self.controller.get_name().lower() == "GitHub".lower() or
                self.controller.get_name().lower() == "GitLab".lower() or
                self.controller.get_name().lower() == "LocalFilesystem".lower()
        ):
            url_with_line_number = True
            leak_url = f"{url}#L{line_number}"
        self.log_message(f"\nLeak source: {leak_url}")

        self.log_message("\n\n")
        finding_id = f"{url}_{sanitized_secret}"
        finding_id = _sha1_hash(finding_id)
        new_finding = {"id": finding_id, "url": url, "secret": sanitized_secret,
                       "details": {"matched_regex_config": scan_text_result["matched_regex_config"],
                                   "platform": platform,
                                   "ticket_field": field}}

        if url_with_line_number:
            new_finding["url"] = leak_url

        if finding_id not in self.report_json["findings"]:
            self.report_json["findings"][finding_id] = new_finding
        if post_comment:
            comment_template = self.cfg.get("comment_params", {}).get("message_template", "")
            bot_name = self.cfg.get("comment_params", {}).get("bot_name", "bot")
            secret_manager = scan_text_result.get("scan_arguments", {}).get("secret_manager", "")
            contact_help = scan_text_result.get("scan_arguments", {}).get("contact_help", "")
            label = scan_text_result.get("scan_arguments", {}).get("label", "")
            format_variables = ["finding_info", "bot_name", "secret_manager", "contact_help", "label"]
            for variable in format_variables:
                if comment_template.find(variable) == -1:
                    comment_template += f"\n{variable}: {{{variable}}}"
            comment = comment_template.format(finding_info=finding_info, bot_name=bot_name,
                                              secret_manager=secret_manager,
                                              contact_help=contact_help, label=label)
            if self.controller.get_name().lower() == "Slack".lower():
                comment = comment + f"\nLeak source: {url}"

            return self.controller.post_comment(issue_id, comment)
        return True

    def get_scope_config(self):
        scope_config = None
        if self.scope:
            scope_terms = ["jql", "cql", "search", "query"]
            for t in scope_terms:
                query_index = self.scope.lower().replace(" ", "").find(f"{t}:".lower())
                if query_index == 0:
                    query = self.scope[len(t) + 1:]
                    scope_config = {t: query}
                    return scope_config

        if self.map and self.map.lower() != "Disabled".lower():
            # New mapping. Skipp loading old mapped scope
            return scope_config
        if self.map_file:
            map_file = self.map_file
            if os.path.exists(map_file):
                with open(map_file, "r") as f:
                    scope_config = json.load(f)
                if self.scope and scope_config:
                    fields = str(self.scope).split("/")
                    if len(fields) > 1:
                        from langchain_text_splitters import RecursiveJsonSplitter
                        json_str = json.dumps(scope_config)
                        max_size = len(json_str)
                        chunk_index = int(fields[0]) - 1
                        chunks = int(fields[1])

                        chunk_max = max_size - 1
                        chunk_min = 1
                        chunk_size = int((chunk_min + chunk_max) / 2)

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
                                if self.debug:
                                    message = f"Search counter: [{counter}]/[{max_attempts}] | Split nodes: {len(json_chunks)} | Binary search: {chunk_min}  < [chunk_size:{chunk_size}] < {chunk_max}"
                                    self.log_message(message, level=logging.WARNING)

                                if len(json_chunks) < chunks:
                                    # chunk_size too big
                                    chunk_max = chunk_size
                                else:
                                    # chunk_size too small
                                    chunk_min = chunk_size

                                chunk_size = int((chunk_min + chunk_max) / 2)

                        if len(json_chunks) > chunk_index:
                            scope_config = json_chunks[chunk_index]
            else:
                self.log_message(f"Map file [{map_file}] not found!", level=logging.WARNING)

        return scope_config

    def get_config(self):
        if self.cfg:
            return self.cfg
        return {}

    def scan(self):

        N0S1_TOKEN = os.getenv("N0S1_TOKEN")
        n0s1_pro = spark1.Spark1(token_auth=N0S1_TOKEN)
        mode = "community"
        if n0s1_pro.is_connected(self.scan_arguments):
            mode = "professional"
        message = f"Starting scan in {mode} mode..."
        self.log_message(message)

        self._set_controller_config()
        if not self.regex_config or not self.controller:
            raise ValueError("No regex configuration provided to the scanner")
            return
        scan_comment = self.scan_arguments.get("scan_comment", False)
        post_comment = self.scan_arguments.get("post_comment", False)
        limit = self.scan_arguments.get("limit", None)

        for ticket in self.controller.get_data(scan_comment, limit):
            issue_id = ticket.get("issue_id")
            url = ticket.get("url")
            if self.debug:
                self.log_message(f"Scanning [{issue_id}]: {url}")

            comments = ticket.get("ticket", {}).get("comments", {}).get("data", [])
            label = self.cfg.get("comment_params", {}).get("label", "")
            post_comment_for_this_issue = post_comment
            if post_comment_for_this_issue:
                for comment in comments:
                    if comment.lower().find(label.lower()) != -1:
                        # Comment with leak warning has been already posted. Skip
                        # posting a new comment again
                        post_comment_for_this_issue = False
                        break
            self.scan_arguments["post_comment"] = post_comment_for_this_issue

            for key in ticket.get("ticket", {}):
                item = ticket.get("ticket", {}).get(key, {})
                name = item.get("name", "")
                data = item.get("data", None)
                data_type = item.get("data_type", None)
                if data_type and data_type.lower() == "str".lower():
                    if data and data.lower().find(label.lower()) == -1:
                        self.scan_text_and_report_leaks(data, name, self.regex_config, self.scan_arguments, ticket)
                elif data_type:
                    for item_data in data:
                        if item_data and item_data.lower().find(label.lower()) == -1:
                            self.scan_text_and_report_leaks(item_data, name, self.regex_config, self.scan_arguments, ticket)
        return self.report_json

    def scan_text_and_report_leaks(self, data, name, regex_config, scan_arguments, ticket):
        secret_found, scan_text_result = scan_text(regex_config, data)
        scan_text_result["ticket_data"] = ticket
        scan_text_result["ticket_data"]["field"] = name
        scan_text_result["ticket_data"]["platform"] = self.controller.get_name()
        scan_text_result["scan_arguments"] = scan_arguments
        if secret_found:
            self.report_leaked_secret(scan_text_result)


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


