import logging
import time

try:
    from . import hollow_controller as hollow_controller
except Exception:
    import n0s1.controllers.hollow_controller as hollow_controller


class JiraController(hollow_controller.HollowController):
    def __init__(self):
        super().__init__()

    def set_config(self, config=None):
        super().set_config(config)
        from jira import JIRA
        SERVER = self._config.get("server", "")
        EMAIL = self._config.get("email", "")
        TOKEN = self._config.get("token", "")
        TIMEOUT = self._config.get("timeout", -1)
        VERIFY_SSL = not self._config.get("insecure", False)
        options = {"verify": VERIFY_SSL}
        if EMAIL and len(EMAIL) > 0:
            if TIMEOUT and TIMEOUT > 0:
                self._client = JIRA(SERVER, options=options, basic_auth=(EMAIL, TOKEN), timeout=TIMEOUT)
            else:
                self._client = JIRA(SERVER, options=options, basic_auth=(EMAIL, TOKEN))
        else:
            if TIMEOUT and TIMEOUT > 0:
                self._client = JIRA(SERVER, options=options, token_auth=TOKEN, timeout=TIMEOUT)
            else:
                self._client = JIRA(SERVER, options=options, token_auth=TOKEN)
        return self.is_connected()

    def get_name(self):
        return "Jira"

    def is_connected(self):
        if self._client:
            if user := self._client.myself():
                self.log_message(f"Logged to {self.get_name()} as {user}")
            else:
                self.log_message(f"Unable to connect to {self.get_name()} instance. Check your credentials.", logging.ERROR)
                return False

            if projects := self._client.projects():
                project_found = False
                issue_found = False
                for key in projects:
                    project_found = True
                    ql = f"project = '{key}'"
                    for issue in self._client.search_issues(ql):
                        if issue:
                            issue_found = True
                            return True
                if project_found:
                    if issue_found:
                        return True
                    else:
                        self.log_message(f"Unable to list {self.get_name()} issues. Check your permissions.", logging.ERROR)
                else:
                    self.log_message(f"Unable to list {self.get_name()} projects. Check your permissions.", logging.ERROR)
            else:
                self.log_message(f"Unable to connect to {self.get_name()} instance. Check your credentials.", logging.ERROR)
        return False

    def _get_projects(self, limit=None):
        if self._scan_scope:
            projects = []
            for key in self._scan_scope.get("projects", {}):
                projects.append(key)
            return projects
        self.connect()
        return self._client.projects()

    def _get_issues(self, project_key, limit=None):
        from jira.exceptions import JIRAError
        start = 0
        if not limit or limit < 0:
            limit = 50
        issue_start = start
        issue_keys = []
        if self._scan_scope:
            issue_keys = self._scan_scope.get("projects", {}).get(project_key, {})
        if len(issue_keys) > 0:
            counter = 0
            issues = []
            for key in issue_keys:
                counter += 1
                issue = self._client.issue(key)
                issues.append(issue)
                if counter > limit:
                    counter = 0
                    yield issues
                    issues = []
            if len(issues) > 0:
                yield issues
        else:
            ql = f"project = '{project_key}'"
            issues_finished = False
            while not issues_finished:
                try:
                    self.connect()
                    issues = self._client.search_issues(ql, startAt=issue_start, maxResults=limit)
                except JIRAError as e:
                    self.log_message(f"Error while searching issues on Jira project: [{project_key}]. Skipping...",
                                     logging.WARNING)
                    self.log_message(e)
                    issues = [{}]
                    break
                except Exception as e:
                    message = str(e) + f" client.search_issues({ql}, startAt={issue_start}, maxResults={limit})"
                    self.log_message(message, logging.WARNING)
                    issues = [{}]
                    time.sleep(1)
                    continue
                issue_start += limit
                issues_finished = len(issues) <= 0
                yield issues

    def get_mapping(self, levels=-1, limit=None):
        if not self._client:
            return {}
        map_data = {"projects": {}}
        if projects := self._get_projects(limit):
            for project in projects:
                map_data["projects"][str(project.key)] = {}
                if levels < 0 or levels > 1:
                    for issues in self._get_issues(str(project.key), limit):
                        for issue in issues:
                            map_data["projects"][str(project.key)][str(issue.key)] = {}
        return map_data

    def get_data(self, include_coments=False, limit=None):
        from jira.exceptions import JIRAError
        if not self._client:
            return {}
        try:
            self.connect()
            projects = self._get_projects(limit)
        except Exception as e:
            message = str(e) + f" client.projects()"
            self.log_message(message, logging.WARNING)
            projects = []

        for key in projects:
            self.log_message(f"Scanning Jira project: [{key}]...")
            for issues in self._get_issues(key, limit):
                for issue in issues:
                    url = issue.self.split('/rest/api')[0] + "/browse/" + issue.key;
                    title = issue.fields.summary
                    description = issue.fields.description
                    comments = []
                    if include_coments:
                        try:
                            self.connect()
                            issue_comments = self._client.comments(issue.id)
                            comments.extend(c.body for c in issue_comments)
                        except Exception as e:
                            message = str(e) + f" client.comments({issue.id})"
                            self.log_message(message, logging.WARNING)
                            comments = []
                            time.sleep(1)

                    ticket = self.pack_data(title, description, comments, url, issue.key)
                    yield ticket

    def post_comment(self, issue, comment):
        if not self._client:
            return False
        comment = comment.replace("#", "0")
        self.connect()
        comment_status = self._client.add_comment(issue, body=comment)
        status = comment_status.id
        return bool(status and len(status) > 0 and int(status) > 0)
