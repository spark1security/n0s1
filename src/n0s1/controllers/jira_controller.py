import logging


class JiraControler():
    def __init__(self):
        self._client = None

    def set_config(self, config):
        from jira import JIRA
        SERVER = config.get("server", "")
        EMAIL = config.get("email", "")
        TOKEN = config.get("token", "")
        if EMAIL and len(EMAIL) > 0:
            self._client = JIRA(SERVER, basic_auth=(EMAIL, TOKEN))
        else:
            self._client = JIRA(SERVER, token_auth=TOKEN)
        return self.is_connected()

    def get_name(self):
        return "Jira"

    def is_connected(self):
        if self._client:
            user = self._client.myself()
            if user:
                logging.info(f"Logged to {self.get_name()} as {user}")
            else:
                logging.error(f"Unable to connect to {self.get_name()} instance. Check your credentials.")
                return False

            projects = self._client.projects()

            if projects:
                project_found = False
                issue_found = False
                for key in projects:
                    project_found = True
                    ql = f"project = {key}"
                    for issue in self._client.search_issues(ql):
                        if issue:
                            issue_found = True
                            return True
                if project_found:
                    if issue_found:
                        return True
                    else:
                        logging.error(f"Unable to list {self.get_name()} issues. Check your permissions.")
                else:
                    logging.error(f"Unable to list {self.get_name()} projects. Check your permissions.")
            else:
                logging.error(f"Unable to connect to {self.get_name()} instance. Check your credentials.")
        return False

    def get_data(self, include_coments=False):
        if not self._client:
            return None, None, None, None, None
        for key in self._client.projects():
            ql = f"project = {key}"
            logging.info(f"Scanning Jira project: [{key}]...")
            for issue in self._client.search_issues(ql):
                url = issue.self.split('/rest/api')[0] + "/browse/" + issue.key;
                title = issue.fields.summary
                description = issue.fields.description
                comments = []
                if include_coments:
                    issue_comments = self._client.comments(issue.id)
                    for c in issue_comments:
                        comments.append(c.body)
                yield title, description, comments, url, issue.key

    def post_comment(self, issue, comment):
        if not self._client:
            return False
        comment = comment.replace("#", "0")
        comment_status = self._client.add_comment(issue, body=comment)
        status = comment_status.id
        if status and len(status) > 0 and int(status) > 0:
            return True
        return False
