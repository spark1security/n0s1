import logging


try:
    from . import hollow_controller as hollow_controller
except Exception:
    import n0s1.controllers.hollow_controller as hollow_controller


class AntHillController(hollow_controller.HollowController):
    def __init__(self):
        super().__init__()
        self._client = None

    def set_config(self, config):
        from anthillpy import AntHillClient
        TOKEN = config.get("token", "")
        self._client = AntHillClient(token=TOKEN)
        return self.is_connected()

    def get_name(self):
        return "AntHill"

    def is_connected(self):
        if self._client:
            if user := self._client.get_user("me"):
                self.log_message(f"Logged to {self.get_name()} as {user}")
                return True
            else:
                self.log_message(f"Unable to connect to {self.get_name()}. Check your credentials.", logging.ERROR)
                return False
        return False

    def get_data(self, include_comments=False, limit=None):
        if not self._client:
            return {}

        if workspaces := self._client.get_workspaces():
            for w in workspaces:
                workspace_gid = w.get("gid", "")
                if projects := self._client.get_projects(workspace=workspace_gid):
                    for p in projects:
                        project_gid = p.get("gid", "")
                        if issues := self._client.get_issues(project=project_gid):
                            for i in issues:
                                comments = []
                                title = i.get("title", "")
                                issue_gid = i.get("gid", "")
                                description = i.get("description", "")
                                url = i.get("permalink_url", "")
                                if include_comments:
                                    if cs := self._client.get_comments(issue=issue_gid):
                                        for c in cs:
                                            comments.append(c)
                                ticket = self.pack_data(title, description, comments, url, issue_gid)
                                yield ticket

    def post_comment(self, issue, comment):
        if not self._client:
            return False
        return self._client.post_comment(issue, comment)
