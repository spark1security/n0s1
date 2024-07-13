import logging


try:
    from . import hollow_controller as hollow_controller
except Exception:
    import n0s1.controllers.hollow_controller as hollow_controller


class AsanaController(hollow_controller.HollowController):
    def __init__(self):
        super().__init__()
        self._client = None

    def set_config(self, config):
        import asana
        TOKEN = config.get("token", "")
        self._client = asana.Client.access_token(TOKEN)
        return self.is_connected()

    def get_name(self):
        return "Asana"

    def is_connected(self):
        if self._client:
            if user := self._client.users.get_user("me"):
                self.log_message(f"Logged to {self.get_name()} as {user}")
            else:
                self.log_message(f"Unable to connect to {self.get_name()} instance. Check your credentials.", logging.ERROR)
                return False

            if spaces := self._client.workspaces.get_workspaces():
                workspace_found = False
                project_found = False
                for s in spaces:
                    workspace_gid = s.get("gid", "")
                    if len(workspace_gid) > 0:
                        workspace_found = True
                        if projects := self._client.projects.get_projects_for_workspace(workspace_gid):
                            for p in projects:
                                project_found = True
                                break
                if workspace_found:
                    if project_found:
                        return True
                    else:
                        self.log_message(f"Unable to list {self.get_name()} projects. Check your permissions.", logging.ERROR)
                else:
                    self.log_message(f"Unable to list {self.get_name()} workspaces. Check your permissions.", logging.ERROR)
            else:
                self.log_message(f"Unable to connect to {self.get_name()} instance. Check your credentials.", logging.ERROR)
        return False

    def get_data(self, include_coments=False, limit=None):
        if not self._client:
            return {}

        if workspaces := self._client.workspaces.get_workspaces():
            for w in workspaces:
                workspace_gid = w.get("gid", "")
                if projects := self._client.projects.get_projects_for_workspace(workspace_gid):
                    for p in projects:
                        project_gid = p.get("gid", "")
                        if tasks := self._client.tasks.get_tasks_for_project(project_gid, opt_fields=["name", "gid", "notes", "permalink_url"]):
                            for t in tasks:
                                comments = []
                                title = t.get("name", "")
                                task_gid = t.get("gid", "")
                                description = t.get("notes", "")
                                url = t.get("permalink_url", "")
                                if include_coments:
                                    if stories := self._client.stories.get_stories_for_task(task_gid):
                                        for s in stories:
                                            if s.get("type", "").lower() == "comment".lower():
                                                comment = s.get("text", "")
                                                comments.append(comment)
                                ticket = self.pack_data(title, description, comments, url, task_gid)
                                yield ticket

    def post_comment(self, task_gid, comment):
        if not self._client:
            return False
        if comment_status := self._client.stories.create_story_for_task(task_gid, {"type": "comment", "text": comment}):
            status = comment_status.get("text", "")
        return len(status) > 0
