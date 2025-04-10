import logging


try:
    from . import hollow_controller as hollow_controller
except Exception:
    import n0s1.controllers.hollow_controller as hollow_controller


class AsanaController(hollow_controller.HollowController):
    def __init__(self):
        super().__init__()

    def set_config(self, config=None):
        super().set_config(config)
        import asana
        TOKEN = self._config.get("token", "")
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

    def _get_workspaces(self, limit=None):
        workspaces = []
        if self._scan_scope:
            for key in self._scan_scope.get("workspaces", {}):
                w = self._client.workspaces.get_workspace(key)
                workspaces.append(w)
        if len(workspaces) > 0:
            return workspaces
        self.connect()
        return self._client.workspaces.get_workspaces()

    def _get_projects(self, workspace_gid, limit=None):
        projects = []
        if self._scan_scope:
            for key in self._scan_scope.get("workspaces", {}).get(workspace_gid, {}).get("projects", {}):
                p = self._client.projects.get_project(key)
                projects.append(p)
        if len(projects) > 0:
            return projects
        self.connect()
        return self._client.projects.get_projects_for_workspace(workspace_gid)

    def _get_tasks(self, workspace_gid, project_gid, limit=None):
        tasks = []
        if self._scan_scope:
            for key in self._scan_scope.get("workspaces", {}).get(workspace_gid, {}).get("projects", {}).get(project_gid, {}).get("tasks", {}):
                t = self._client.tasks.get_task(key, opt_fields=["name", "gid", "notes", "permalink_url"])
                tasks.append(t)
        if len(tasks) > 0:
            return tasks
        self.connect()
        return self._client.tasks.get_tasks_for_project(project_gid, opt_fields=["name", "gid", "notes", "permalink_url"])

    def _get_stories(self, workspace_gid, project_gid, task_gid, limit=None):
        stories = []
        if self._scan_scope:
            for key in self._scan_scope.get("workspaces", {}).get(workspace_gid, {}).get("projects", {}).get(project_gid, {}).get("tasks", {}).get(task_gid, {}).get("stories", {}):
                s = self._client.stories.get_story(key)
                stories.append(s)
        if stories:
            return stories
        self.connect()
        return self._client.stories.get_stories_for_task(task_gid)

    def get_mapping(self, levels=-1, limit=None):
        if not self._client:
            return {}
        map_data = {"workspaces": {}}
        if workspaces := self._get_workspaces(limit):
            for w in workspaces:
                workspace_gid = w.get("gid", "")
                if len(workspace_gid) > 0:
                    w_item = {
                        "gid": workspace_gid,
                        "name": w.get("name", ""),
                        "projects": {}
                    }
                    map_data["workspaces"][workspace_gid] = w_item
                    if levels > 0 and levels <= 1:
                        continue
                    if projects := self._get_projects(workspace_gid, limit):
                        for p in projects:
                            project_gid = p.get("gid", "")
                            p_item = {
                                "gid": project_gid,
                                "name": p.get("name", ""),
                                "tasks": {}
                            }
                            if len(project_gid) > 0:
                                map_data["workspaces"][workspace_gid]["projects"][project_gid] = p_item
                            if levels > 0 and levels <= 2:
                                continue
                            tasks = self._get_tasks(workspace_gid, project_gid)
                            for t in tasks:
                                task_gid = t.get("gid", "")
                                t_item = {
                                    "gid": task_gid,
                                    "name": t.get("name", ""),
                                    "stories": {}
                                }
                                if len(task_gid) > 0:
                                    map_data["workspaces"][workspace_gid]["projects"][project_gid]["tasks"][task_gid] = t_item
                                if levels > 0 and levels <= 3:
                                    continue
                                stories = self._get_stories(workspace_gid, project_gid, task_gid, limit)
                                for s in stories:
                                    story_gid = s.get("gid", "")
                                    s_item = {
                                        "gid": story_gid,
                                        "name": s.get("name", "")
                                    }
                                    if len(story_gid) > 0:
                                        map_data["workspaces"][workspace_gid]["projects"][project_gid]["tasks"][task_gid]["stories"][story_gid] = s_item

        return map_data

    def get_data(self, include_coments=False, limit=None):
        if not self._client:
            return {}

        if workspaces := self._get_workspaces(limit):
            for w in workspaces:
                workspace_gid = w.get("gid", "")
                if projects := self._get_projects(workspace_gid, limit):
                    for p in projects:
                        project_gid = p.get("gid", "")
                        if tasks := self._get_tasks(workspace_gid, project_gid, limit=None):
                            for t in tasks:
                                comments = []
                                title = t.get("name", "")
                                task_gid = t.get("gid", "")
                                description = t.get("notes", "")
                                url = t.get("permalink_url", "")
                                if include_coments:
                                    if stories := self._get_stories( workspace_gid, project_gid, task_gid, limit):
                                        for s in stories:
                                            if s.get("type", "").lower() == "comment".lower():
                                                comment = s.get("text", "")
                                                comments.append(comment)
                                ticket = self.pack_data(title, description, comments, url, task_gid)
                                yield ticket

    def post_comment(self, task_gid, comment):
        if not self._client:
            return False
        self.connect()
        if comment_status := self._client.stories.create_story_for_task(task_gid, {"type": "comment", "text": comment}):
            status = comment_status.get("text", "")
        return len(status) > 0
