import logging


try:
    from . import hollow_controller as hollow_controller
except Exception:
    import n0s1.controllers.hollow_controller as hollow_controller


class GitLabController(hollow_controller.HollowController):
    def __init__(self):
        super().__init__()
        self._client = None

    def set_config(self, config=None):
        super().set_config(config)
        import gitlab
        TOKEN = config.get("token", "")
        URL = config.get("url", "https://gitlab.com")
        self._client = gitlab.Gitlab(URL, private_token=TOKEN)
        self._group = config.get("group", "")
        self._project = config.get("project", "")
        self._branch = config.get("branch", "")
        return self.is_connected()

    def get_name(self):
        return "GitLab"

    def is_connected(self):
        if self._client:
            try:
                self._client.auth()
                user = self._client.user
                self.log_message(f"Logged to {self.get_name()} as {user.username}")
                return True
            except Exception as e:
                self.log_message(f"Unable to connect to {self.get_name()}. Check your credentials: {e}", logging.ERROR)
                return False
        return False

    def _get_project_obj(self, project_id=None):
        if self._group and self._project and  len(self._group) and len(self._project) > 0:
            path_with_namespace = f"{self._group}/{self._project}".lower()
            return self._client.projects.get(path_with_namespace)
        return self._client.projects.get(project_id)

    def _get_projects(self):
        owner = {}
        projects = []

        if self._scan_scope:
            owner = self._scan_scope.get("owner", {})
            for key in self._scan_scope.get("projects", {}):
                projects.append(key)
        if len(projects) > 0:
            return projects, owner
        
        self.connect()
        if self._group and len(self._group) > 0:
            try:
                group = self._client.groups.get(self._group)
                projects = group.projects.list(all=True)
                owner = {"type": "group", "name": self._group}
            except Exception as e:
                message = f"Unable to get projects from group {self._group}: {e}"
                self.log_message(message, logging.ERROR)
        else:
            projects = self._client.projects.list(all=True)
            owner = {"type": "authenticated_user", "name": self._client.user.username}

        if self._project and len(self._project) > 0:
            for p in projects:
                path_with_namespace = f"{self._group}/{self._project}".lower()
                if p.path_with_namespace.lower() == path_with_namespace or str(p.id) == self._project:
                    return [p], owner
            try:
                # Try direct access by ID or path
                project = self._client.projects.get(self._project)
                return [project], owner
            except Exception:
                return [], owner

        return projects, owner

    def _filter_branches(self, branches, project_id):
        filtered_branches = branches
        if self._branch and len(self._branch) > 0:
            filtered_branches = []
            input_branches = self._branch.split(",")
            if len(input_branches) == 1:
                if input_branches[0].lower() == "default".lower():
                    # Special case for default branch
                    self.connect()
                    project_obj = self._get_project_obj(project_id)
                    if project_obj:
                        filtered_branches.append(project_obj.default_branch)
                        return filtered_branches
            for b in branches:
                branch_name = b.name if hasattr(b, 'name') else b
                if branch_name in input_branches and branch_name not in filtered_branches:
                    filtered_branches.append(b)
        return filtered_branches

    def _get_branches(self, project_id, limit=None):
        branches = []
        if self._scan_scope:
            project_id_str = str(project_id)
            branches = self._scan_scope.get("projects", {}).get(project_id_str, {}).get("branches", {})
        if len(branches) > 0:
            return self._filter_branches(branches, project_id)
        
        self.connect()
        project_obj = self._get_project_obj(project_id)
        if project_obj:
            branches = project_obj.branches.list(all=True)
        return self._filter_branches(branches, project_id)

    def _get_files(self, project_id, branch_name, path="", limit=None):
        files = []
        if self._scan_scope:
            files = self._scan_scope.get("projects", {}).get(project_id, {}).get("branches", {}).get(branch_name, {}).get("files", [])
        if len(files) > 0:
            return files
        
        self.connect()
        project_obj = self._get_project_obj(project_id)
        if project_obj:
            try:
                items = project_obj.repository_tree(path=path, ref=branch_name, recursive=True, all=True)
                for item in items:
                    if item['type'] == 'blob':
                        files.append(item['path'])
            except Exception as e:
                message = f"Error listing files from branch {branch_name}: {e}"
                self.log_message(message, logging.ERROR)
        return files

    def get_mapping(self, levels=-1, limit=None):
        if not self._client:
            return {}
        
        projects, owner = self._get_projects()
        map_data = {"owner": owner, "projects": {}}
        
        if projects:
            for project in projects:
                project_id = project.id if hasattr(project, 'id') else project
                project_name = project.path_with_namespace if hasattr(project, 'path_with_namespace') else project
                
                message = f"Searching in project: {project_name}"
                self.log_message(message, logging.INFO)
                
                if project_id:
                    p_item = {
                        "id": project_id,
                        "name": project_name,
                        "branches": {}
                    }
                    map_data["projects"][project_id] = p_item
                    
                    if levels > 0 and levels <= 1:
                        continue
                        
                    if branches := self._get_branches(project_id, limit):
                        for branch in branches:
                            branch_name = branch.name if hasattr(branch, 'name') else branch
                            message = f"Searching in branch: {branch_name}"
                            self.log_message(message, logging.INFO)
                            
                            b_item = {
                                "name": branch_name,
                                "files": {}
                            }
                            
                            if branch_name:
                                map_data["projects"][project_id]["branches"][branch_name] = b_item
                                
                            if levels > 0 and levels <= 2:
                                continue
                                
                            files = self._get_files(project_id, branch_name)
                            map_data["projects"][project_id]["branches"][branch_name]["files"] = files
                            
                            if levels > 0 and levels <= 3:
                                continue
        return map_data

    def get_data(self, include_comments=False, limit=None):
        if not self._client:
            return {}

        projects = None
        q = self.get_query_from_scope()
        if q:
            projects = self._client.projects.list(search=q, all=True)
        if not projects:
            projects, owner = self._get_projects()
            
        if projects:
            for project in projects:
                # Always get the full project object to ensure all attributes are available
                if hasattr(project, 'id'):
                    project_id = project.id
                    # Get the full project object
                    try:
                        project = self._client.projects.get(project_id)
                    except Exception as e:
                        message = f"Error getting full project object for ID {project_id}: {e}"
                        self.log_message(message, logging.ERROR)
                        continue
                else:
                    project_id = project
                    try:
                        project = self._get_project_obj(project_id)
                    except Exception as e:
                        message = f"Error getting project object for ID {project_id}: {e}"
                        self.log_message(message, logging.ERROR)
                        continue
                
                project_name = project.path_with_namespace
                project_url = project.web_url
                project_id = project.id
                
                message = f"Searching in project: {project_name}"
                self.log_message(message, logging.INFO)

                # Iterate through each branch
                for branch in self._get_branches(project_id):
                    branch_name = branch.name if hasattr(branch, 'name') else branch
                    message = f"Searching in branch: {branch_name}"
                    self.log_message(message, logging.INFO)

                    # Iterate through each file in the branch
                    try:
                        files = self._get_files(project_id, branch_name)
                        for file_path in files:
                            try:
                                # Fetch file content
                                file_content = project.files.get(file_path=file_path, ref=branch_name)
                                raw_content = file_content.decode()
                                # Properly decode bytes to string
                                if isinstance(raw_content, bytes):
                                    file_data = raw_content.decode('utf-8', errors='replace')
                                else:
                                    file_data = raw_content
                                url = f"{project_url}/-/blob/{branch_name}/{file_path}"
                                file = self.pack_data(file_data, url)
                                yield file
                            except Exception as e:
                                message = f"Error accessing file {file_path} from branch {branch_name}: {e}"
                                self.log_message(message, logging.ERROR)
                    except Exception as e:
                        message = f"Error accessing branch {branch_name}: {e}"
                        self.log_message(message, logging.ERROR)

    def post_comment(self, issue, comment):
        if not self._client:
            return False
        message = f"Unable to post comment to {issue}!"
        self.log_message(message, logging.ERROR)
        return False

    def pack_data(self, file_data, url):
        ticket_data = {
            "ticket": {
                "file": {
                    "name": "file",
                    "data": file_data,
                    "data_type": "str"
                },
            },
            "url": url,
            "issue_id": url
        }
        return ticket_data