import logging


try:
    from . import hollow_controller as hollow_controller
except Exception:
    import n0s1.controllers.hollow_controller as hollow_controller


class GitHubController(hollow_controller.HollowController):
    def __init__(self):
        super().__init__()
        self._client = None

    def set_config(self, config=None):
        super().set_config(config)
        from github import Github
        TOKEN = config.get("token", "")
        self._client = Github(TOKEN)
        self._owner = config.get("owner", "")
        self._repo = config.get("repo", "")
        self._branch = config.get("branch", "")
        return self.is_connected()

    def get_name(self):
        return "GitHub"

    def is_connected(self):
        if self._client:
            if user := self._client.get_user():
                self.log_message(f"Logged to {self.get_name()} as {user}")
                return True
            else:
                self.log_message(f"Unable to connect to {self.get_name()}. Check your credentials.", logging.ERROR)
                return False
        return False

    def _get_repo_fullname(self, repo_name):
        owner = self._owner
        repo_fullname = ""

        git_suffix = ".git"
        suffix_len = len(git_suffix)
        repo_name_len = len(repo_name)
        git_url_suffix = repo_name.lower()[repo_name_len-suffix_len:]
        if git_url_suffix == git_suffix:
            repo_fullname = repo_name.lower().replace("git://github.com/", "")
            repo_fullname = repo_fullname[:-suffix_len]
            return repo_fullname

        if not owner or len(owner) <= 0:
            owner = self._client.get_user().login
        repo_fullname = owner + "/" + repo_name
        return repo_fullname

    def _get_repo_obj(self, repo_gid=None):
        if self._repo and len(self._repo) > 0:
            repo_name = self._get_repo_fullname(self._repo)
            return self._client.get_repo(repo_name)
        full_name = self._get_repo_fullname(repo_gid)
        return self._client.get_repo(full_name)

    def _get_repos(self):
        owner = {}
        repos = []

        if self._scan_scope:
            owner = self._scan_scope.get("owner", {})
            for key in self._scan_scope.get("repos", {}):
                repos.append(key)
        if len(repos) > 0:
            return repos, owner
        self.connect()
        if self._owner and len(self._owner) > 0:
            from github import UnknownObjectException
            try:
                org = self._client.get_organization(self._owner)
                repos = org.get_repos()
                owner = {"type": "org", "name": self._owner}
            except UnknownObjectException as e:
                try:
                    message = f"Unable to get ORG {self._owner} as owner: {e}"
                    self.log_message(message, logging.WARNING)
                    message = f"Trying to get user {self._owner} as owner..."
                    self.log_message(message, logging.WARNING)
                    repos = self._client.get_user(self._owner).get_repos()
                    owner = {"type": "user", "name": self._owner}
                except Exception as e:
                    message = f"Unable to get repos from {self._owner}: {e}"
                    self.log_message(message, logging.ERROR)
        else:
            user = self._client.get_user()
            repos = user.get_repos()
            owner = {"type": "authenticated_user", "name": user.login}

        if self._repo and len(self._repo) > 0:
            for r in repos:
                if r.name.lower() == self._repo.lower():
                    return [r], owner
            return [], owner

        return repos, owner

    def _filter_branches(self, branches, repo_gid):
        filtered_branches = branches
        if self._branch and len(self._branch) > 0:
            filtered_branches = []
            input_branches = self._branch.split(",")
            if len(input_branches) == 1:
                if input_branches[0].lower() == "default".lower():
                    # Special case for default branch
                    self.connect()
                    repo_obj = self._get_repo_obj(repo_gid)
                    if repo_obj:
                        filtered_branches.append(repo_obj.default_branch)
                        return filtered_branches
            for b in branches:
                branch_name = b.name if hasattr(b, 'name') else b
                if branch_name in input_branches and branch_name not in filtered_branches:
                    filtered_branches.append(b)
        return filtered_branches

    def _get_branches(self, repo_gid, limit=None):
        branches = []
        if self._scan_scope:
            branches = self._scan_scope.get("repos", {}).get(repo_gid, {}).get("branches", {})
        if len(branches) > 0:
            return self._filter_branches(branches, repo_gid)
        self.connect()
        repo_obj = self._get_repo_obj(repo_gid)
        if repo_obj:
            branches = repo_obj.get_branches()
        return self._filter_branches(branches, repo_gid)

    def _get_files(self, repo_gid, branch_gid, limit=None):
        files = []
        files_content = []
        if self._scan_scope:
            files = self._scan_scope.get("repos", {}).get(repo_gid, {}).get("branches", {}).get(branch_gid, {}).get("files", [])
        if len(files) > 0:
            return files, files_content
        self.connect()
        repo_obj = self._get_repo_obj(repo_gid)
        if repo_obj:
            files = []
            try:
                contents = repo_obj.get_contents("", ref=branch_gid)
                while contents:
                    file_content = contents.pop(0)
                    if file_content.type == "dir":
                        contents.extend(repo_obj.get_contents(file_content.path, ref=branch_gid))
                    else:
                        files.append(file_content.path)
                        files_content.append(file_content)
            except Exception as e:
                message = f"Error listing files from branch {branch_gid}: {e}"
                self.log_message(message, logging.ERROR)
        return files, files_content

    def get_mapping(self, levels=-1, limit=None):
        if not self._client:
            return {}
        repos, owner = self._get_repos()
        map_data = {"owner": owner, "repos": {}}
        if repos:
            for repo in repos:
                repo_gid = repo.git_url
                message = f"Searching in repository: {repo.html_url}"
                self.log_message(message, logging.INFO)
                if len(repo_gid) > 0:
                    r_item = {
                        "gid": repo_gid,
                        "name": repo.name,
                        "branches": {}
                    }
                    map_data["repos"][repo_gid] = r_item
                    if levels > 0 and levels <= 1:
                        continue
                    if branches := self._get_branches(repo_gid, limit):
                        for branch in branches:
                            message = f"Searching in branch: {branch.name}"
                            self.log_message(message, logging.INFO)
                            branch_gid = branch.name
                            b_item = {
                                "gid": branch.commit.sha,
                                "name": branch.name,
                                "files": {}
                            }
                            if len(branch_gid) > 0:
                                map_data["repos"][repo_gid]["branches"][branch_gid] = b_item
                            if levels > 0 and levels <= 2:
                                continue
                            files, files_content = self._get_files(repo_gid, branch_gid)
                            map_data["repos"][repo_gid]["branches"][branch_gid]["files"] = files
                            if levels > 0 and levels <= 3:
                                continue
        return map_data

    def get_data(self, include_comments=False, limit=None):
        if not self._client:
            return {}

        repos = None
        q = self.get_query_from_scope()
        if q:
            repos = self._client.search_repositories(query=q)
        if not repos:
            repos, owner = self._get_repos()
        if repos:
            for repo in repos:
                if isinstance(repo, str):
                    repo = self._get_repo_obj(repo)
                repo_gid = repo.git_url
                repo_html_url = repo.html_url
                message = f"Searching in repository: {repo_html_url}"
                self.log_message(message, logging.INFO)

                # Iterate through each branch
                for branch in self._get_branches(repo_gid):
                    branch_gid = ""
                    if isinstance(branch, str):
                        branch_gid = branch
                    else:
                        branch_gid = branch.name
                    message = f"Searching in branch: {branch_gid}"
                    self.log_message(message, logging.INFO)

                    # Iterate through each file in the branch
                    try:
                        files, files_content = self._get_files(repo_gid, branch_gid)
                        use_preloaded_content = False
                        if len(files_content) > 0:
                            use_preloaded_content = True
                            files = files_content
                        for f in files:
                            try:
                                if use_preloaded_content:
                                    file_data = f.decoded_content.decode(errors='ignore')
                                    f = f.path
                                else:
                                    # Fetch file content
                                    file_data = repo.get_contents(f, ref=branch_gid).decoded_content.decode(errors='ignore')
                                url = repo.html_url + f"/blob/{branch_gid}/{f}"
                                file = self.pack_data(file_data, url)
                                yield file
                            except Exception as e:
                                message = f"Error accessing file {f} from branch {branch_gid}: {e}"
                                self.log_message(message, logging.ERROR)
                    except Exception as e:
                        message = f"Error accessing branch {branch_gid}: {e}"
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
