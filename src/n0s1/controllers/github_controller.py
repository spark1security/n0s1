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
        from github import Github
        TOKEN = config.get("token", "")
        self._client = Github(TOKEN)
        self._owner = config.get("owner", "")
        self._repo = config.get("repo", "")
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

    def get_data(self, include_comments=False, limit=None):
        if not self._client:
            return {}

        repos = None
        if self._owner and len(self._owner) > 0:
            org = self._client.get_organization(self._owner)
            repos = org.get_repos()
        else:
            repos = self._client.get_user().get_repos()

        for repo in repos:
            print(f"Searching in repository: {repo.name}")

            # Iterate through each branch
            for branch in repo.get_branches():
                print(f"  Checking branch: {branch.name}")

                # Iterate through each file in the branch
                try:
                    contents = repo.get_contents("", ref=branch.name)
                    while contents:
                        file_content = contents.pop(0)
                        if file_content.type == "dir":
                            contents.extend(repo.get_contents(file_content.path, ref=branch.name))
                        else:
                            # Fetch file content and search for the term
                            file_data = repo.get_contents(file_content.path,
                                                          ref=branch.name).decoded_content.decode(errors='ignore')
                            url = repo.html_url + f"/blob/{branch.name}/{file_content.path}"
                            file = self.pack_data(file_data, url)
                            yield file
                except Exception as e:
                    print(f"  Error accessing branch {branch.name}: {e}")

    def post_comment(self, issue, comment):
        if not self._client:
            return False
        return self._client.post_comment(issue, comment)

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
