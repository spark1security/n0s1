import logging

try:
    from . import hollow_controller as hollow_controller
except Exception:
    import n0s1.controllers.hollow_controller as hollow_controller

try:
    import clients.linear_graphql_client as linear_graphql_client
except:
    import n0s1.clients.linear_graphql_client as linear_graphql_client


class LinearController(hollow_controller.HollowController):
    def __init__(self):
        super().__init__()

    def set_config(self, config=None):
        super().set_config(config)
        TOKEN = self._config.get("token", "")
        headers = {
            "Content-Type": "application/json",
            "Authorization": TOKEN,
        }
        self._client = linear_graphql_client.LinearGraphQLClient(
            logging=logging,
            headers=headers,
        )
        return self.is_connected()

    def get_name(self):
        return "Linear"

    def is_connected(self):
        if self._client:
            if user := self._client.get_curret_user():
                self.log_message(f"Logged to Linear as {user}")
            else:
                self.log_message("Unable to connect to Linear instance. Check your credentials.", logging.ERROR)
                return False

            query = {"query": "{ issues { nodes { id } } }", "variables": {}}
            r = self._client.graphql_query(query)
            if r.status_code == 200:
                data = r.json()
                issues = data.get("data", {}).get("issues", {}).get("nodes", [])
                if len(issues) > 0:
                    return True
                else:
                    self.log_message("Unable to list Linear issues. Check your permissions.", logging.ERROR)
            else:
                self.log_message("Unable to connect to Linear instance. Check your credentials.", logging.ERROR)
        return False

    def get_data(self, include_coments=False, limit=None):
        if not self._client:
            return {}
        self.connect()
        for linear_data in self._client.get_issues_and_comments(20):
            self.connect()
            for edge in linear_data.get("data", {}).get("issues", {}).get("edges", []):
                item = edge.get("node", {})
                url = item.get("url", "")
                title = item.get("title", "")
                description = item.get("description", "")
                issue_key = item.get("identifier", "")
                comments = []
                if include_coments:
                    for node in item.get("comments", {}).get("nodes", []):
                        comment = node.get("body", "")
                        if len(comment) > 0:
                            comments.append(comment)
                ticket = self.pack_data(title, description, comments, url, issue_key)
                yield ticket

    def post_comment(self, issue, comment):
        if not self._client:
            return False
        comment_status = self._client.add_comment(issue, comment)
        return comment_status.get("data", {}).get("commentCreate", {}).get("success", False)
