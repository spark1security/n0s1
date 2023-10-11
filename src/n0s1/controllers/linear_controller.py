import logging

try:
    import clients.linear_graphql_client as linear_graphql_client
except:
    import n0s1.clients.linear_graphql_client as linear_graphql_client


class LinearControler():
    def __init__(self):
        self._client = None

    def set_config(self, config):
        TOKEN = config.get("token", "")
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
            user = self._client.get_curret_user()
            if user:
                logging.info(f"Logged to Linear as {user}")
            else:
                logging.error(f"Unable to connect to Linear instance. Check your credentials.")
                return False

            query = {"query": "{ issues { nodes { id } } }", "variables": {}}
            r = self._client.graphql_query(query)
            if r.status_code == 200:
                data = r.json()
                issues = data.get("data", {}).get("issues", {}).get("nodes", [])
                if len(issues) > 0:
                    return True
                else:
                    logging.error(f"Unable to list Linear issues. Check your permissions.")
            else:
                logging.error(f"Unable to connect to Linear instance. Check your credentials.")
        return False

    def get_data(self, include_coments=False):
        if not self._client:
            return None, None, None, None, None
        for linear_data in self._client.get_issues_and_comments(20):
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
                yield title, description, comments, url, issue_key

    def post_comment(self, issue, comment):
        if not self._client:
            return False
        comment_status = self._client.add_comment(issue, comment)
        return comment_status.get("data", {}).get("commentCreate", {}).get("success", False)