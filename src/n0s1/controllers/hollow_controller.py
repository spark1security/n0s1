import logging


class HollowController:
    def __init__(self):
        self._client = None
        self._config = None
        self._check_connection_after = 200
        self._requests_counter = 0
        self._scan_scope = None
        self.log_message_callback = None
        self._url = None
        self._user = None
        self._password = None

    def set_config(self, config=None):
        if config:
            self._config = config
            self._scan_scope = self._config.get("scan_scope", None)
        return self._config is not None

    def get_config(self):
        if self._config is not None:
            return self._config
        return {}

    def set_log_message_callback(self, log_message_callback):
        self.log_message_callback = log_message_callback

    def get_name(self):
        return "Hollow"

    def connect(self):
        self._requests_counter += 1
        if self._requests_counter > self._check_connection_after:
            self._requests_counter = 0
            if not self.is_connected():
                # Force new connection
                self._client = None

        if not self._client:
            if self.set_config():
                return self.is_connected()
        return True

    def is_connected(self):
        return False

    def get_data(self, include_coments=False, limit=None):
        return {}

    def get_mapping(self, levels=-1, limit=None):
        return {}

    def post_comment(self, issue, comment):
        return self.is_connected()

    def log_message(self, message, level=logging.INFO):
        if self.log_message_callback:
            self.log_message_callback(message, level)
        else:
            print(message)

    def pack_data(self, title, description, comments, url, ticket_key):
        ticket_data = {
            "ticket": {
                "title": {
                    "name": "title",
                    "data": title,
                    "data_type": "str"
                },
                "description": {
                    "name": "description",
                    "data": description,
                    "data_type": "str"
                },
                "comments": {
                    "name": "comments",
                    "data": comments,
                    "data_type": "list"
                }
            },
            "url": url,
            "issue_id": ticket_key
        }
        return ticket_data

    def get_query_from_scope(self):
        query = None
        if self._scan_scope:
            query = self._scan_scope.get("query", None)
            if not query:
                query = self._scan_scope.get("search", None)
            if not query:
                query = self._scan_scope.get("jql", None)
            if not query:
                query = self._scan_scope.get("cql", None)
        return query

    def _get_request(self, url):
        from requests.auth import HTTPBasicAuth
        import requests
        response = None
        try:
            headers = {
                "Content-Type": "application/json"
            }
            if self._user:
                auth = HTTPBasicAuth(self._user, self._password)
                response = requests.request(
                    "GET",
                    url,
                    headers=headers,
                    auth=auth
                )
            else:
                headers["Authorization"] = f"Bearer {self._password}"
                response = requests.request(
                    "GET",
                    url,
                    headers=headers
                )
        except Exception as e:
            self.log_message(str(e))
        return response

    def _post_request(self, url, payload):
        from requests.auth import HTTPBasicAuth
        import requests
        import json
        response = None
        try:
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            if self._user:
                auth = HTTPBasicAuth(self._user, self._password)
                response = requests.request(
                    "POST",
                    url,
                    headers=headers,
                    auth=auth,
                    data=json.dumps(payload)
                )
            else:
                headers["Authorization"] = f"Bearer {self._password}"
                response = requests.request(
                    "POST",
                    url,
                    headers=headers,
                    data=json.dumps(payload)
                )
        except Exception as e:
            self.log_message(str(e))
        return response
