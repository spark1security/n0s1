import logging


class HollowController:
    def __init__(self):
        self._client = None
        self._config = None
        self._check_connection_after = 200
        self._requests_counter = 0
        self._scan_scope = None
        self.log_message_callback = None

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
