import logging


class HollowController:
    def __init__(self):
        self.client = None
        self.log_message_callback = None

    def set_config(self, config):
        return self.is_connected()

    def set_log_message_callback(self, log_message_callback):
        self.log_message_callback = log_message_callback

    def get_name(self):
        return "Hollow"

    def is_connected(self):
        return False

    def get_data(self, include_coments=False, limit=None):
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
