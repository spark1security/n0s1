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
        return None, None, None, None, None

    def post_comment(self, issue, comment):
        return self.is_connected()

    def log_message(self, message, level=logging.INFO):
        if self.log_message_callback:
            self.log_message_callback(message, level)
        else:
            print(message)