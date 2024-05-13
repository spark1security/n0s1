import json
import logging
from WrikePy import *


class WrikeControler():
    def __init__(self):
        self._client = None

    def set_config(self, config):
        TOKEN = config.get("token", "")
        base_url = "https://www.wrike.com/api/v4"
        self._client = Wrike(base_url, TOKEN)
        return self.is_connected()

    def get_name(self):
        return "Wrike"

    def is_connected(self):
        if self._client:
            acc = Account(self._client)
            response = acc.query__account()
            logged_in = False
            try:
                if 200 <= response.status_code < 300:
                    acc_info = json.loads(response.text)
                    logged_in = True
                    logging.info(f"Logged to {self.get_name()} as {acc_info}")
            except Exception as ex:
                logging.warning(ex)
                pass
            if not logged_in:
                logging.error(f"Unable to connect to {self.get_name()} instance. Check your credentials.")
                return False

            t = Tasks(self._client, parameters={"fields": ["description"]})
            response = t.query__tasks()
            list_tasks = False

            try:
                if 200 <= response.status_code < 300:
                    tasks = json.loads(response.text)
                    task_list = tasks.get("data", [])
                    if len(task_list) > 0:
                        list_tasks = True
                        return True
            except Exception as ex:
                logging.warning(ex)
                pass
            if not list_tasks:
                logging.error(f"Unable to list {self.get_name()} tasks. Check your permissions.")
        return False

    def get_data(self, include_coments=False, limit=None):
        if not self._client:
            return None, None, None, None, None

        t = Tasks(self._client, parameters={"fields": ["description"]})
        response = t.query__tasks()
        tasks = {}
        try:
            if 200 <= response.status_code < 300:
                tasks = json.loads(response.text)
        except Exception as ex:
            logging.warning(ex)

        task_list = tasks.get("data", [])
        for t in task_list:
            title = t.get("title", "")
            description = t.get("description", "")
            url = t.get("permalink", "")
            comments = []
            if task_id := t.get("id", None):
                if include_coments:
                    comments_obj = Comments(self._client, [task_id])
                    response = comments_obj.query__tasks_taskId_comments()
                    json_data = {}
                    try:
                        if 200 <= response.status_code < 300:
                            json_data = json.loads(response.text)
                    except Exception as ex:
                        logging.warning(ex)

                    c_data = json_data.get("data", [])
                    for c in c_data:
                        comments.append(c.get("text", ""))
                yield title, description, comments, url, task_id

    def post_comment(self, task_id, comment):
        if not self._client:
            return False
        comment = comment.replace("<REDACTED>", "**********")
        comment = comment.replace("\n", "<br>")
        comments_obj = Comments(self._client, [task_id], parameters={"text": comment, "plainText": False})
        if comments_obj:
            response = comments_obj.create__tasks_taskId_comments()
            try:
                if 200 <= response.status_code < 300:
                    json_data = json.loads(response.text)
                    added_comment = json_data.get("data", [])[0]
                    if len(added_comment) > 0:
                        return True
            except Exception as ex:
                logging.warning(ex)
        return False
