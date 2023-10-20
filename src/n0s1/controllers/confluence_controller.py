import html
import logging


class ConfluenceControler():
    def __init__(self):
        self._client = None
        self._url = None
        self._user = None
        self._password = None

    def set_config(self, config):
        from atlassian import Confluence
        SERVER = config.get("server", "")
        EMAIL = config.get("email", "")
        TOKEN = config.get("token", "")
        self._url = SERVER
        self._user = EMAIL
        self._password = TOKEN
        if EMAIL and len(EMAIL) > 0:
            self._client = Confluence(url=SERVER, username=EMAIL, password=TOKEN)
        else:
            self._client = Confluence(url=SERVER, token=TOKEN)
        return self.is_connected()

    def get_name(self):
        return "Confluence"

    def _get_request(self, url):
        from requests.auth import HTTPBasicAuth
        import requests
        response = None
        try:
            if self._user:
                auth = HTTPBasicAuth(self._user, self._password)
                headers = {
                    "Content-Type": "application/json"
                }
                response = requests.request(
                    "GET",
                    url,
                    headers=headers,
                    auth=auth
                )
            else:
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self._password}"
                }
                response = requests.request(
                    "GET",
                    url,
                    headers=headers
                )
        except Exception as e:
            logging.info(e)
        return response

    def get_current_user(self):
        user = None
        url = f"{self._url}/rest/api/user/current"
        response = self._get_request(url)
        if response and response.status_code == 200:
            user = response.json()
        if user:
            user_type = user.get("type", "")
            if len(user_type) > 0:
                return user
        else:
            url = f"{self._url}/wiki/rest/api/user/current"
            response = self._get_request(url)
            if response and response.status_code == 200:
                user = response.json()
            if user:
                user_type = user.get("type", "")
                if len(user_type) > 0:
                    return user
        return None

    def is_connected(self):
        if self._client:
            user = self.get_current_user()
            if user:
                logging.info(f"Logged to {self.get_name()} as {user}")
            else:
                logging.error(f"Unable to connect to {self.get_name()} instance. Check your credentials.")
                return False

            spaces = self._client.get_all_spaces()

            if spaces:
                space_found = False
                page_found = False
                for s in spaces.get("results", []):
                    key = s.get("key", "")
                    if len(key) > 0:
                        space_found = True
                        pages = self._client.get_all_pages_from_space(key)
                        if len(pages) > 0:
                            page_found = True
                            break
                if space_found:
                    if page_found:
                        return True
                    else:
                        logging.error(f"Unable to list {self.get_name()} pages. Check your permissions.")
                else:
                    logging.error(f"Unable to list {self.get_name()} spaces. Check your permissions.")
            else:
                logging.error(f"Unable to connect to {self.get_name()} instance. Check your credentials.")
        return False

    def get_data(self, include_coments=False):
        if not self._client:
            return None, None, None, None, None

        start = 0
        limit = 500
        finished = False
        while not finished:
            res = self._client.get_all_spaces(start=start, limit=limit)
            start = limit
            limit += start
            spaces = res.get("results", [])

            for s in spaces:
                key = s.get("key", "")
                logging.info(f"Scanning Confluence space: [{key}]...")
                if len(key) > 0:
                    pages_start = 0
                    pages_limit = 50
                    pages_finished = False
                    while not pages_finished:
                        pages = self._client.get_all_pages_from_space(key, start=pages_start, limit=pages_limit)
                        pages_start = pages_limit
                        pages_limit += pages_start

                        for p in pages:
                            comments = []
                            title = p.get("title", "")
                            page_id = p.get("id", "")
                            body = self._client.get_page_by_id(page_id, expand="body.storage")
                            description = body.get("body", {}).get("storage", {}).get("value", "")
                            url = body.get("_links", {}).get("base") + p.get("_links", {}).get("webui", "")
                            if include_coments:
                                comments_start = 0
                                comments_limit = 25
                                comments_finished = False
                                while not comments_finished:
                                    comments_response = self._client.get_page_comments(page_id, expand="body.storage",
                                                                                     start=comments_start,
                                                                                     limit=comments_limit)
                                    comments_start = comments_limit
                                    comments_limit += comments_start
                                    comments_result = comments_response.get("results", [])

                                    for c in comments_result:
                                        comment = c.get("body", {}).get("storage", {}).get("value", "")
                                        comments.append(comment)

                                    if len(comments_result) <= 0:
                                        comments_finished = True

                            yield title, description, comments, url, page_id

                        if len(pages) <= 0:
                            pages_finished = True

            if len(spaces) <= 0:
                finished = True

    def post_comment(self, issue, comment):
        if not self._client:
            return False
        comment = comment.replace("#", "0")
        comment = html.escape(comment, quote=True)
        comment_status = self._client.add_comment(issue, comment)
        if comment_status:
            status = comment_status.get("id", "")
        if int(status) > 0:
            return True
        return False
