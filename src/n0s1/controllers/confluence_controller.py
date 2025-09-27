import html
import logging
import time


try:
    from . import hollow_controller as hollow_controller
except Exception:
    import n0s1.controllers.hollow_controller as hollow_controller


class ConfluenceController(hollow_controller.HollowController):
    def __init__(self):
        super().__init__()
        self._url = None
        self._user = None
        self._password = None

    def set_config(self, config=None):
        super().set_config(config)
        from atlassian import Confluence
        SERVER = self._config.get("server", "")
        EMAIL = self._config.get("email", "")
        TOKEN = self._config.get("token", "")
        TIMEOUT = self._config.get("timeout", -1)
        VERIFY_SSL = not self._config.get("insecure", False)
        self._url = SERVER
        self._user = EMAIL
        self._password = TOKEN
        if EMAIL and len(EMAIL) > 0:
            if TIMEOUT and TIMEOUT > 0:
                self._client = Confluence(url=SERVER, verify_ssl=VERIFY_SSL, username=EMAIL, password=TOKEN, timeout=TIMEOUT)
            else:
                self._client = Confluence(url=SERVER, verify_ssl=VERIFY_SSL, username=EMAIL, password=TOKEN)
        else:
            if TIMEOUT and TIMEOUT > 0:
                self._client = Confluence(url=SERVER, verify_ssl=VERIFY_SSL, token=TOKEN, timeout=TIMEOUT)
            else:
                self._client = Confluence(url=SERVER, verify_ssl=VERIFY_SSL, token=TOKEN)
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
            self.log_message(str(e))
        return response

    def get_current_user(self):
        url = f"{self._url}/rest/api/user/current"
        response = self._get_request(url)
        user = response.json() if response and response.status_code == 200 else None
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
            if user := self.get_current_user():
                self.log_message(f"Logged to {self.get_name()} as {user}")
            else:
                self.log_message(f"Unable to connect to {self.get_name()} instance. Check your credentials.", logging.ERROR)
                return False

            if spaces := self._client.get_all_spaces():
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
                        self.log_message(f"Unable to list {self.get_name()} pages. Check your permissions.", logging.ERROR)
                else:
                    self.log_message(f"Unable to list {self.get_name()} spaces. Check your permissions.", logging.ERROR)
            else:
                self.log_message(f"Unable to connect to {self.get_name()} instance. Check your credentials.", logging.ERROR)
        return False

    def _get_workspaces(self, limit=None):
        if self._scan_scope:
            workspaces = []
            for key in self._scan_scope.get("workspaces", {}):
                workspaces.append(key)
            yield workspaces
        else:
            space_start = 0
            if not limit or limit < 0:
                limit = 50
            finished = False
            while not finished:
                try:
                    self.connect()
                    res = self._client.get_all_spaces(start=space_start, limit=limit)
                    spaces = res.get("results", [])
                except Exception as e:
                    message = str(e) + f" get_all_spaces(start={space_start}, limit={limit})"
                    self.log_message(message, logging.WARNING)
                    spaces = [{}]
                    time.sleep(1)
                    continue
                space_start += limit
                if len(spaces) <= 0:
                    finished = True
                yield spaces

    def _get_pages(self, workspace_key, limit=None):
        from atlassian.confluence import ApiPermissionError
        start = 0
        if not limit or limit < 0:
            limit = 50
        pages_start = start
        page_keys = []
        if self._scan_scope:
            page_keys = self._scan_scope.get("workspaces", {}).get(workspace_key, {})
        if len(page_keys) > 0:
            counter = 0
            pages = []
            for key in page_keys:
                counter += 1
                page = self._client.get_page_by_id(key)
                pages.append(page)
                if counter > limit:
                    counter = 0
                    yield pages
                    pages = []
            if len(pages) > 0:
                yield pages
        else:
            if len(workspace_key) > 0:
                pages_finished = False
                while not pages_finished:
                    try:
                        self.connect()
                        pages = self._client.get_all_pages_from_space(workspace_key, start=pages_start, limit=limit)
                    except ApiPermissionError as e:
                        message = str(e) + f" get_all_pages_from_space({workspace_key}, start={pages_start}, limit={limit}). Skipping..."
                        self.log_message(message, logging.WARNING)
                        pages = [{}]
                        break
                    except Exception as e:
                        message = str(e) + f" get_all_pages_from_space({workspace_key}, start={pages_start}, limit={limit})"
                        self.log_message(message, logging.WARNING)
                        pages = [{}]
                        time.sleep(1)
                        continue
                    pages_start += limit
                    if len(pages) <= 0:
                        pages_finished = True
                    yield pages

    def get_mapping(self, levels=-1, limit=None):
        if not self._client:
            return {}
        map_data = {"workspaces": {}}
        for spaces in self._get_workspaces(limit):
            for space in spaces:
                workspace_key = space.get("key", None)
                if workspace_key:
                    map_data["workspaces"][workspace_key] = {}
                    if levels < 0 or levels > 1:
                        for pages in self._get_pages(workspace_key, limit):
                            for page in pages:
                                page_id = page.get("id", None)
                                page_title = page.get("title", "")
                                if page_id:
                                    map_data["workspaces"][workspace_key][page_id] = {"title": page_title}
        return map_data

    def get_data(self, include_coments=False, limit=None):
        if not self._client:
            return {}

        pages = []
        using_cql = False
        cql = self.get_query_from_scope()
        if cql:
            try:
                res = self._client.cql(cql, limit=limit)
                while res:
                    results = res.get("results", [])
                    for r in results:
                        content_type = r.get("content", {}).get("type", None)
                        if content_type and content_type.lower() == "page".lower():
                            pages.append(r.get("content", {}))

                    next = res.get("_links", {}).get("next", None)
                    res = None
                    if next:
                        url = f"{self._url}/wiki{next}"
                        response = self._get_request(url)
                        if response:
                            res = response.json()

                if len(pages) > 0:
                    using_cql = True
                    yield from self.process_pages(include_coments, limit, pages)
                else:
                    message = f"No pages found for [cql:{cql}]. Scan will not be scoped."
                    self.log_message(message, logging.WARNING)
                    self._scan_scope = None
            except Exception as e:
                message = str(e) + f" cql({cql}, limit={limit})"
                self.log_message(message, logging.WARNING)

        if using_cql:
            return

        for spaces in self._get_workspaces(limit):
            for s in spaces:
                key = s
                if isinstance(s, dict):
                    key = s.get("key", "")
                self.log_message(f"Scanning Confluence space: [{key}]...")
                if len(key) > 0:
                    for pages in self._get_pages(key, limit):
                        yield from self.process_pages(include_coments, limit, pages)

    def process_pages(self, include_coments, limit, pages):
        for p in pages:
            comments = []
            title = p.get("title", "")
            page_id = p.get("id", "")
            try:
                self.connect()
                body = self._client.get_page_by_id(page_id, expand="body.storage")
            except Exception as e:
                message = str(e) + f" get_page_by_id({page_id})"
                self.log_message(message, logging.WARNING)
                body = {}
                time.sleep(1)
                continue

            description = body.get("body", {}).get("storage", {}).get("value", "")
            url = body.get("_links", {}).get("base", "") + p.get("_links", {}).get("webui", "")
            if len(page_id) > 0 and include_coments:
                if not limit or limit < 0:
                    limit = 50
                comments_start = 0
                comments_finished = False
                while not comments_finished:
                    try:
                        self.connect()
                        comments_response = self._client.get_page_comments(page_id, expand="body.storage",
                                                                           start=comments_start, limit=limit)
                        comments_result = comments_response.get("results", [])
                    except Exception as e:
                        message = str(
                            e) + f" get_page_comments({page_id}, expand=\"body.storage\", start={comments_start}, limit={limit})"
                        self.log_message(message, logging.WARNING)
                        comments_result = [{}]
                        time.sleep(1)
                        continue
                    comments_start += limit

                    for c in comments_result:
                        comment = c.get("body", {}).get("storage", {}).get("value", "")
                        comments.append(comment)

                    if len(comments_result) <= 0:
                        comments_finished = True

            ticket = self.pack_data(title, description, comments, url, page_id)
            yield ticket

    def post_comment(self, issue, comment):
        if not self._client:
            return False
        comment = comment.replace("#", "0")
        comment = html.escape(comment, quote=True)
        status = -1
        self.connect()
        if comment_status := self._client.add_comment(issue, comment):
            status = comment_status.get("id", "")
        return int(status) > 0
