import logging

try:
    import clients.http_client as http_client
except Exception:
    import n0s1.clients.http_client as http_client


class Spark1(http_client.HttpClient):
    def __init__(self, headers: dict = None, server: str = None, options: dict[str, str | bool] = None,
                 basic_auth: tuple[str, str] | None = None, token_auth: str | None = None, validate=False,
                 get_server_info: bool = True, async_: bool = False, async_workers: int = 5,
                 max_retries: int = 3, timeout: None | float | tuple[float, float] | tuple[float, None] | None = None,
                 auth: tuple[str, str] = None):
        self.base_url = "https://spark1security.ai"
        if server:
            self.base_url = server
        authorization = basic_auth
        if token_auth:
            authorization = token_auth
        if not headers:
            headers = {
                "Content-Type": "application/json",
                "Authorization": authorization,
            }
        else:
            headers["Authorization"] = authorization
        super().__init__(uri=self.base_url, logging=logging, headers=headers)

    def is_connected(self):
        auth_url = self.base_url + "/auth"
        try:
            self._get_request(auth_url)
        except Exception as ex:
            logging.info(str(ex))
            return False
        return True

