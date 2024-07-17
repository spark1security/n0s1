import logging
import socket

try:
    import clients.http_client as http_client
except Exception:
    import n0s1.clients.http_client as http_client


def _get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        local_ip = s.getsockname()[0]
    except:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip


class Spark1(http_client.HttpClient):
    def __init__(self, headers: dict = None, server: str = None, options: dict[str, str] = None,
                 basic_auth: tuple[str, str] = None, token_auth: str = None, validate=False,
                 get_server_info: bool = True, async_: bool = False, async_workers: int = 5,
                 max_retries: int = 3, timeout: int = None,
                 auth: tuple[str, str] = None):
        self.base_url = "https://api.spark1.us"
        # self.base_url = "http://127.0.0.1:5000"
        self.local_ip = _get_local_ip()
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

    def is_connected(self, config=None):
        if config is None:
            config = {}
        data = {
            "scanner_ip": self.local_ip,
            "scan_target": config.get("scan_target", ""),
            "report_format": config.get("report_format", "")
        }
        auth_url = self.base_url + "/api/v1/auth"
        try:
            r = self._post_request(auth_url, json=data)
            if r.status_code == 200:
                session_token = r.json().get("token", "")
                if session_token and len(session_token) > 0:
                    return True
        except Exception as ex:
            logging.info(str(ex))
            return False
        return False

