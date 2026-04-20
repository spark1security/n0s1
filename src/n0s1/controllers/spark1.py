import logging
import socket
import requests

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


def _inject_cred(req_validator, cred):
    import copy
    req_validator_sensitive = copy.deepcopy(req_validator)

    # Basic auth tuple: replace second element (password/token)
    auth = req_validator_sensitive.get("auth")
    if auth and isinstance(auth, (tuple, list)) and len(auth) == 2:
        req_validator_sensitive["auth"] = (auth[0], cred)
        return req_validator_sensitive

    headers = req_validator_sensitive.get("headers", {})
    auth_header = headers.get("Authorization", "")

    # Bearer / Token header
    for scheme in ("Bearer", "Token", "Basic"):
        if auth_header.lower().startswith(scheme.lower() + " "):
            headers["Authorization"] = f"{scheme} {cred}"
            return req_validator_sensitive

    # Replace any bare Authorization header value
    if auth_header:
        headers["Authorization"] = cred
        return req_validator_sensitive

    # Common API-key headers
    for key in ("X-API-Key", "X-Auth-Token", "X-Access-Token", "Api-Key", "api-key"):
        if key in headers:
            headers[key] = cred
            return req_validator_sensitive

    # Query-param tokens
    params = req_validator_sensitive.get("params", {})
    for key in ("api_key", "token", "access_token", "apikey", "key"):
        if key in params:
            params[key] = cred
            return req_validator_sensitive

    # Fallback: set Authorization header as a bearer token
    headers["Authorization"] = f"Bearer {cred}"
    req_validator_sensitive["headers"] = headers
    return req_validator_sensitive

def _execute_request(req: dict, timeout: int = 15) -> dict:
    try:
        kwargs = {
            "method": req.get("method", None),
            "url": req.get("url", None),
            "headers": req.get("headers", {}),
            "params": req.get("params", {}),
            "timeout": timeout,
            "allow_redirects": True,
        }
        if req.get("auth"):
            kwargs["auth"] = req.get("auth", None)
        req_body = req.get("body", None)
        if req_body:
            if isinstance(req_body, dict):
                kwargs["json"] = req_body
            else:
                kwargs["data"] = req_body
        resp = requests.request(**kwargs)

        return {
            "status_code": resp.status_code,
            "headers": resp.headers,
            "body": resp.text[:2000],
            "error": None,
        }
    except requests.exceptions.Timeout:
        return {"status_code": None, "headers": {}, "body": "", "error": "request timed out"}
    except Exception as exc:
        return {"status_code": None, "headers": {}, "body": "", "error": str(exc)}


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

    def ai_analysis(self, report=None, sensitive_report=None):
        if report is None:
            return None
        auth_url = self.base_url + "/api/v1/analyses"
        updated_report = None
        try:
            # AI agent to generate an HTTP request to validate the credential
            r = self._post_request(auth_url, json=report)
            if r.status_code == 200:
                updated_report = r.json()
                for id in updated_report.get("findings", {}):
                    req_validator = updated_report.get("findings", {})[id].get("ai_report", {}).get("request_validator", {})

                    url = req_validator.get("url", None)
                    method = req_validator.get("method", None)
                    if url and method:
                        cred = sensitive_report.get("findings", {})[id].get("sensitive_secret", None)
                        if cred:
                            req_validator = _inject_cred(req_validator, cred)
                            # Execute the HTTP request generated by AI and store the responses in the report
                            resp = _execute_request(req_validator)
                            updated_report["findings"][id]["ai_report"]["response_validator"] = resp
        except Exception as ex:
            logging.info(str(ex))

        try:
            if updated_report:
                # Submit the updated report with the HTTP responses so the AI agent can confirm which credentials were valid
                r = self._post_request(auth_url, json=updated_report)
                if r.status_code == 200:
                    analyzed_report = r.json()
                    # Return the report with the verdict from the AI agent
                    return analyzed_report

        except Exception as ex:
            logging.info(str(ex))

        return None

