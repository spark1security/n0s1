import logging
import socket
import requests
import json

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

        data = dict(resp.headers)
        resp_headers = json.loads(json.dumps(data))

        return {
            "status_code": resp.status_code,
            "headers": resp_headers,
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
        self.base_url = "https://n0s1.spark1.us"
        self.base_url = "http://127.0.0.1:5000"
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

    def upload_report(self, report: dict, ai_analysis: bool = False):
        if report is None:
            return None
        upload_report_url = self.base_url + "/api/v1/scans"
        try:
            payload = dict(report)
            if ai_analysis:
                payload["ai_analysis"] = True
            r = self._post_request(upload_report_url, json=payload)
            return r
        except Exception as ex:
            logging.info(str(ex))
        return None

    def get_scan_status(self, report_uuid: str):
        if not report_uuid:
            return None
        url = f"{self.base_url}/api/v1/scans/{report_uuid}"
        try:
            r = self._get_request(url)
            if r.status_code == 200:
                return r.json()
        except Exception as ex:
            logging.info(str(ex))
        return None

    def upload_responses(self, report_uuid: str, report: dict):
        if not report_uuid or report is None:
            return None
        url = f"{self.base_url}/api/v1/scans/{report_uuid}"
        try:
            r = self._patch_request(url, json=report)
            return r
        except Exception as ex:
            logging.info(str(ex))
        return None

    def submit_for_ai_analysis(self, report_uuid: str = None, report: dict = None):
        try:
            if report_uuid and not report:
                url = f"{self.base_url}/api/v1/scans/{report_uuid}/analyze"
                r = self._post_request(url, json={})
            else:
                payload = dict(report or {})
                payload["ai_analysis"] = True
                url = f"{self.base_url}/api/v1/scans/analyze"
                r = self._post_request(url, json=payload)
            return r
        except Exception as ex:
            logging.info(str(ex))
        return None


def _execute_request_validators(remote_report: dict, local_report: dict = None) -> dict:
    """Client-side step 2: inject credentials and execute each request_validator."""
    local_findings = (local_report or {}).get("findings", {})
    findings = remote_report.get("findings", {})
    for finding_id, finding in findings.items():
        req_validator = finding.get("ai_report", {}).get("request_validator")
        if not req_validator:
            continue
        if finding.get("ai_report", {}).get("response_validator"):
            continue
        cred = (
            local_findings.get(finding_id, {}).get("sensitive_secret")
            or finding.get("mocked_secret", "")
        )
        if cred:
            req_validator = _inject_cred(req_validator, cred)
        resp = _execute_request(req_validator)
        finding.setdefault("ai_report", {})["response_validator"] = resp
        remote_report["findings"][finding_id] = finding
    return remote_report

