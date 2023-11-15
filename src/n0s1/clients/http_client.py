import requests
from requests.models import Response
from types import ModuleType


class HttpClient:
    def __init__(
            self,
            headers: dict,
            logging: ModuleType,
            uri: str = None,
    ) -> None:
        if uri is None:
            raise Exception("Must specify URI")
        self.uri = uri
        self.headers = headers
        self.logging = logging

    def _delete_request(self, url: str = None, params: dict = None, headers: dict = None, data=None) -> Response:
        if url is None or len(url) <= 0:
            url = self.uri
        if headers:
            response = requests.delete(
                url,
                params=params,
                headers={**headers, **self.headers},
                data=data,
            )
        else:
            response = requests.delete(
                url,
                params=params,
                headers=self.headers,
                data=data,
            )
        self.logging.debug(
            f"HTTP DELETE request status: [{response.status_code}]. URL: {url}"
        )
        self.logging.debug(response.text)
        return response

    def _get_request(self, url: str = None, params: dict = None, headers: dict = None, data=None,
                     timeout=None) -> Response:
        if url is None or len(url) <= 0:
            url = self.uri
        if headers:
            response = requests.get(
                url,
                params=params,
                headers={**headers, **self.headers},
                data=data,
                timeout=timeout,
            )
        else:
            response = requests.get(
                url,
                params=params,
                headers=self.headers,
                data=data,
                timeout=timeout,
            )
        self.logging.debug(
            f"HTTP GET request status: [{response.status_code}]. URL: {url}"
        )
        self.logging.debug(response.text)
        return response

    def _post_request(
            self, url: str = None, params: dict = None, headers: dict = None, data=None, json: dict = None
    ) -> Response:
        if url is None or len(url) <= 0:
            url = self.uri
        if headers:
            response = requests.post(
                url,
                params=params,
                headers={**headers, **self.headers},
                data=data,
                json=json,
            )
        else:
            response = requests.post(
                url,
                params=params,
                headers=self.headers,
                data=data,
                json=json,
            )
        self.logging.debug(response.text)
        return response

    def _put_request(self, url: str = None, params: dict = None, headers: dict = None, data=None) -> Response:
        if url is None or len(url) <= 0:
            url = self.uri
        if headers:
            response = requests.put(
                url,
                params=params,
                headers={**headers, **self.headers},
                data=data,
            )
        else:
            response = requests.put(
                url,
                params=params,
                headers=self.headers,
                data=data,
            )
        self.logging.debug(response.text)
        return response
