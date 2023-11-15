import logging
import time
from datetime import datetime, timezone
from types import ModuleType

try:
    import clients.http_client as http_client
except Exception:
    import n0s1.clients.http_client as http_client


def _generate_query_issues_with_pagination(pagination_arguments):
    query_issues_pagination = f"""
    {{
        issues{pagination_arguments} {{
            edges {{
                node {{
                    id
                    identifier
                    url
                    title
                    description
                    comments {{
                        nodes {{
                            id
                            body
                        }}
                    }}
                }}
                cursor
            }}
            pageInfo {{
                hasNextPage
                endCursor
            }}
        }}
    }}
    """
    return {"query": query_issues_pagination, "variables": {}}


class LinearGraphQLClient(http_client.HttpClient):
    def __init__(
            self,
            headers: dict,
            logging: ModuleType,
            uri: str = None,
    ) -> None:
        if not uri:
            uri = "https://api.linear.app"
        super().__init__(headers, logging, uri)
        self._user = None

    def graphql_query(self, query):
        url = f"{self.uri}/graphql/"
        r = self._post_request(url, json=query)

        # Check for rate limiting
        # https://developers.linear.app/docs/graphql/working-with-the-graphql-api/rate-limiting
        if r.status_code == 200 or 400 <= r.status_code < 500:
            rate_limit = r.headers.get("X-RateLimit-Requests-Limit", -1)
            rate_limit_remaining = r.headers.get("X-RateLimit-Requests-Remaining", -1)
            rate_limit_reset = r.headers.get("X-RateLimit-Requests-Reset", -1)
            if int(rate_limit_remaining) < 20:
                try:
                    self._extracted_from_graphql_query_13(
                        rate_limit_reset, rate_limit_remaining, rate_limit
                    )
                except Exception as e:
                    logging.warning(e)
        return r

    # TODO Rename this here and in `graphql_query`
    def _extracted_from_graphql_query_13(self, rate_limit_reset, rate_limit_remaining, rate_limit):
        timestamp_reset = float(rate_limit_reset) / 1000
        datetime_now_obj = datetime.now(timezone.utc)
        timestamp_now = datetime_now_obj.timestamp()
        retry_after = int(timestamp_reset - timestamp_now) + 5

        reset_datatime = datetime.utcfromtimestamp(timestamp_reset)
        self.logging.warning(
            f"Approaching rate limit! There are [{rate_limit_remaining}] requests remaining out of [{rate_limit}]. Current date: [{datetime_now_obj}] Rate Limit reset time: [{reset_datatime} UTC]. Retrying after [{retry_after}] seconds..."
        )
        if retry_after < 7200:
            time.sleep(retry_after)
        else:
            logging.warning(
                f"Retry after period is too long: [{retry_after}]. Skipping retry period. Header X-RateLimit-Requests-Reset set to {rate_limit_reset} and UTC epoch seconds now is {timestamp_now}.")

    def get_curret_user(self):
        query_me = f"""
        query Me {{
          viewer {{
            id
            name
            email
          }}
        }}
        """
        query = {"query": query_me}
        response = self.graphql_query(query)
        return response.json() if response.status_code == 200 else None

    def get_issue(self, id):
        query_issue = f"""
        query Issue {{
          issue(id: "{id}") {{
            id
            identifier
            url
            title
            description
            comments {{
              nodes {{
                id
                body
              }}
            }}
          }}
        }}
        """
        query = {"query": query_issue}
        response = self.graphql_query(query)
        return response.json() if response.status_code == 200 else None

    def set_issue_title(self, issue_id, title):
        query_issue = f"""
        mutation IssueUpdate {{
          issueUpdate(
            id: "{issue_id}",
            input: {{
              title: "{title}"
            }}
          ) {{
            success
            issue {{
              id
              title
              state {{
                id
                name
              }}
            }}
          }}
        }}
        """
        query = {"query": query_issue}
        response = self.graphql_query(query)
        return response.json() if response.status_code == 200 else None

    def add_comment(self, issue_id, comment):
        comment = comment.replace("\n", "\\n")
        query_issue = f"""
        mutation commentCreate {{
          commentCreate(
            input: {{
              issueId: "{issue_id}",
              body: "{comment}"
            }}
          )
          {{
            success
            comment {{
              id
            }}
          }}
        }}
        """
        query = {"query": query_issue}
        response = self.graphql_query(query)
        return response.json() if response.status_code == 200 else None

    def get_issues_and_comments(self, issues_per_page=100):
        pagination_arguments = f"(first: {issues_per_page})"
        query = _generate_query_issues_with_pagination(pagination_arguments)
        response = self.graphql_query(query)

        page_num = 0
        has_next_page = False
        cursor = None

        if response.status_code == 200:
            r = response.json()
            yield r
            has_next_page = r.get("data", {}).get("issues", {}).get("pageInfo", {}).get("hasNextPage", False)
            cursor = r.get("data", {}).get("issues", {}).get("pageInfo", {}).get("endCursor", None)

        while has_next_page and cursor:
            pagination_arguments = f"(first: {issues_per_page}, after: \"{cursor}\")"
            query = _generate_query_issues_with_pagination(pagination_arguments)
            response = self.graphql_query(query)

            page_num += 1
            scanned_issues = page_num * issues_per_page
            self.logging.info(
                f"Total Linear issues scanned: [{scanned_issues}]. Page number: [{page_num}]. Paginating with cursor: [{cursor}]")

            has_next_page = False
            cursor = None

            if response.status_code == 200:
                r = response.json()
                yield r
                has_next_page = r.get("data", {}).get("issues", {}).get("pageInfo", {}).get("hasNextPage", False)
                cursor = r.get("data", {}).get("issues", {}).get("pageInfo", {}).get("endCursor", None)

        return {}

    def get_all_issues_and_comments(self):
        result = {"data": {"issues": {"edges": [], "pageInfo": {}}}}
        issues_per_page = 100
        for r in self.get_issues_and_comments(issues_per_page):
            if r:
                result["data"]["issues"]["edges"] += r.get("data", {}).get("issues", {}).get("edges", [])
        return result
