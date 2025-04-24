import datetime
import logging
import re
import time

try:
    from . import hollow_controller as hollow_controller
except Exception:
    import n0s1.controllers.hollow_controller as hollow_controller


class SlackController(hollow_controller.HollowController):
    def __init__(self):
        super().__init__()

    def set_config(self, config=None):
        super().set_config(config)
        from slack_sdk import WebClient
        from slack_sdk.errors import SlackApiError
        TOKEN = self._config.get("token", "")
        self._client = WebClient(token=TOKEN)
        return self.is_connected()

    def get_name(self):
        return "Slack"

    def is_connected(self):
        if user := self._client.auth_test():
            self.log_message(f"Logged to Slack as {user}")
        else:
            self.log_message(f"Unable to connect to Slack. Check your credentials.", logging.ERROR)
            return False
        return True

    def get_data(self, include_coments=False, limit=None):

        using_scan_scope = False
        query = self.get_query_from_scope()
        if query:
            messages = self.run_slack_query(query)
            for m in messages:
                if len(m) > 0:
                    using_scan_scope = True
                    yield from self._extract_ticket(m)

        if using_scan_scope:
            return

        max_day_range = 365 * 100
        range_days = 1
        now = datetime.datetime.now()

        # Slack query by timestamp works like "greater than >" and "less than <" operators as opposed to ">=" and "<=".
        # If you want to pull messages from 2024-07-14 you have to provide the following query: after:2024-07-13 before:2024-07-15
        # Notice that the messages from the starting date (after:2024-07-13) and the end date (before:2024-07-15) are not included to the query results
        end_day = now + datetime.timedelta(days=1)
        start_day = now - datetime.timedelta(days=range_days)

        start_day_str = start_day.strftime("%Y-%m-%d")
        end_day_str = end_day.strftime("%Y-%m-%d")

        query = f"after:{start_day_str} before:{end_day_str}"
        days_counter = 0
        while days_counter < max_day_range:
            messages = self.run_slack_query(query)
            for m in messages:
                len_messages = len(m)
                if len_messages <= 0:
                    range_days = range_days * 2
                else:
                    range_days = 1
                    yield from self._extract_ticket(m)

            end_day = start_day + datetime.timedelta(days=1)
            start_day = start_day - datetime.timedelta(days=range_days)
            start_day_str = start_day.strftime("%Y-%m-%d")
            end_day_str = end_day.strftime("%Y-%m-%d")
            query = f"after:{start_day_str} before:{end_day_str}"
            days_counter += range_days

    def _extract_ticket(self, message):
        for item in message:
            message = item.get("text", "")
            iid = item.get("iid", "")
            url = item.get("permalink", "")
            ticket = self.pack_data(message, item, url, iid)
            yield ticket

    def post_comment(self, issue, comment):
        from slack_sdk.errors import SlackApiError
        try:
            channel_id, thread_ts = self.extract_channel_id_and_ts(issue)
            if comment and len(comment) > 0 and len(channel_id) > 0 and len(thread_ts) > 0:
                self.connect()
                response = self._client.chat_postMessage(
                    channel=channel_id,
                    text=comment,
                    thread_ts=thread_ts,
                    unfurl_links=False
                )

                self.log_message(f"Message sent successfully")
                response_ts = response.get("ts", "")
                self.log_message(f"Thread Timestamp: {response_ts}")

        except SlackApiError as e:
            error_message = e.response.get("error", "")
            self.log_message(f"Error sending message: {error_message}", logging.ERROR)

    def pack_data(self, message, raw_data, url, iid):
        channel_id = raw_data.get("channel", {}).get("id", "")
        channel_name = raw_data.get("channel", {}).get("name", "")
        is_channel = raw_data.get("channel", {}).get("is_channel", "")
        timestamp = raw_data.get("ts", "")
        slack_type = raw_data.get("type", "")
        ticket_data = {
            "ticket": {
                "message": {
                    "name": "message",
                    "data": message,
                    "data_type": "str"
                },
            },
            "url": url,
            "issue_id": url,
            "raw_data": {
                "iid": iid,
                "channel_name": channel_name,
                "channel_id": channel_id,
                "is_channel": is_channel,
                "timestamp": timestamp,
                "slack_type": slack_type
            }
        }
        return ticket_data

    def search_with_rate_limit(self, query, sort, cursor):
        from slack_sdk.errors import SlackApiError
        response = None
        try:
            self.connect()
            response = self._client.search_messages(query=query, sort=sort, cursor=cursor)
        except SlackApiError as ex:
            message = str(ex) + f" client.search_messages()"
            self.log_message(message, logging.WARNING)
            retry_after = ex.response.headers.get("Retry-After", "")
            if len(retry_after) <= 0:
                retry_after = ex.response.headers.get("retry-after", "")
            if len(retry_after) > 0:
                retry_after = int(retry_after)
            else:
                retry_after = 30
            retry_after += 5
            self.log_message(f"Rate limit reached! Retrying after [{retry_after}] seconds...", logging.WARNING)
            time.sleep(retry_after)
            response = self.search_with_rate_limit(query, sort, cursor)

        except Exception as ex:
            message = str(ex) + f" client.search_messages()"
            self.log_message(message, logging.ERROR)

        return response

    def run_slack_query(self, query):
        cursor = ""
        self.log_message(f"Scanning Slack messages: [{query}]...")
        time.sleep(0.2)
        if response := self.search_with_rate_limit(query=query, sort="timestamp", cursor="*"):
            messages = response.get("messages", {}).get("matches", [])
            cursor = response.get("messages", {}).get("pagination", {}).get("next_cursor", "")
            yield messages

        while len(cursor) > 0:
            time.sleep(0.2)
            if response := self.search_with_rate_limit(query=query, sort="timestamp", cursor=cursor):
                messages = response.get("messages", {}).get("matches", [])
                cursor = response.get("messages", {}).get("pagination", {}).get("next_cursor", "")
                yield messages

    def extract_channel_id_and_ts(self, link):
        # Extract the channel ID and message timestamp from the link
        match = re.search(r'archives/([^/]+)/p(\d+)', link)
        if match:
            channel_id = match.group(1)
            message_ts = f"{match.group(2)[:10]}.{match.group(2)[10:]}"
            return channel_id, message_ts
        else:
            self.log_message("Invalid Slack link format", logging.ERROR)

        return "", ""
