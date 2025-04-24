import logging


try:
    from . import hollow_controller as hollow_controller
except Exception:
    import n0s1.controllers.hollow_controller as hollow_controller


class ZendeskController(hollow_controller.HollowController):
    def __init__(self):
        super().__init__()
        self._client = None

    def set_config(self, config):
        super().set_config(config)
        from zenpy import Zenpy
        SERVER = self._config.get("server", "")
        EMAIL = self._config.get("email", "")
        TOKEN = self._config.get("token", "")
        creds = {
            "email": EMAIL,
            "token": TOKEN,
            "subdomain": SERVER
        }
        self._client = Zenpy(**creds)
        return self.is_connected()

    def get_name(self):
        return "Zendesk"

    def is_connected(self):
        if self._client:
            if user := self._client.users.me():
                self.log_message(f"Logged to {self.get_name()} as {user} - {user.email}")
                return True
            else:
                self.log_message(f"Unable to connect to {self.get_name()}. Check your credentials.", logging.ERROR)
                return False
        return False

    def get_data(self, include_comments=False, limit=None):
        if not self._client:
            return {}

        try:
            server = self._config.get("server", "")

            using_scan_scope = False
            query = self.get_query_from_scope()
            if query:
                tickets = self._client.search(query=query)
                if len(tickets) > 0:
                    using_scan_scope = True

            if not using_scan_scope:
                # Fetch all tickets (paginated)
                tickets = self._client.tickets()

            for ticket in tickets:
                self.log_message(f"Scanning Zendesk Ticket ID: {ticket.id}, Subject: {ticket.subject}, Status: {ticket.status}, Created: {ticket.created_at}")
                comments = []
                title = ticket.subject
                ticket_id = ticket.id
                description = ticket.description
                url = ticket.url
                if len(server):
                    url = f"https://{server}.zendesk.com/agent/tickets/{ticket_id}"
                if include_comments:
                    if cs := self._client.tickets.comments(ticket_id):
                        for c in cs:
                            c_body = c.body
                            comments.append(c_body)
                ticket = self.pack_data(title, description, comments, url, ticket_id)
                yield ticket
        except Exception as e:
            message = str(e) + f" client.get_data()"
            self.log_message(message, logging.WARNING)

    def post_comment(self, issue, comment):
        if not self._client:
            return False
        from zenpy.lib.api_objects import Ticket, Comment
        c = Comment(body=comment, public=True)
        ticket = Ticket(id=issue, comment=c)
        return self._client.tickets.update(ticket)
