"""TheHive adapter STUB. Documents the contract; does NOT talk to a server.

Not tested against a live TheHive instance. Left in place so Week-4 can swap
LocalJSONBackend for a real implementation without changing the dispatcher.
"""
from .base import TicketingBackend


class TheHiveBackend(TicketingBackend):
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.status = "not_implemented"

    def create(self, ticket):
        raise NotImplementedError(
            "TheHiveBackend is a documented stub. Implement POST /api/alert against "
            "TheHive 4 and map ticket fields: title, severity, sourceRef=event_id, "
            "description from ai_triage.summary, tags from playbook_id + alert_rule."
        )

    def get(self, ticket_id):
        raise NotImplementedError

    def update_review(self, ticket_id, review_status, analyst_decision):
        raise NotImplementedError