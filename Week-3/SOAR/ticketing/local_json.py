import json
from pathlib import Path
from .base import TicketingBackend


class LocalJSONBackend(TicketingBackend):
    """Idempotent on ticket_id. Re-processing the same evidence is a no-op."""

    def __init__(self, directory):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, ticket_id):
        return self.dir / f"{ticket_id}.json"

    def create(self, ticket):
        path = self._path(ticket["ticket_id"])
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        path.write_text(json.dumps(ticket, indent=2, ensure_ascii=False), encoding="utf-8")
        return ticket

    def get(self, ticket_id):
        path = self._path(ticket_id)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def update_review(self, ticket_id, review_status, analyst_decision):
        allowed = {"Pending Review", "Approved", "Corrected", "Rejected"}
        if review_status not in allowed:
            raise ValueError(f"invalid review_status {review_status!r}")
        t = self.get(ticket_id)
        if t is None:
            raise KeyError(ticket_id)
        t["review_status"] = review_status
        t["analyst_decision"] = analyst_decision
        self._path(ticket_id).write_text(json.dumps(t, indent=2, ensure_ascii=False),
                                         encoding="utf-8")
        return t