class TicketingBackend:
    def create(self, ticket):
        raise NotImplementedError

    def get(self, ticket_id):
        raise NotImplementedError

    def update_review(self, ticket_id, review_status, analyst_decision):
        raise NotImplementedError