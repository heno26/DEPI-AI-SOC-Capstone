class EnrichmentStub:
    """Explicitly does nothing. Never fabricates a reputation verdict."""

    def run(self, doc):
        ev = doc.get("evidence", {}) or {}
        iocs = []
        for key in ("source_ip", "destination_ip", "process_guid", "transaction_id",
                    "process_image"):
            if key in ev and ev[key]:
                iocs.append({"type": key, "value": ev[key], "source": "week2_evidence"})
        if "verified_counts" in ev:
            for k, v in ev["verified_counts"].items():
                iocs.append({"type": k, "value": v, "source": "week2_evidence"})
        return {
            "iocs_extracted": iocs,
            "reputation_lookup": {
                "performed": False,
                "reason": "no live threat-intelligence feed in lab; verdict NOT fabricated",
            },
            "asset_context": {
                "lookup_performed": False,
                "reason": "no asset database in lab",
            },
        }