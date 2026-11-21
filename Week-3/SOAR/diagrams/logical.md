# Logical Playbook Flow

```mermaid
flowchart TD
  A[Evidence JSON] --> B{Envelope valid?<br/>human_validation_required==true}
  B -- no --> Z1[Reject: invalid envelope]
  B -- yes --> C{qa_status in<br/>SCHEMA_PASS / REVIEW_REQUIRED?}
  C -- no --> Z2[Reject: unknown QA status]
  C -- yes --> D[Route by source_trigger.key]
  D --> E{Playbook found?}
  E -- no --> Z3[Skip: no route]
  E -- yes --> F[Tier 0: parse + extract IOCs + enrich stub]
  F --> G{Playbook tier_max}
  G -- Tier 0 --> H[Ticket only<br/>no proposals]
  G -- Tier 1 --> I[Append proposed actions]
  H --> J[Create ticket<br/>review_status=Pending Review]
  I --> J
  J --> K[Append audit line]
  K --> L{Analyst review}
  L -- Approve --> M[Tier 1 action approved<br/>execution still MANUAL]
  L -- Reject --> N[Ticket closed as rejected]
  L -- Correct --> O[Ticket corrected]
  M --> P[Out-of-band execution<br/>NOT in this package]
  N --> Q[Closed]
  O --> Q
  P --> Q