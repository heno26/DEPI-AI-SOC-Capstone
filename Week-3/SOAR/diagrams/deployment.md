# Deployment Topology

```mermaid
flowchart LR
  subgraph W2["Week-2 (immutable evidence)"]
    OO[OpenObserve SIEM<br/>historical replay]
    R1[SIEM05/06 receiver<br/>127.0.0.1:8765]
    R2[Exchange receiver<br/>127.0.0.1:8766]
    EV[(Evidence/SIEM-OpenObserve/<br/>*_AI_Triage*.json)]
    OO --> R1 --> EV
    OO --> R2 --> EV
  end

  subgraph W3["Week-3 SOAR (this package)"]
    D[dispatcher.py<br/>file-based, no network]
    PB[playbooks/PB-01..04.yaml]
    EN[enrichment/stub.py<br/>no live TI]
    TK[ticketing/local_json.py]
    AU[(audit/<event_id>.jsonl)]
    TI[(tickets/<event_id>.json)]
    D --> PB
    D --> EN
    D --> TK
    TK --> TI
    D --> AU
  end

  EV -- read-only --> D

  subgraph OUT["Explicitly NOT connected"]
    TH[TheHive server<br/>stub only]
    FW[Firewall / EDR<br/>Tier-2 prohibited]
    OL[Ollama / Mistral<br/>not re-invoked]
  end