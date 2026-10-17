> **Reviewed update (16 October 2026):** See `Week-1-Final-Report.md` and `Testing/AI-Accuracy-Review.md` for **actual results and manual ratings**. The original README below describes pre-execution status and is preserved for provenance. Screenshots are not contained in this package.

# Project 5 — AI-Assisted SOC Automation & Full Incident Response Capstone
## Week 1: Local AI Setup & SOC Prompt Engineering

Digital Egypt Pioneers Initiative (DEPI) · Cybersecurity track

## Folder Structure
```
Week-1/
├── README.md                          <- this file
├── Week-1-Final-Report.md             <- final report (complete after running tests)
├── Setup/Ollama-Setup-Guide.md        <- Deliverable 1: AI lab setup guide
├── Benchmarks/
│   ├── benchmark.py                   <- benchmark script (Python, no extra packages)
│   └── Model-Benchmark.md             <- Deliverable 2: local model benchmark
├── SOC-Prompts/                       <- Deliverable 3: SOC prompt library
│   ├── Log-Analysis.txt
│   ├── Alert-Triage.txt
│   ├── Threat-Intelligence.txt
│   └── Incident-Report.txt
├── Privacy/Privacy-Ethics-Checklist.md<- Deliverable 4: privacy / ethics checklist
└── Testing/
    ├── Test-Cases.json                <- 7 synthetic SOC test cases
    └── AI-Accuracy-Review.md          <- Deliverable 5: AI accuracy review
```

## Quick Start (PowerShell)
```powershell
winget install Ollama.Ollama           # then close and reopen PowerShell
ollama pull llama3.2:3b
ollama pull mistral:7b
ollama pull phi3:mini
cd path\to\Week-1
python Benchmarks\benchmark.py --models llama3.2:3b --cases TC-03   # smoke test
python Benchmarks\benchmark.py                                      # full benchmark
```
Full details: `Setup\Ollama-Setup-Guide.md`.

## Status of Work
| Item | Status |
|---|---|
| Platform choice (Ollama) and reasoning | ✅ Done (in the setup guide) |
| Setup guide, 4 prompts, 7 test cases, `benchmark.py`, checklist and review templates | ✅ Created |
| `benchmark.py` logic (scoring, CSV/JSON output) | ✅ Checked against a simulated Ollama server (code test only; no model results exist) |
| Install Ollama and pull models | ⏳ **You must do this** |
| Run benchmark, collect results | ⏳ **You must do this** |
| Offline / privacy tests | ⏳ **You must do this** |
| Fill `Model-Benchmark.md`, `AI-Accuracy-Review.md`, privacy checklist | ⏳ **You must do this** |
| Final recommendation + final report | ⏳ After the results |

**No benchmark results, screenshots, or test outcomes are included — they must come from your computer.**

## Week 1 Completion Checklist
- [ ] Ollama installed; `ollama --version` works
- [ ] 3 models installed (Llama, Mistral, Phi); `ollama list` shows them
- [ ] Basic functionality test passed (Setup Guide, Test 1–4)
- [ ] GPU usage checked with `ollama ps`
- [ ] Offline test done (network disabled)
- [ ] Localhost-only check done (`127.0.0.1:11434`)
- [ ] Full benchmark run completed; results saved in `Benchmarks\results\`
- [ ] Raw answers reviewed; manual scores filled in
- [ ] `Model-Benchmark.md` completed, recommended model chosen
- [ ] `AI-Accuracy-Review.md` completed
- [ ] `Privacy-Ethics-Checklist.md` completed
- [ ] `Week-1-Final-Report.md` completed
- [ ] Screenshots collected (list below)

## Evidence / Screenshots Checklist
| # | Screenshot | Proves |
|---|---|---|
| 1 | `ollama --version` and `ollama list` (3 models) | Installation |
| 2 | `nvidia-smi` | GPU available |
| 3 | `ollama run llama3.2:3b` with a SOC answer | Basic functionality |
| 4 | `ollama ps` while a model is loaded | GPU/CPU usage |
| 5 | Wi-Fi/network disabled + model still answering | Offline operation |
| 6 | `Get-NetTCPConnection -LocalPort 11434` | Localhost-only |
| 7 | Benchmark terminal output + summary | Benchmark executed |
| 8 | `results.csv` / `summary.csv` opened | Results exist |
| 9 | One raw answer next to the input log (best and worst) | Accuracy review |
| 10 | Task Manager (GPU + RAM) during a 7B run | Resource usage |

## Compatibility with Later Weeks
- Prompts use a single `{{INPUT}}` placeholder, so Week 2 can feed real logs/alerts to the same prompts.
- `benchmark.py` already talks to the Ollama REST API; Week 2–3 scripts can reuse the same call.
- Week 2–4 are intentionally **not** started.
