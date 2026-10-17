# AI Lab Setup Guide — Ollama on Windows 11

**Project 5 – Week 1: Local AI Setup & SOC Prompt Engineering**
**Target machine:** Windows 11 · 16 GB RAM · NVIDIA RTX 3050 (6 GB VRAM) · Intel Core i7

---

## 1. Why Ollama?

| Platform | Verdict for this project |
|---|---|
| **Ollama** (chosen) | Command-line + local REST API (`localhost:11434`). One command to download and run a model. The REST API lets Python scripts (Week 2–4) call the model with no extra libraries. Free, open source. |
| LM Studio | Good GUI, but it is harder to script and automate in later weeks. |
| GPT4All | Simple GUI, but a smaller model catalog and less automation support. |

Ollama is the simplest option that also stays compatible with the SOAR automation planned for Week 3.

## 2. Required Software

| Software | Purpose | Cost |
|---|---|---|
| Windows 11 + PowerShell | Run commands | Included |
| NVIDIA driver (recent) | GPU acceleration (RTX 3050) | Free |
| Ollama for Windows | Runs the models | Free |
| Python 3.8+ | Runs `benchmark.py` (no extra packages) | Free |
| ~10 GB free disk space | Model files | — |

## 3. Installation

Open **PowerShell** (Start → type `PowerShell`).

### 3.1 Check the GPU driver
```powershell
nvidia-smi
```
Expected: a table showing `NVIDIA GeForce RTX 3050` and about 6144 MiB memory. If the command is not found, install the latest driver from nvidia.com and reboot.

### 3.2 Install Ollama
Option A (installer): download `OllamaSetup.exe` from https://ollama.com/download and run it.
Option B (command line):
```powershell
winget install Ollama.Ollama
```
**Close and reopen PowerShell**, then verify:
```powershell
ollama --version
```

### 3.3 Install Python
```powershell
python --version
```
If it is missing: `winget install Python.Python.3.12` (then reopen PowerShell). During a manual install, tick **“Add python.exe to PATH”**.

## 4. Download the Models (one time, needs internet)

Three model families are required: **Llama, Mistral, Phi**. These sizes fit a 6 GB GPU:

```powershell
ollama pull llama3.2:3b
ollama pull mistral:7b
ollama pull phi3:mini
```

| Model | Family | Approx. download size* | Fit on 6 GB VRAM |
|---|---|---|---|
| `llama3.2:3b` | Llama 3 | ~2 GB | Fully on GPU (expected) |
| `mistral:7b` | Mistral | ~4 GB | Mostly/fully on GPU; may split with CPU (slower) |
| `phi3:mini` | Phi | ~2 GB | Fully on GPU (expected) |

\* Approximate. Check the real size with `ollama list`. If a tag is not found, look up the current tag at https://ollama.com/library and use it instead (for example `llama3.1:8b` is an optional larger Llama; it will not fully fit in 6 GB VRAM).

> **Privacy warning:** Do **not** use model tags ending in `-cloud`. They run on remote servers and would break the “local only” requirement.

Verify:
```powershell
ollama list
```

## 5. Run and Test Ollama

### Test 1 — Basic functionality (interactive)
```powershell
ollama run llama3.2:3b
```
Type: `In one sentence, what is a brute-force attack?` — then `/bye` to exit.

### Test 2 — Is the GPU used?
In a second PowerShell window while a model is loaded:
```powershell
ollama ps
```
The `PROCESSOR` column should show `100% GPU` for the small models. A split such as `30%/70% CPU/GPU` means part of the model runs on CPU (slower, but works).

### Test 3 — Local REST API (what Python will use)
```powershell
$body = @{ model = "llama3.2:3b"; prompt = "Reply with the word OK"; stream = $false } | ConvertTo-Json
Invoke-RestMethod -Uri http://localhost:11434/api/generate -Method Post -Body $body -ContentType "application/json"
```
Expected: an object with a `response` field.

### Test 4 — Use a SOC prompt manually
```powershell
cd path\to\Week-1
$log = "Oct 14 02:11:03 web01 sshd[2211]: Failed password for root from 203.0.113.45 port 51126 ssh2"
$p = (Get-Content .\SOC-Prompts\Log-Analysis.txt -Raw).Replace("{{INPUT}}", $log)
$p | ollama run llama3.2:3b
```

### Test 5 — Run the benchmark
```powershell
cd path\to\Week-1

# Quick smoke test (1 model, 1 test case)
python Benchmarks\benchmark.py --models llama3.2:3b --cases TC-03

# Full benchmark (3 models x 7 test cases; roughly 15-40 minutes on this hardware)
python Benchmarks\benchmark.py
```
Results are saved in `Benchmarks\results\run_<date>\` (`raw\` answers, `results.csv`, `summary.csv`, `results.json`).

## 6. Offline and Privacy Tests

1. Make sure all three models are already downloaded (`ollama list`).
2. **Turn off Wi-Fi / unplug Ethernet** (or enable Airplane mode). Confirm: `ping 8.8.8.8` fails.
3. Run `ollama run llama3.2:3b`, ask a question → it must still answer.
4. Run the smoke test from Test 5 while offline → it must still work.
5. Confirm Ollama listens only on the local machine:
```powershell
Get-NetTCPConnection -LocalPort 11434 | Select-Object LocalAddress, LocalPort, State
```
Expected `LocalAddress`: `127.0.0.1` (not `0.0.0.0`).

Record the results in `Privacy\Privacy-Ethics-Checklist.md`.

## 7. Stop / Free Memory
```powershell
ollama stop llama3.2:3b
```
Only run **one model at a time** on this 16 GB / 6 GB VRAM machine (the benchmark script already unloads each model when it finishes).

## 8. Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| `ollama` is not recognized | PowerShell opened before install | Close and reopen PowerShell; or reboot |
| `connection refused` on port 11434 / `benchmark.py` says “cannot reach Ollama” | Ollama server not running | Open the **Ollama** app from the Start menu, or run `ollama serve` in a separate window |
| `Error: listen tcp 127.0.0.1:11434: bind` | Server already running | This is fine — it is already running; do not start a second one |
| Very slow answers | Model running on CPU | Run `ollama ps`; update the NVIDIA driver; use a smaller model; close GPU-heavy apps (games, browsers with video) |
| `nvidia-smi` not found | Driver missing | Install NVIDIA driver, reboot |
| `model requires more system memory` / out-of-memory | Not enough free RAM/VRAM | Close other apps; use `llama3.2:3b` or `phi3:mini`; lower context: `--num-ctx 2048` |
| `pull model manifest: file does not exist` | Wrong or renamed tag | Check the exact tag on https://ollama.com/library |
| Download stops or fails | Network interruption | Re-run the same `ollama pull` command — it resumes |
| C: drive is full | Models are large | Set a different folder: `setx OLLAMA_MODELS "D:\ollama-models"`, then restart Ollama and re-pull |
| `python` not found | Python not installed / not on PATH | Install Python and tick “Add to PATH”; try `py` instead of `python` |
| Benchmark entry shows `error: timed out` | Slow model / long output | Increase `--timeout 1200`, lower `--max-tokens 500` |
| Model answers are inconsistent between runs | Sampling randomness | The script uses `temperature 0` and a fixed seed; small differences are still possible |
