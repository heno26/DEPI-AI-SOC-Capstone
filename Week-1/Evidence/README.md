# Evidence Screenshots — Complete Locally Before Submission

The user reported capturing screenshots 01–10. **No screenshot files were present in the uploaded `results.zip`**, so this package intentionally does not fabricate or attach them. Copy the images already saved on your computer into this folder.

| Filename | What must be visible |
|---|---|
| `01-Ollama-Installation.png` | `ollama --version`, `ollama list`, `python --version` |
| `02-GPU-Information.png` | `nvidia-smi` and RTX 3050 |
| `03-AI-Model-Running.png` | Llama local prompt and response (two images acceptable) |
| `04-GPU-Execution.png` | `ollama ps`, 100% GPU offload for Llama |
| `05-Offline-Test.png` | Network disconnected and local model still answering |
| `06-Privacy-Verification.png` | `127.0.0.1:11434` in Listen state |
| `07-Benchmark-Execution.png` | Original 3-model benchmark console; do not hide two HTTP 500 failures |
| `08-Benchmark-Results.png` | `summary.csv` from original run (7, 6, 6 successful) |
| `09-Accuracy-Validation.png` | Ground-truth sender IP `192.0.2.88` vs Phi-3 false `192.008.0.34` |
| `10-Resource-Monitoring.png` | Mistral CPU/RAM/VRAM from Task Manager and/or `nvidia-smi` |

If you saved `03` or `10` as A/B images, keep those original names; update the checklist accordingly.

## Evidence quality notes

Screenshot 05 should include clear proof of network adapters disconnected. A single failed TCP test to 1.1.1.1 is not sufficient alone.

Screenshots are supporting evidence, **not substitutes for benchmark raw output**.
