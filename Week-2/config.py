"""Week 2 configuration. All generation settings are configurable here or via CLI flags.

No credentials are stored anywhere in this project. All AI inference uses a LOCAL Ollama server.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "Data"
RESULTS_DIR = BASE_DIR / "Results"
PROMPTS_DIR = BASE_DIR / "Prompts"
VALIDATION_DIR = BASE_DIR / "Validation"
DETECTION_DIR = BASE_DIR / "Detection"
SANITIZED_DIR = DATA_DIR / "_sanitized"

# ---- Ollama (local only; non-loopback hosts are refused by ollama_client) ----
OLLAMA_URL = os.environ.get("SOC_OLLAMA_URL", "http://127.0.0.1:11434")

# ---- Models (never switched silently) ----
PRIMARY_MODEL = "mistral:7b-instruct-v0.3-q4_K_S"
BACKUP_MODEL = "llama3.2:3b"

# ---- Generation settings (INITIAL CANDIDATES - must be validated on the local machine) ----
# temperature / repeat_penalty come from the Week 1 successful Mistral retry (TC-06).
# num_predict is raised from Week 1 800 because many Week 1 outputs were cut off by that cap.
# num_ctx 6144 is an UNTESTED candidate; Week 1 used 4096. Check `ollama ps` for GPU offload.
GENERATION = {
    "temperature": 0.2,
    "repeat_penalty": 1.15,
    "num_ctx": 6144,
    "num_predict": 1500,
    "seed": 42,
}

# One controlled retry, only for token-repeat-limit / empty output. Same model, settings recorded.
MAX_RETRIES = 1
RETRY_OVERRIDES = {"temperature": 0.3, "repeat_penalty": 1.2}

REQUEST_TIMEOUT_S = 420
KEEP_ALIVE = "10m"

# ---- Input limits ----
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_EVENTS = 5000
MAX_EVENT_CHARS_IN_PROMPT = 900
CHARS_PER_TOKEN = 2.8
PROMPT_OVERHEAD_TOKENS = 1100
CONTEXT_MARGIN_TOKENS = 250

PROMPT_FILES = {
    "log_analysis": "log_analysis.txt",
    "alert_triage": "alert_triage.txt",
    "detection_improvement": "detection_improvement.txt",
}

REVIEW_STATUSES = ["Pending Review", "Approved", "Corrected", "Rejected"]
