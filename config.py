# =============================================================================
# ReconCrew v3 - Configuration (reads from environment / .env)
# =============================================================================

import os

# --- LLM Provider ---
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "lmstudio")  # lmstudio | openai | anthropic

# --- LM Studio ---
LM_STUDIO_HOST = os.getenv("LM_STUDIO_HOST", "http://192.168.50.213:1234")
LM_STUDIO_MODEL = os.getenv("LM_STUDIO_MODEL", "qwen2.5-14b-instruct")

# --- OpenAI ---
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")

# --- Anthropic ---
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

# --- LLM Parameters ---
LLM_TEMPERATURE = 0.2
LLM_MAX_TOKENS = 4096

# --- Scan Settings ---
MAX_CRAWL_DEPTH = int(os.getenv("MAX_CRAWL_DEPTH", "3"))
MAX_PAGES = int(os.getenv("MAX_PAGES", "50"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))
REQUEST_DELAY = float(os.getenv("REQUEST_DELAY", "0.3"))
FUZZ_THREADS = int(os.getenv("FUZZ_THREADS", "50"))
MAX_FUZZ_ENDPOINTS = int(os.getenv("MAX_FUZZ_ENDPOINTS", "100"))

# --- User Agent ---
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

# --- Output ---
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./reports")

# --- Secrets Patterns ---
SECRET_PATTERNS = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})",
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token":         r"gh[ps]_[A-Za-z0-9_]{36,}",
    "Slack Token":          r"xox[bpors]-[0-9A-Za-z\-]{10,}",
    "Private Key":          r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----",
    "JWT Token":            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Generic API Key":      r"(?i)(api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})",
    "Generic Secret":       r"(?i)(secret|password|passwd|pwd|token)\s*[:=]\s*['\"]?([^\s'\"]{8,})",
    "Bearer Token":         r"(?i)bearer\s+[A-Za-z0-9_\-\.]+",
    "Basic Auth":           r"(?i)basic\s+[A-Za-z0-9+/=]{10,}",
    "Internal IP":          r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    "Email Address":        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Hardcoded URL":        r"(?i)https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|internal|staging|dev|test)[^\s'\"]*",
}
