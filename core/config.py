"""
config.py
Central configuration. Add ANY free AI API here — Groq, OpenRouter, Google Gemini,
Ollama (local, no key needed), or any OpenAI-compatible endpoint.

Set env vars (or edit defaults below) for the provider you want to use.
"""
import os
from dotenv import load_dotenv

# Explicitly load .env from the project root (one level above core/),
# regardless of which directory the app is launched from.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENV_PATH = os.path.join(_PROJECT_ROOT, ".env")
load_dotenv(_ENV_PATH)


# ---------------------------------------------------------------------------
# LLM PROVIDER REGISTRY — add a new free API by adding one entry here.
# "chat_path" + "auth_header" let us hit almost any OpenAI-compatible API.
# ---------------------------------------------------------------------------
LLM_PROVIDERS = {
    "groq": {
        "base_url": "https://api.groq.com/openai/v1/chat/completions",
        "model": "llama-3.3-70b-versatile",
        "key_env": "GROQ_API_KEY",
        "auth_style": "bearer",
        "free": True,
        "notes": "Free tier, very fast inference. Get key: https://console.groq.com/keys",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1/chat/completions",
        "model": "meta-llama/llama-3.3-70b-instruct:free",
        "key_env": "OPENROUTER_API_KEY",
        "auth_style": "bearer",
        "free": True,
        "notes": "Many ':free' models. Get key: https://openrouter.ai/keys",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "model": "gemini-1.5-flash",
        "key_env": "GEMINI_API_KEY",
        "auth_style": "query_param",
        "free": True,
        "notes": "Free tier. Get key: https://aistudio.google.com/apikey",
    },
    "ollama": {
        "base_url": "http://localhost:11434/api/chat",
        "model": "llama3.1",
        "key_env": None,
        "auth_style": "none",
        "free": True,
        "notes": "Fully local & free, no internet/key needed. Run: ollama run llama3.1",
    },
    "huggingface": {
        "base_url": "https://api-inference.huggingface.co/models/{model}",
        "model": "meta-llama/Llama-3.1-8B-Instruct",
        "key_env": "HF_API_KEY",
        "auth_style": "bearer",
        "free": True,
        "notes": "Free inference API (rate limited). Get key: https://huggingface.co/settings/tokens",
    },
    "custom": {
        "base_url": os.getenv("CUSTOM_LLM_URL", ""),
        "model": os.getenv("CUSTOM_LLM_MODEL", ""),
        "key_env": "CUSTOM_LLM_API_KEY",
        "auth_style": os.getenv("CUSTOM_LLM_AUTH_STYLE", "bearer"),
        "free": True,
        "notes": "Plug in ANY other OpenAI-compatible free API via .env",
    },
}

# Which provider to use right now. Change via env var or here.
ACTIVE_LLM_PROVIDER = os.getenv("ACTIVE_LLM_PROVIDER", "groq")

# Threat intel feeds (free, optional keys)
THREAT_INTEL = {
    "abuseipdb": {
        "url": "https://api.abuseipdb.com/api/v2/check",
        "key_env": "ABUSEIPDB_API_KEY",
        "free": True,
    },
    "otx": {  # AlienVault OTX - free
        "url": "https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general",
        "key_env": "OTX_API_KEY",
        "free": True,
    },
}

# App paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def _pick_writable_output_dir():
    candidate = os.path.join(BASE_DIR, "..", "output")
    try:
        os.makedirs(candidate, exist_ok=True)
        test_file = os.path.join(candidate, ".write_test")
        with open(test_file, "w") as f:
            f.write("ok")
        os.remove(test_file)
        return candidate
    except (PermissionError, OSError):
        # Fallback: use a writable folder in the user's home directory
        # (common on Windows when the app is installed under Program Files)
        fallback = os.path.join(os.path.expanduser("~"), "secanalyzer_output")
        os.makedirs(fallback, exist_ok=True)
        return fallback

OUTPUT_DIR = _pick_writable_output_dir()
