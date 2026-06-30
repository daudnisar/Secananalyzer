"""
llm_analysis.py
Pluggable LLM client. Works with whichever provider is set as ACTIVE_LLM_PROVIDER
in core/config.py / .env. To add a new free API, just add an entry to LLM_PROVIDERS
in config.py — no code changes needed here as long as it's OpenAI-chat-compatible,
Gemini-style, or Ollama-style (all three formats are already handled below).
"""
import os
import json
import requests
from core.config import LLM_PROVIDERS, ACTIVE_LLM_PROVIDER

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst.
You are given structured detection findings, MITRE ATT&CK mappings, risk scores,
and a timeline from an automated log analysis pipeline.

Write a concise analyst-grade assessment that includes:
1. Executive summary (3-4 sentences, plain language)
2. Likely attack narrative / kill chain interpretation
3. Most critical findings and why they matter
4. Recommended immediate actions (containment/remediation), as a short list
5. False positive likelihood notes if relevant

Be specific, reference IPs/users/hosts from the data, and keep it under 400 words."""


def _call_groq_or_openai_style(provider_cfg, prompt, api_key):
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": provider_cfg["model"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 900,
    }
    r = requests.post(provider_cfg["base_url"], headers=headers, json=payload, timeout=60)
    r.raise_for_status()
    data = r.json()
    return data["choices"][0]["message"]["content"]


def _call_gemini(provider_cfg, prompt, api_key):
    url = provider_cfg["base_url"].format(model=provider_cfg["model"])
    payload = {
        "contents": [{"parts": [{"text": SYSTEM_PROMPT + "\n\n" + prompt}]}]
    }
    r = requests.post(url, params={"key": api_key}, json=payload, timeout=60)
    r.raise_for_status()
    data = r.json()
    return data["candidates"][0]["content"]["parts"][0]["text"]


def _call_ollama(provider_cfg, prompt, api_key=None):
    payload = {
        "model": provider_cfg["model"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
    }
    r = requests.post(provider_cfg["base_url"], json=payload, timeout=120)
    r.raise_for_status()
    data = r.json()
    return data["message"]["content"]


def _call_huggingface(provider_cfg, prompt, api_key):
    url = provider_cfg["base_url"].format(model=provider_cfg["model"])
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {"inputs": SYSTEM_PROMPT + "\n\n" + prompt}
    r = requests.post(url, headers=headers, json=payload, timeout=60)
    r.raise_for_status()
    data = r.json()
    if isinstance(data, list) and data and "generated_text" in data[0]:
        return data[0]["generated_text"]
    return json.dumps(data)


def build_analysis_prompt(detections, timeline, overall_risk):
    summary = {
        "overall_risk": {"score": overall_risk["score"], "label": overall_risk["label"]},
        "detections": [
            {
                "rule": d["rule"],
                "severity": d.get("severity"),
                "risk_score": d.get("risk_score"),
                "mitre": d.get("mitre"),
                "description": d.get("description"),
                "src_ip": d.get("src_ip"),
                "user": d.get("user"),
                "threat_intel": d.get("threat_intel"),
            }
            for d in detections
        ],
        "timeline_sample": timeline[:25],
    }
    return "DATA:\n" + json.dumps(summary, indent=2, default=str)


def run_llm_analysis(detections, timeline, overall_risk, provider_name=None) -> dict:
    provider_name = provider_name or ACTIVE_LLM_PROVIDER
    provider_cfg = LLM_PROVIDERS.get(provider_name)

    if not provider_cfg:
        return {"provider": provider_name, "error": f"Unknown provider '{provider_name}'."}

    api_key = os.getenv(provider_cfg["key_env"]) if provider_cfg.get("key_env") else None
    if provider_cfg.get("key_env") and not api_key:
        return {
            "provider": provider_name,
            "error": f"No API key found. Set {provider_cfg['key_env']} in your .env "
                     f"({provider_cfg.get('notes', '')})",
        }

    prompt = build_analysis_prompt(detections, timeline, overall_risk)

    try:
        if provider_name in ("groq", "openrouter", "custom"):
            text = _call_groq_or_openai_style(provider_cfg, prompt, api_key)
        elif provider_name == "gemini":
            text = _call_gemini(provider_cfg, prompt, api_key)
        elif provider_name == "ollama":
            text = _call_ollama(provider_cfg, prompt)
        elif provider_name == "huggingface":
            text = _call_huggingface(provider_cfg, prompt, api_key)
        else:
            return {"provider": provider_name, "error": "Unsupported provider type."}

        return {"provider": provider_name, "model": provider_cfg["model"], "analysis": text}

    except requests.RequestException as ex:
        return {"provider": provider_name, "error": f"Request failed: {ex}"}
    except (KeyError, IndexError, json.JSONDecodeError) as ex:
        return {"provider": provider_name, "error": f"Unexpected response format: {ex}"}


def list_available_providers():
    """Returns provider info for UI dropdown — name, model, free flag, setup notes."""
    return [
        {
            "id": name,
            "model": cfg["model"],
            "free": cfg.get("free", True),
            "needs_key": bool(cfg.get("key_env")),
            "key_env": cfg.get("key_env"),
            "notes": cfg.get("notes", ""),
            "configured": bool(os.getenv(cfg["key_env"])) if cfg.get("key_env") else True,
        }
        for name, cfg in LLM_PROVIDERS.items()
    ]
