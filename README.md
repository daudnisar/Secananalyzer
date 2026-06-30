SecanAnalyzer — AI-Powered Log Analysis & Incident Reporting Pipeline

Pipeline: Logs → Parser → Normalizer → Detection Engine → Threat Intelligence →
MITRE ATT&CK Mapper → Timeline Builder → Risk Scoring → LLM Analysis →
Incident Report Generator → Dashboard/API**

 1. Setup

```bash
cd secanalyzer
pip install -r requirements.txt --break-system-packages
cp .env.example .env
```

2. Add ANY free AI API (pick one)
Edit `.env` and set `ACTIVE_LLM_PROVIDER` + the matching key. Supported out of the box:

| Provider | Free? | Get a key |
|---|---|---|
| `groq` | ✅ Yes, fast | https://console.groq.com/keys |
| `openrouter` | ✅ Yes (`:free` models) | https://openrouter.ai/keys |
| `gemini` | ✅ Yes | https://aistudio.google.com/apikey |
| `ollama` | ✅ Fully local, no key | install Ollama, `ollama run llama3.1` |
| `huggingface` | ✅ Yes (rate-limited) | https://huggingface.co/settings/tokens |
| `custom` | Any other OpenAI-compatible free API | set `CUSTOM_LLM_URL` etc. |

You don't need to touch any code — just set the env vars. To add a brand-new
free API later, open `core/config.py` and add one entry to `LLM_PROVIDERS`.

3. Run the dashboard + API

```bash
uvicorn api:app --reload --port 8000
```

Open http://localhost:8000 → upload a log file or paste raw logs → pick your
AI provider from the dropdown → click "Run Full Pipeline".

 4. Use as an API directly

```bash
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@sample_logs/sample.log" \
  -F "llm_provider=groq"
```

Returns JSON with: events, detections, MITRE mappings, timeline, risk scores,
LLM analysis text, and links to download the generated Markdown/JSON report.

 5. Use as a pure Python pipeline (no server)

```python
from core.pipeline import run_pipeline

with open("sample_logs/sample.log") as f:
    text = f.read()

result = run_pipeline(text, source_name="sample.log", llm_provider="groq")
print(result["report_markdown"])
```

 Pipeline stages (where the code lives)
| Stage | File |
|---|---|
| Parser | `core/parser.py` — JSON, syslog, CEF, key=value, plain text |
| Normalizer | `core/normalizer.py` — common event schema |
| Detection Engine | `core/detection_engine.py` — brute force, priv-esc, malware, recon, multi-IP login, suspicious commands |
| Threat Intelligence | `core/threat_intel.py` — AbuseIPDB / OTX (free tiers) + local blocklist fallback |
| MITRE Mapper | `core/mitre_mapper.py` — maps each rule to ATT&CK tactic/technique |
| Timeline Builder | `core/timeline_builder.py` |
| Risk Scoring | `core/risk_scoring.py` — 0–100 per detection + overall incident score |
| LLM Analysis | `core/llm_analysis.py` — pluggable, any free API |
| Report Generator | `core/report_generator.py` — Markdown + JSON, saved to `output/` |
| Dashboard/API | `api.py` + `static/index.html` |

Extending

- New detection rule: add a function to `core/detection_engine.py` and append it to `RULES`.
- New MITRE mapping:add an entry to `MITRE_MAP` in `core/mitre_mapper.py`.
- New free AI API: add an entry to `LLM_PROVIDERS` in `core/config.py`.
- New log format: add a `_parse_xxx_line()` function in `core/parser.py`.

Try it now with the included sample

```bash
uvicorn api:app --reload --port 8000
 then in the dashboard, upload sample_logs/sample.log
```

It contains a simulated brute-force attack, privilege escalation, malicious
payload download, AV detection, multi-IP account login, and a port-scan-like
pattern — enough to trigger every rule at once.
