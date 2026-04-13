# ReconCrew v3 — Semi-Agentic Web Reconnaissance

Multi-agent web recon system with LLM-powered analysis. Each phase runs a specialized tool, then an AI agent interprets the results. If the LLM fails, the scan continues with raw data — it never breaks.

## Architecture

```
┌────────────────────────────────────────────────────┐
│                    main.py                         │
│                                                    │
│  Phase 1: web_spider()  → agent_spider_analyze()   │
│  Phase 2: js_analyzer() → agent_js_analyze()       │
│  Phase 3: secrets_scan() → agent_secrets_analyze()  │
│  Phase 4: form_analyzer()→ agent_forms_analyze()   │
│  Phase 5: fuzzer()       → agent_fuzz_analyze()    │
│  Phase 6:                  agent_coordinator()     │
│                                                    │
│  Tool = Python code          Agent = LLM analysis  │
│  (always works)              (fallback if fails)   │
└─────────────────────┬──────────────────────────────┘
                      │
              ┌───────▼────────┐
              │   LLM Client   │
              │                │
              │ • LM Studio    │
              │ • OpenAI API   │
              │ • Anthropic    │
              └────────────────┘
```

## Quick Start (Docker)

```bash
# 1. Clone
git clone https://github.com/YOUR_USER/recon-crew.git
cd recon-crew

# 2. Configure
cp .env.example .env
nano .env   # Set your LM Studio IP or API keys

# 3. Run
docker compose run --rm reconcrew https://target.com
```

## Quick Start (Python)

```bash
# 1. Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
nano .env

# 3. Run
python src/main.py https://target.com
```

## LLM Providers

Edit `.env` to switch:

| Provider | Config |
|----------|--------|
| **LM Studio** (local) | `LLM_PROVIDER=lmstudio` + `LM_STUDIO_HOST=http://IP:1234` |
| **OpenAI** | `LLM_PROVIDER=openai` + `OPENAI_API_KEY=sk-...` |
| **Anthropic** | `LLM_PROVIDER=anthropic` + `ANTHROPIC_API_KEY=sk-ant-...` |

## Flags

```bash
python src/main.py https://target.com              # Full scan
python src/main.py https://target.com --skip-fuzz   # Skip endpoint fuzzing
python src/main.py https://target.com --skip-ai     # No LLM, raw data only
```

## Output

- `reports/recon_<target>_<timestamp>.html` — Interactive report
- `reports/recon_<target>_<timestamp>.json` — Structured JSON
- `reports/raw_<target>_<timestamp>.json` — Raw tool data

## What It Finds

| Phase | Tool | Agent Analyzes |
|-------|------|----------------|
| Spider | Crawl, discover assets | Tech versions, exposure, attack surface |
| JS Analysis | Parse JS for endpoints/secrets | Impact of exposed endpoints and keys |
| Secrets | Probe sensitive paths | Severity of exposed files |
| Forms | Check CSRF, auth, uploads | Injection candidates, auth weaknesses |
| Fuzzer | Async HTTP method + suffix fuzz | Access control gaps |
| Coordinator | — | Synthesizes all findings into report |

## Disclaimer

**Authorized security testing only.** Unauthorized use is illegal.
