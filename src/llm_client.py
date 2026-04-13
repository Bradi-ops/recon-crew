# =============================================================================
# ReconCrew v3 - LLM Client
# =============================================================================
# Unified LLM interface. Supports LM Studio, OpenAI, and Anthropic.
# Agents call llm_ask() and don't care which provider is behind it.
# =============================================================================

import json
import httpx
from config import (
    LLM_PROVIDER, LLM_TEMPERATURE, LLM_MAX_TOKENS,
    LM_STUDIO_HOST, LM_STUDIO_MODEL,
    OPENAI_API_KEY, OPENAI_MODEL,
    ANTHROPIC_API_KEY, ANTHROPIC_MODEL,
)


def llm_ask(prompt: str, system: str = "", max_tokens: int = None) -> str | None:
    """
    Send a prompt to the configured LLM and return the response text.
    Returns None on failure.
    """
    mt = max_tokens or LLM_MAX_TOKENS

    if LLM_PROVIDER == "lmstudio":
        return _call_openai_compatible(
            host=LM_STUDIO_HOST,
            model=LM_STUDIO_MODEL,
            api_key="lm-studio",
            prompt=prompt,
            system=system,
            max_tokens=mt,
        )
    elif LLM_PROVIDER == "openai":
        return _call_openai_compatible(
            host="https://api.openai.com",
            model=OPENAI_MODEL,
            api_key=OPENAI_API_KEY,
            prompt=prompt,
            system=system,
            max_tokens=mt,
        )
    elif LLM_PROVIDER == "anthropic":
        return _call_anthropic(prompt, system, mt)
    else:
        print(f"[!] Unknown LLM provider: {LLM_PROVIDER}")
        return None


def _call_openai_compatible(host, model, api_key, prompt, system, max_tokens):
    """Call OpenAI-compatible API (LM Studio, OpenAI, etc.)."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    try:
        # GPT-5.x models use max_completion_tokens instead of max_tokens
        token_param = "max_completion_tokens" if host == "https://api.openai.com" else "max_tokens"

        r = httpx.post(
            f"{host}/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": model,
                "messages": messages,
                "temperature": LLM_TEMPERATURE,
                token_param: max_tokens,
            },
            timeout=180,
        )
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"]
        else:
            print(f"[!] LLM API error {r.status_code}: {r.text[:200]}")
            return None
    except Exception as e:
        print(f"[!] LLM request failed: {e}")
        return None


def _call_anthropic(prompt, system, max_tokens):
    """Call Anthropic API."""
    try:
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": max_tokens,
                "system": system or "You are a security analyst.",
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=180,
        )
        if r.status_code == 200:
            return r.json()["content"][0]["text"]
        else:
            print(f"[!] Anthropic API error {r.status_code}: {r.text[:200]}")
            return None
    except Exception as e:
        print(f"[!] Anthropic request failed: {e}")
        return None


def llm_ask_json(prompt: str, system: str = "") -> dict | None:
    """Ask LLM and parse response as JSON. Returns None on failure."""
    response = llm_ask(prompt, system)
    if not response:
        return None

    try:
        clean = response.strip()
        # Strip markdown fences
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1] if "\n" in clean else clean[3:]
        if clean.endswith("```"):
            clean = clean.rsplit("```", 1)[0]
        return json.loads(clean.strip())
    except json.JSONDecodeError:
        # Try to find JSON object in the response
        try:
            start = response.index("{")
            end = response.rindex("}") + 1
            return json.loads(response[start:end])
        except (ValueError, json.JSONDecodeError):
            return None


def check_llm_connection() -> bool:
    """Verify LLM is accessible."""
    if LLM_PROVIDER == "lmstudio":
        try:
            r = httpx.get(f"{LM_STUDIO_HOST}/api/v1/models", timeout=5)
            if r.status_code == 200:
                models = r.json().get("models", r.json().get("data", []))
                loaded = [m for m in models if m.get("loaded_instances")]
                print(f"[+] LM Studio — {len(loaded)} model(s) loaded")
                for m in loaded:
                    print(f"    └─ {m.get('key', m.get('id', '?'))}")
                return len(loaded) > 0
        except Exception as e:
            print(f"[!] Cannot connect to LM Studio: {e}")
            return False

    elif LLM_PROVIDER == "openai":
        if not OPENAI_API_KEY:
            print("[!] OPENAI_API_KEY not set")
            return False
        print(f"[+] OpenAI — model: {OPENAI_MODEL}")
        return True

    elif LLM_PROVIDER == "anthropic":
        if not ANTHROPIC_API_KEY:
            print("[!] ANTHROPIC_API_KEY not set")
            return False
        print(f"[+] Anthropic — model: {ANTHROPIC_MODEL}")
        return True

    return False