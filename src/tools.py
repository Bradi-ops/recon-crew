# =============================================================================
# ReconCrew v3 - Recon Tools
# =============================================================================
# Pure Python tools. No LLM dependency. Each returns structured JSON.
# =============================================================================

import re
import json
import time
import asyncio
import hashlib
import httpx
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from config import (
    USER_AGENT, REQUEST_TIMEOUT, REQUEST_DELAY,
    MAX_CRAWL_DEPTH, MAX_PAGES, SECRET_PATTERNS,
    FUZZ_THREADS, MAX_FUZZ_ENDPOINTS,
)


def _get_client():
    return httpx.Client(
        headers={"User-Agent": USER_AGENT},
        timeout=REQUEST_TIMEOUT,
        follow_redirects=True,
        verify=False,
    )


# =============================================================================
# TOOL 1: Web Spider
# =============================================================================
def web_spider(target_url: str) -> dict:
    """Crawl target, return structured data about all discovered assets."""
    visited = set()
    results = {
        "pages": [], "js_files": set(), "css_files": set(),
        "forms": [], "comments": [], "emails": set(),
        "external_links": set(), "internal_links": set(),
        "meta_tags": [], "headers_of_interest": {},
        "technologies_detected": set(),
    }

    base_domain = urlparse(target_url).netloc

    def crawl(url, depth=0):
        if depth > MAX_CRAWL_DEPTH or len(visited) >= MAX_PAGES or url in visited:
            return
        if urlparse(url).netloc != base_domain:
            return

        visited.add(url)
        time.sleep(REQUEST_DELAY)

        try:
            client = _get_client()
            response = client.get(url)

            # Headers
            for h in ["server", "x-powered-by", "x-framework", "x-generator",
                       "x-aspnet-version", "x-debug", "x-rag-provider",
                       "access-control-allow-origin", "content-security-policy",
                       "strict-transport-security"]:
                val = response.headers.get(h)
                if val:
                    results["headers_of_interest"][h] = val

            server = response.headers.get("server", "")
            powered = response.headers.get("x-powered-by", "")
            if server:
                results["technologies_detected"].add(f"Server: {server}")
            if powered:
                results["technologies_detected"].add(f"X-Powered-By: {powered}")

            soup = BeautifulSoup(response.text, "lxml")
            results["pages"].append({
                "url": url,
                "status": response.status_code,
                "title": soup.title.string.strip() if soup.title and soup.title.string else None,
            })

            # JS files
            for script in soup.find_all("script", src=True):
                js_url = urljoin(url, script["src"])
                if js_url.startswith("//"):
                    js_url = f"https:{js_url}"
                results["js_files"].add(js_url)

            # CSS
            for link in soup.find_all("link", rel="stylesheet"):
                if link.get("href"):
                    css_url = urljoin(url, link["href"])
                    if css_url.startswith("//"):
                        css_url = f"https:{css_url}"
                    results["css_files"].add(css_url)

            # Inline tech detection
            for script in soup.find_all("script", src=False):
                if script.string:
                    for tech, pat in {"React": r"React\.|ReactDOM", "Angular": r"ng-app|angular\.module",
                                      "Vue.js": r"Vue\.|new Vue", "jQuery": r"jQuery|\$\(",
                                      "Next.js": r"__NEXT_DATA__", "Webpack": r"webpackJsonp"}.items():
                        if re.search(pat, script.string):
                            results["technologies_detected"].add(tech)

            # Comments
            for c in re.findall(r"<!--(.*?)-->", response.text, re.DOTALL):
                c = c.strip()
                if len(c) > 3:
                    results["comments"].append({"page": url, "comment": c[:500]})

            # Forms
            for form in soup.find_all("form"):
                form_data = {
                    "page": url,
                    "action": urljoin(url, form.get("action", "")),
                    "method": form.get("method", "GET").upper(),
                    "inputs": [],
                }
                for inp in form.find_all(["input", "textarea", "select"]):
                    form_data["inputs"].append({
                        "name": inp.get("name", ""), "type": inp.get("type", "text"),
                        "value": inp.get("value", ""), "hidden": inp.get("type") == "hidden",
                    })
                results["forms"].append(form_data)

            # Meta tags
            for meta in soup.find_all("meta"):
                attrs = {k: v for k, v in meta.attrs.items()}
                if attrs:
                    results["meta_tags"].append(attrs)

            # Links
            for a in soup.find_all("a", href=True):
                link_url = urljoin(url, a["href"])
                lp = urlparse(link_url)
                if lp.netloc == base_domain:
                    results["internal_links"].add(link_url)
                    crawl(link_url, depth + 1)
                elif lp.scheme in ("http", "https"):
                    results["external_links"].add(link_url)

            # Emails
            results["emails"].update(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", response.text))
            client.close()

        except Exception as e:
            results["pages"].append({"url": url, "error": str(e)})

    crawl(target_url)
    return {k: list(v) if isinstance(v, set) else v for k, v in results.items()}


# =============================================================================
# TOOL 2: JS Analyzer
# =============================================================================
def js_analyzer(js_urls: list) -> list:
    """Analyze JS files for endpoints, secrets, comments."""
    findings = []
    endpoint_patterns = [
        (r"""['"`](/api/[^'"`\s]{3,})['"`]""", "API Endpoint"),
        (r"""['"`](/v[0-9]+/[^'"`\s]{3,})['"`]""", "Versioned Endpoint"),
        (r"""['"`](https?://[^'"`\s]{10,})['"`]""", "Hardcoded URL"),
        (r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""", "Fetch Call"),
        (r"""\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""", "HTTP Method Call"),
        (r"""axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""", "Axios Call"),
        (r"""(?:baseURL|baseUrl|BASE_URL|API_URL|API_BASE)\s*[:=]\s*['"`]([^'"`]+)['"`]""", "Base URL"),
    ]

    comment_pat = re.compile(
        r"(?://\s*(TODO|FIXME|HACK|BUG|SECURITY|WARNING|DEPRECATED)[^\n]*)|"
        r"(?:/\*\s*(TODO|FIXME|HACK|BUG|SECURITY|WARNING|DEPRECATED).*?\*/)",
        re.IGNORECASE | re.DOTALL,
    )

    client = _get_client()
    for js_url in js_urls:
        time.sleep(REQUEST_DELAY)
        try:
            r = client.get(js_url)
            content = r.text
            ff = {"file": js_url, "size": len(content),
                  "hash": hashlib.md5(content.encode()).hexdigest(),
                  "endpoints": [], "secrets": [], "comments": [], "source_maps": []}

            for pat, label in endpoint_patterns:
                for m in re.findall(pat, content):
                    ff["endpoints"].append({"type": label, "value": m})

            for name, pat in SECRET_PATTERNS.items():
                for m in re.findall(pat, content):
                    val = m if isinstance(m, str) else m[0]
                    ff["secrets"].append({"type": name, "value": val[:80]})

            for m in comment_pat.finditer(content):
                ff["comments"].append(m.group(0).strip()[:300])

            for ref in re.findall(r"//[#@]\s*sourceMappingURL=(\S+)", content):
                ff["source_maps"].append(urljoin(js_url, ref))

            if ff["endpoints"] or ff["secrets"] or ff["comments"] or ff["source_maps"]:
                findings.append(ff)
        except Exception as e:
            findings.append({"file": js_url, "error": str(e)})

    client.close()
    return findings


# =============================================================================
# TOOL 3: Secrets Scanner
# =============================================================================
def secrets_scanner(target_url: str) -> list:
    """Check common sensitive paths."""
    findings = []
    client = _get_client()
    base = target_url.rstrip("/")

    paths = [
        "/.env", "/.env.bak", "/.env.local", "/.env.production",
        "/.git/config", "/.git/HEAD",
        "/robots.txt", "/sitemap.xml", "/.htaccess", "/web.config",
        "/config.json", "/config.yml", "/package.json", "/composer.json",
        "/.well-known/security.txt",
        "/swagger.json", "/swagger-ui.html", "/api-docs",
        "/openapi.json", "/graphql", "/graphiql",
        "/.DS_Store", "/wp-config.php.bak", "/backup.sql",
        "/phpinfo.php", "/server-status", "/server-info",
        "/crossdomain.xml", "/elmah.axd", "/trace.axd",
    ]

    for path in paths:
        time.sleep(REQUEST_DELAY)
        try:
            url = f"{base}{path}"
            r = client.get(url)

            if r.status_code == 200:
                content = r.text
                if len(content) < 50 or "not found" in content.lower()[:200]:
                    continue
                finding = {"path": path, "url": url, "status": 200,
                           "size": len(content), "content_type": r.headers.get("content-type", ""),
                           "secrets_found": [], "preview": content[:300]}
                for name, pat in SECRET_PATTERNS.items():
                    for m in re.findall(pat, content):
                        val = m if isinstance(m, str) else m[0]
                        finding["secrets_found"].append({"type": name, "value": val[:60]})
                findings.append(finding)
            elif r.status_code == 403:
                findings.append({"path": path, "url": url, "status": 403,
                                 "note": "Forbidden - exists but access denied"})
        except Exception:
            continue

    client.close()
    return findings


# =============================================================================
# TOOL 4: Form Analyzer
# =============================================================================
def form_analyzer(forms: list) -> list:
    """Analyze forms for security issues."""
    analysis = []
    for form in forms:
        fa = {"page": form.get("page", ""), "action": form.get("action", ""),
              "method": form.get("method", ""), "findings": [], "risk_level": "info"}
        inputs = form.get("inputs", [])
        names = [i.get("name", "").lower() for i in inputs]

        # CSRF check
        csrf = ["csrf", "token", "_token", "authenticity_token", "nonce"]
        has_csrf = any(any(c in n for c in csrf) for n in names)
        if not has_csrf and form.get("method", "").upper() == "POST":
            fa["findings"].append({"type": "Missing CSRF Token", "severity": "high",
                                   "detail": "POST form without CSRF protection"})
            fa["risk_level"] = "high"

        # Auth forms
        if any(kw in " ".join(names) for kw in ["password", "passwd", "login", "signin"]):
            fa["findings"].append({"type": "Auth Form", "severity": "info",
                                   "detail": f"Login form found. Inputs: {names}"})
            if form.get("action", "").startswith("http://"):
                fa["findings"].append({"type": "Insecure Auth", "severity": "critical",
                                       "detail": "Auth form submits over HTTP"})
                fa["risk_level"] = "critical"

        # File upload
        if "file" in [i.get("type", "") for i in inputs]:
            fa["findings"].append({"type": "File Upload", "severity": "medium",
                                   "detail": "File upload input found"})

        # Hidden fields
        for inp in inputs:
            if inp.get("hidden") and inp.get("value"):
                fa["findings"].append({"type": "Hidden Field", "severity": "low",
                                       "detail": f"{inp.get('name', '?')} = {inp.get('value', '')[:50]}"})

        # Injectable params
        sqli_names = ["id", "user", "search", "query", "q", "order", "sort", "filter"]
        injectable = [n for n in names if any(c in n for c in sqli_names)]
        if injectable:
            fa["findings"].append({"type": "Injection Candidates", "severity": "medium",
                                   "detail": f"Interesting params: {injectable}"})

        if fa["findings"]:
            analysis.append(fa)
    return analysis


# =============================================================================
# TOOL 5: Endpoint Prober (Async, passive)
# =============================================================================
def endpoint_prober(base_url: str, endpoints: list) -> list:
    """
    Passively probe discovered endpoints with GET only.
    No method bruting, no payload injection. Just checks:
    - Does the endpoint exist?
    - What does it return? (status, size, content-type, headers)
    - Is there anything interesting in the response?
    """
    results = []

    jobs = []
    for ep in endpoints[:MAX_FUZZ_ENDPOINTS]:
        url = ep if ep.startswith("http") else f"{base_url.rstrip('/')}{ep}"
        jobs.append((url, None))
        # Also check .json variant for API endpoints
        if "/api/" in url or "/wp-json/" in url or "/v1/" in url or "/v2/" in url:
            if not url.endswith(".json"):
                jobs.append((f"{url}.json", "json_variant"))

    async def probe_one(client, sem, url, note):
        async with sem:
            try:
                r = await client.get(url, follow_redirects=True)
                if r.status_code != 404:
                    res = {
                        "endpoint": url,
                        "status": r.status_code,
                        "size": len(r.text),
                        "content_type": r.headers.get("content-type", ""),
                    }

                    # Capture interesting headers
                    hdrs = {}
                    for h in ("allow", "x-powered-by", "server", "x-debug",
                              "www-authenticate", "x-frame-options",
                              "access-control-allow-origin", "x-request-id",
                              "x-rag-provider", "x-generator"):
                        v = r.headers.get(h)
                        if v:
                            hdrs[h] = v
                    if hdrs:
                        res["headers"] = hdrs

                    # Preview for small responses (API responses, configs)
                    if r.status_code == 200 and len(r.text) < 5000:
                        res["preview"] = r.text[:500]

                    # Flag auth-required endpoints
                    if r.status_code in (401, 403):
                        res["note"] = "requires_auth"
                    elif r.status_code == 500:
                        res["note"] = "server_error"
                    elif note:
                        res["note"] = note

                    results.append(res)
            except Exception:
                pass

    async def run():
        sem = asyncio.Semaphore(FUZZ_THREADS)
        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT, verify=False,
            follow_redirects=True,
        ) as client:
            await asyncio.gather(*[probe_one(client, sem, u, n) for u, n in jobs],
                                 return_exceptions=True)

    asyncio.run(run())

    # Deduplicate
    seen = set()
    unique = []
    for r in results:
        key = f"{r['endpoint']}:{r['status']}"
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique
