# =============================================================================
# ReconCrew v3 - Agents
# =============================================================================
# Semi-agentic: each agent runs its tool directly, then asks the LLM
# ONE question to analyze the results. No ReAct loops. No tool selection.
# The agent's "intelligence" is in how it interprets results, not in
# deciding what to do.
#
# If the LLM fails, the agent returns raw data — the scan never breaks.
# =============================================================================

import json
from llm_client import llm_ask_json


AGENT_SYSTEM = """You are a senior penetration tester analyzing reconnaissance data.
You MUST respond with ONLY valid JSON, no markdown, no backticks, no explanation.
Be specific about security implications. Flag version-specific vulnerabilities."""


def agent_spider_analyze(spider_data: dict) -> dict:
    """Agent: analyze spider results for interesting patterns."""
    summary = {
        "pages_crawled": len(spider_data.get("pages", [])),
        "technologies": spider_data.get("technologies_detected", []),
        "headers": spider_data.get("headers_of_interest", {}),
        "emails": spider_data.get("emails", []),
        "comments_sample": spider_data.get("comments", [])[:15],
        "external_links_sample": spider_data.get("external_links", [])[:10],
        "forms_count": len(spider_data.get("forms", [])),
        "meta_generators": [
            m.get("content", "") for m in spider_data.get("meta_tags", [])
            if m.get("name") == "generator"
        ],
    }

    prompt = f"""Analyze this web spider output and identify security-relevant findings.

DATA:
{json.dumps(summary, indent=2)}

Return JSON:
{{
  "findings": [
    {{"title": "...", "severity": "critical|high|medium|low|info", "category": "information_disclosure", "description": "...", "evidence": "...", "recommendation": "..."}}
  ],
  "technologies_summary": ["clean list of detected tech with versions"],
  "attack_surface_notes": "brief notes on interesting attack vectors spotted"
}}"""

    result = llm_ask_json(prompt, AGENT_SYSTEM)
    if result:
        print(f"    [AI] Spider agent found {len(result.get('findings', []))} findings")
        return result

    # Fallback: basic findings from raw data
    findings = []
    for tech in summary["technologies"]:
        findings.append({"title": f"Technology: {tech}", "severity": "info",
                         "category": "information_disclosure", "description": f"Detected: {tech}",
                         "evidence": tech, "recommendation": "Keep updated"})
    for email in summary["emails"]:
        findings.append({"title": f"Email Exposed: {email}", "severity": "low",
                         "category": "information_disclosure", "description": "Email found in HTML source",
                         "evidence": email, "recommendation": "Consider removing from source"})
    return {"findings": findings, "technologies_summary": summary["technologies"],
            "attack_surface_notes": "LLM unavailable, basic analysis only"}


def agent_js_analyze(js_data: list) -> dict:
    """Agent: analyze JS findings for security impact."""
    if not js_data or all(isinstance(f, dict) and "note" in f for f in js_data):
        return {"findings": [], "notes": "No target-specific JS to analyze"}

    # Condense for LLM
    condensed = []
    for f in js_data:
        if isinstance(f, dict) and (f.get("endpoints") or f.get("secrets") or f.get("comments")):
            condensed.append({
                "file": f.get("file", ""),
                "endpoints": f.get("endpoints", [])[:20],
                "secrets": f.get("secrets", []),
                "comments": f.get("comments", [])[:5],
                "source_maps": f.get("source_maps", []),
            })

    if not condensed:
        return {"findings": [], "notes": "No interesting JS findings"}

    prompt = f"""Analyze these JavaScript analysis results for security issues.

DATA:
{json.dumps(condensed, indent=2)}

Return JSON:
{{
  "findings": [
    {{"title": "...", "severity": "critical|high|medium|low|info", "category": "endpoints|secrets|information_disclosure", "description": "...", "evidence": "...", "recommendation": "..."}}
  ],
  "interesting_endpoints": ["list of endpoints worth testing manually"],
  "notes": "any patterns or architecture observations"
}}"""

    result = llm_ask_json(prompt, AGENT_SYSTEM)
    if result:
        print(f"    [AI] JS agent found {len(result.get('findings', []))} findings")
        return result

    # Fallback
    findings = []
    for f in js_data:
        if isinstance(f, dict):
            for s in f.get("secrets", []):
                findings.append({"title": f"Secret in JS: {s['type']}", "severity": "high",
                                 "category": "secrets", "description": f"Found in {f.get('file', '?')}",
                                 "evidence": s["value"][:50], "recommendation": "Remove from client-side code"})
    return {"findings": findings, "notes": "LLM unavailable, basic analysis"}


def agent_secrets_analyze(secrets_data: list) -> dict:
    """Agent: analyze secrets scan results."""
    if not secrets_data:
        return {"findings": [], "notes": "No sensitive paths found"}

    prompt = f"""Analyze these sensitive path scan results.

DATA:
{json.dumps(secrets_data, indent=2)}

Return JSON:
{{
  "findings": [
    {{"title": "...", "severity": "critical|high|medium|low|info", "category": "secrets|misconfig", "description": "...", "evidence": "...", "recommendation": "..."}}
  ],
  "notes": "overall assessment of exposed paths"
}}"""

    result = llm_ask_json(prompt, AGENT_SYSTEM)
    if result:
        print(f"    [AI] Secrets agent found {len(result.get('findings', []))} findings")
        return result

    # Fallback
    findings = []
    for s in secrets_data:
        sev = "high" if s.get("secrets_found") else ("medium" if s.get("status") == 200 else "low")
        findings.append({"title": f"Sensitive Path: {s.get('path', '?')}", "severity": sev,
                         "category": "secrets", "description": f"HTTP {s.get('status')} on {s.get('path')}",
                         "evidence": s.get("preview", "")[:200] if s.get("status") == 200 else "",
                         "recommendation": "Restrict access"})
    return {"findings": findings, "notes": "LLM unavailable"}


def agent_forms_analyze(forms_data: list) -> dict:
    """Agent: analyze form security issues."""
    if not forms_data:
        return {"findings": [], "notes": "No form issues found"}

    # Condense - deduplicate similar findings
    form_summary = {"total_forms_with_issues": len(forms_data), "issue_types": {}}
    for form in forms_data:
        for f in form.get("findings", []):
            t = f.get("type", "?")
            form_summary["issue_types"][t] = form_summary["issue_types"].get(t, 0) + 1
    form_summary["sample_forms"] = forms_data[:10]

    prompt = f"""Analyze these form security findings.

DATA:
{json.dumps(form_summary, indent=2)}

Return JSON:
{{
  "findings": [
    {{"title": "...", "severity": "critical|high|medium|low|info", "category": "forms", "description": "...", "evidence": "...", "recommendation": "..."}}
  ],
  "notes": "overall form security assessment"
}}"""

    result = llm_ask_json(prompt, AGENT_SYSTEM)
    if result:
        print(f"    [AI] Forms agent found {len(result.get('findings', []))} findings")
        return result

    # Fallback
    findings = []
    for ftype, count in form_summary["issue_types"].items():
        findings.append({"title": f"{ftype} ({count} forms)", "severity": "medium",
                         "category": "forms", "description": f"{count} forms affected",
                         "evidence": f"Found in {count} forms", "recommendation": "Review form security"})
    return {"findings": findings, "notes": "LLM unavailable"}


def agent_fuzz_analyze(fuzz_data: list) -> dict:
    """Agent: analyze fuzzing results for access control issues."""
    if not fuzz_data:
        return {"findings": [], "notes": "No fuzzing results"}

    # Group by interesting patterns
    fuzz_summary = {
        "total_interesting_responses": len(fuzz_data),
        "by_status": {},
        "methods_accepted": {},
        "notable": [],
    }
    for r in fuzz_data:
        s = str(r.get("status", "?"))
        fuzz_summary["by_status"][s] = fuzz_summary["by_status"].get(s, 0) + 1
        m = r.get("method", "?")
        if m not in ("GET", "OPTIONS"):
            fuzz_summary["methods_accepted"][m] = fuzz_summary["methods_accepted"].get(m, 0) + 1

    # Notable: non-GET methods returning 200, auth endpoints, debug endpoints
    for r in fuzz_data:
        if (r.get("method") in ("PUT", "DELETE", "PATCH") and r.get("status") == 200) or \
           r.get("status") in (401, 403, 500) or \
           any(kw in r.get("endpoint", "") for kw in ["admin", "debug", "config", "users"]):
            fuzz_summary["notable"].append(r)
            if len(fuzz_summary["notable"]) >= 20:
                break

    prompt = f"""Analyze these endpoint fuzzing results for access control and security issues.

DATA:
{json.dumps(fuzz_summary, indent=2)}

Return JSON:
{{
  "findings": [
    {{"title": "...", "severity": "critical|high|medium|low|info", "category": "endpoints|misconfig", "description": "...", "evidence": "...", "recommendation": "..."}}
  ],
  "notes": "access control assessment"
}}"""

    result = llm_ask_json(prompt, AGENT_SYSTEM)
    if result:
        print(f"    [AI] Fuzz agent found {len(result.get('findings', []))} findings")
        return result

    # Fallback
    findings = []
    for r in fuzz_summary["notable"][:10]:
        findings.append({"title": f"{r.get('method')} {r.get('endpoint', '?')} → {r.get('status')}",
                         "severity": "medium", "category": "endpoints",
                         "description": f"Endpoint responds to {r.get('method')}",
                         "evidence": json.dumps(r), "recommendation": "Review access controls"})
    return {"findings": findings, "notes": "LLM unavailable"}


def agent_coordinator(target: str, all_agent_results: dict, duration: float) -> dict:
    """Coordinator: synthesize all agent findings into final report."""
    # Collect all findings
    all_findings = []
    all_technologies = []
    all_notes = []

    for agent_name, result in all_agent_results.items():
        all_findings.extend(result.get("findings", []))
        all_technologies.extend(result.get("technologies_summary", []))
        notes = result.get("notes") or result.get("attack_surface_notes")
        if notes:
            all_notes.append(f"{agent_name}: {notes}")

    # Deduplicate technologies
    all_technologies = list(set(all_technologies))

    summary_for_llm = {
        "target": target,
        "total_findings": len(all_findings),
        "findings_by_severity": {},
        "agent_notes": all_notes,
        "technologies": all_technologies,
        "findings": all_findings[:50],  # Cap to fit context
    }
    for f in all_findings:
        sev = f.get("severity", "info")
        summary_for_llm["findings_by_severity"][sev] = summary_for_llm["findings_by_severity"].get(sev, 0) + 1

    prompt = f"""You are the lead pentester. Synthesize all agent findings into a final report.

ALL FINDINGS:
{json.dumps(summary_for_llm, indent=2)}

Return JSON:
{{
  "executive_summary": "2-3 paragraphs: what was tested, key risks, overall posture",
  "technologies": ["final clean tech list"],
  "findings": [sorted by severity, deduplicated, each with title/severity/category/description/evidence/recommendation],
  "statistics": {{"pages_crawled": 0, "total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}},
  "next_steps": ["prioritized list of recommended manual testing actions"]
}}"""

    result = llm_ask_json(prompt, AGENT_SYSTEM)
    if result:
        print(f"    [AI] Coordinator produced report with {len(result.get('findings', []))} findings")
        return result

    # Fallback: assemble without LLM
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

    stats = {"pages_crawled": 0, "total_findings": len(all_findings)}
    for f in all_findings:
        s = f.get("severity", "info")
        stats[s] = stats.get(s, 0) + 1

    return {
        "executive_summary": f"Reconnaissance scan of {target}. Found {len(all_findings)} findings.",
        "technologies": all_technologies,
        "findings": all_findings,
        "statistics": stats,
        "next_steps": ["Manual testing of critical findings", "Authentication testing",
                       "SQL injection on identified parameters", "WPScan for WordPress vulns"],
    }
