import os
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
from openai import OpenAI

from src.intelligence.schema import ThreatAnalysisReport

load_dotenv()

_openai_client: Optional[OpenAI] = None


def get_openai_client() -> Optional[OpenAI]:
    global _openai_client
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or api_key.strip() == "":
        return None

    base_url = os.getenv("OPENAI_BASE_URL")
    # Auto-detect Groq keys
    if not base_url and api_key.startswith("gsk_"):
        base_url = "https://api.groq.com/openai/v1"

    if _openai_client is None:
        if base_url:
            _openai_client = OpenAI(api_key=api_key, base_url=base_url)
        else:
            _openai_client = OpenAI(api_key=api_key)
    return _openai_client


def is_llm_available() -> bool:
    return get_openai_client() is not None


def _format_report_context(report: ThreatAnalysisReport) -> str:
    lines = []
    lines.append(f"Incident / Query: \"{report.query}\"\n")

    lines.append("### Identified MITRE Techniques:")
    for t in report.identified_techniques:
        tactics = ", ".join(t.tactics) if t.tactics else "Unknown"
        lines.append(f"- {t.attack_id}: {t.name} [Tactics: {tactics}]")
        if t.description:
            lines.append(f"  Description: {t.description[:200]}...")

    if report.attributed_groups:
        lines.append("\n### Attributed Threat Groups:")
        for g in report.attributed_groups:
            sw = ", ".join(g.software_used[:5]) if g.software_used else "None known"
            overlap = round((g.overlap_ratio or 0) * 100)
            lines.append(f"- {g.group.attack_id}: {g.group.name} ({overlap}% overlap) | Software Arsenal: {sw}")

    if report.identified_software:
        lines.append("\n### Identified Software / Tools:")
        for s in report.identified_software:
            lines.append(f"- {s.software.attack_id}: {s.software.name} ({s.software.type}) | Matched Techniques: {', '.join(s.matched_techniques)}")

    if report.prioritized_mitigations:
        lines.append("\n### Prioritized Defensive Mitigations:")
        for m in report.prioritized_mitigations[:5]:
            lines.append(f"- {m.mitigation.attack_id}: {m.mitigation.name} ({m.coverage_percentage:.0f}% chain coverage)")
            if m.mitigation.description:
                lines.append(f"  Guidance: {m.mitigation.description[:180]}...")

    return "\n".join(lines)


def generate_threat_narrative(report: ThreatAnalysisReport) -> Dict[str, Any]:
    client = get_openai_client()
    if not client:
        return {
            "available": False,
            "narrative": (
                "OpenAI API key is not configured. Add OPENAI_API_KEY to your environment variables "
                "or .env file to enable automated ChatGPT executive briefings and threat hunting runbooks."
            ),
            "model": None,
        }

    model = os.getenv("OPENAI_MODEL", "openai/gpt-oss-120b")
    context = _format_report_context(report)

    system_prompt = (
        "You are Cypher AI, an elite cybersecurity threat intelligence analyst. "
        "Analyze the provided MITRE ATT&CK incident attribution and generate a concise, high-impact tactical briefing. "
        "Strictly ground all assertions in the provided techniques, threat actors, and mitigations. "
        "Do not invent facts or hallucinate external frameworks (OWASP/NIST). Keep the tone authoritative, clear, and actionable."
    )

    user_prompt = f"""
Ground Truth MITRE ATT&CK Intelligence Graph:
{context}

Please provide:
1. Executive Incident Summary (2-3 sentences explaining what occurred and tactical risk).
2. Adversary Profile & Tooling Analysis (threat actor correlation and malware capabilities).
3. Immediate SOC Containment & Threat Hunting Runbook (concrete steps, log sources, and defensive verification based strictly on the prioritized mitigations).
"""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=900,
        )
        narrative = response.choices[0].message.content
        return {
            "available": True,
            "narrative": narrative,
            "model": model,
        }
    except Exception as e:
        print(f"[llm.py] Narrative generation error: {e}")
        return {
            "available": False,
            "narrative": "AI narrative generation is currently unavailable. Please refer to the verified MITRE ATT&CK graph intelligence.",
            "model": model,
        }


def chat_threat_intel(
    report: ThreatAnalysisReport,
    user_message: str,
    history: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    client = get_openai_client()
    if not client:
        return {
            "available": False,
            "reply": "OpenAI API key is not configured. Please set OPENAI_API_KEY.",
            "model": None,
        }

    model = os.getenv("OPENAI_MODEL", "openai/gpt-oss-120b")
    context = _format_report_context(report)

    system_prompt = (
        "You are Cypher AI Assistant, a specialized MITRE ATT&CK threat intelligence copilot. "
        "The analyst is investigating an incident with the following MITRE ATT&CK graph context:\n\n"
        f"{context}\n\n"
        "Answer questions specifically and practically regarding this threat scenario, detection rules (Sigma/Splunk), "
        "containment commands, or adversary behavior. Be concise, direct, and technically precise."
    )

    messages = [{"role": "system", "content": system_prompt}]

    # Append recent conversation history if provided
    if history:
        for msg in history[-6:]:
            messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})

    messages.append({"role": "user", "content": user_message})

    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.3,
            max_tokens=700,
        )
        reply = response.choices[0].message.content
        return {
            "available": True,
            "reply": reply,
            "model": model,
        }
    except Exception as e:
        print(f"[llm.py] Chat copilot error: {e}")
        return {
            "available": False,
            "reply": "AI copilot response is currently unavailable. Please retry in a few moments.",
            "model": model,
        }
