from typing import Optional
from fastapi import APIRouter, Depends

from src.intelligence.graph_reasoning import GraphReasoningEngine
from src.intelligence.llm import generate_threat_narrative, chat_threat_intel
from src.intelligence.schema import (
    ThreatAnalysisRequest,
    ThreatAnalysisReport,
    ThreatChatRequest,
    ThreatChatResponse,
    ThreatNarrativeResponse,
)

router = APIRouter(prefix="/api/intelligence", tags=["Threat Intelligence & Reasoning"])

_reasoning_engine: Optional[GraphReasoningEngine] = None


def get_reasoning_engine() -> GraphReasoningEngine:
    global _reasoning_engine
    if _reasoning_engine is None:
        _reasoning_engine = GraphReasoningEngine()
    return _reasoning_engine


@router.post(
    "/analyze",
    summary="Multi-Hop Threat Intelligence Analysis & Mitigation Matrix",
    response_model=ThreatAnalysisReport,
)
def analyze_threat_narrative(
    request: ThreatAnalysisRequest,
    engine: GraphReasoningEngine = Depends(get_reasoning_engine),
):
    """
    Analyzes an attack scenario narrative, alert text, or observation using Reciprocal Rank Fusion
    and performs automated multi-hop graph reasoning:
    1. Extracts primary attack techniques using RRF.
    2. Attributes most likely adversary groups (APTs) based on technique overlap.
    3. Identifies software tools and malware associated with the observed TTPs.
    4. Computes prioritized mitigation matrix ranked by defensive attack-chain coverage percentage.
    5. Compiles detection data sources and monitoring guidance.
    """
    return engine.analyze_narrative(
        query=request.query,
        max_techniques=request.max_techniques,
        k=request.k,
        history=request.history,
    )



@router.post(
    "/narrative",
    summary="ChatGPT AI Executive Briefing & Containment Runbook",
)
def generate_ai_narrative(report: ThreatAnalysisReport):
    """
    Synthesizes the retrieved MITRE ATT&CK ground truth into an executive incident briefing
    and threat hunting/containment playbook using OpenAI ChatGPT (GPT-4o-mini).
    """
    return generate_threat_narrative(report)


@router.post(
    "/chat",
    summary="Interactive ChatGPT Threat Hunting Copilot",
)
def chat_with_threat_intelligence(request: ThreatChatRequest):
    """
    Allows the analyst to ask interactive follow-up questions to ChatGPT grounded in the
    retrieved MITRE ATT&CK techniques, attributed threat actors, and mitigations.
    """
    return chat_threat_intel(
        report=request.report,
        user_message=request.message,
        history=request.history,
    )

