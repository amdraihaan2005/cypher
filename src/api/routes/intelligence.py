from typing import Optional
from fastapi import APIRouter, Depends

from src.intelligence.graph_reasoning import GraphReasoningEngine
from src.intelligence.schema import (
    ThreatAnalysisRequest,
    ThreatAnalysisReport,
)

router = APIRouter(prefix="/api/intelligence", tags=["Threat Intelligence & Reasoning"])

_reasoning_engine: Optional[GraphReasoningEngine] = None


def get_reasoning_engine() -> GraphReasoningEngine:
    global _reasoning_engine
    if _reasoning_engine is None:
        _reasoning_engine = GraphReasoningEngine()
    return _reasoning_engine


def close_reasoning_engine():
    global _reasoning_engine
    if _reasoning_engine is not None:
        _reasoning_engine.close()
        _reasoning_engine = None


@router.post(
    "/analyze",
    summary="Threat Intelligence Analysis & Mitigation Matrix",
    response_model=ThreatAnalysisReport,
)
async def analyze_threat_narrative(
    request: ThreatAnalysisRequest,
    engine: GraphReasoningEngine = Depends(get_reasoning_engine),
):
    return await engine.analyze_narrative(
        query=request.query,
        max_techniques=request.max_techniques,
        k=request.k,
        history=request.history,
    )
