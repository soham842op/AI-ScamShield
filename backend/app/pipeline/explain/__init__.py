"""Explanation service. Template only for now; no model call is made."""

from app.pipeline.explain.template import TEMPLATE_VERSION, template_explanation
from app.pipeline.types import Explanation, ExplanationEvidence

__all__ = ["TEMPLATE_VERSION", "explain", "template_explanation"]


async def explain(evidence: ExplanationEvidence) -> Explanation:
    return Explanation(text=template_explanation(evidence), source="template", prompt_version=None)
