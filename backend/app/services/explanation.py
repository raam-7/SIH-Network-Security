"""Grounded finding explanations that never participate in compliance decisions."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from backend.app.schemas import ExplanationInput, Finding, FindingExplanation


class ExplanationProvider(Protocol):
    def explain(self, context: ExplanationInput) -> FindingExplanation | dict[str, Any]: ...


class DeterministicExplanationProvider:
    """Safe fallback provider derived exclusively from the structured finding."""

    def explain(self, context: ExplanationInput) -> FindingExplanation:
        observed = repr(context.observed_value)
        expected = repr(context.expected_value)
        concept = context.semantic_concept or context.rule_id
        evidence = context.evidence.exact_text or "No exact configuration statement was captured."
        if context.result.value == "PASS":
            why = f"The observed {concept} value {observed} matches the expected value {expected}."
        elif context.result.value == "FAIL":
            why = f"The observed {concept} value {observed} does not match the expected value {expected}."
        else:
            why = "The deterministic rule could not establish compliance from the available evidence; human review is required."
        return FindingExplanation(
            explanation=why,
            detected_condition=f"Observed {concept} {context.semantic_property or 'value'} = {observed}.",
            expected_condition=f"Expected {concept} {context.semantic_property or 'value'} = {expected}.",
            evidence_summary=f"Evidence from {context.vendor}/{context.platform}: {evidence}",
            explanation_confidence=1.0 if context.evidence.exact_text else 0.7,
            source="deterministic-fallback",
        )


class ExplanationService:
    def __init__(self, provider: ExplanationProvider | None = None):
        self.provider = provider or DeterministicExplanationProvider()
        self.fallback = DeterministicExplanationProvider()

    def explain(self, finding: Finding, *, vendor: str, platform: str) -> FindingExplanation:
        context = ExplanationInput(
            rule_id=finding.rule_id, result=finding.result, severity=finding.severity,
            vendor=vendor, platform=platform, semantic_concept=finding.semantic_concept,
            semantic_property=finding.semantic_property, observed_value=finding.observed_value,
            expected_value=finding.expected_value, evidence=finding.evidence,
            remediation=finding.remediation,
        )
        try:
            candidate = FindingExplanation.model_validate(self.provider.explain(context))
            self._validate_grounding(candidate, context)
            return candidate
        except Exception:
            return self.fallback.explain(context)

    @staticmethod
    def _validate_grounding(candidate: FindingExplanation, context: ExplanationInput) -> None:
        if context.evidence.exact_text and context.evidence.exact_text not in candidate.evidence_summary:
            raise ValueError("provider evidence summary is not grounded in exact evidence")
        if candidate.source.strip() == "":
            raise ValueError("provider source is required")
