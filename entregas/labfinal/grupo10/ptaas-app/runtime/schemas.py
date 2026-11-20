"""Contratos estrictos de la demo: no aceptan campos extra ni hallazgos inventados."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Text = Annotated[str, Field(min_length=1, max_length=1500)]


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True)


class EngagementPlan(StrictModel):
    agents: list[Literal["asset_discovery", "correlation", "reporting"]] = Field(min_length=3, max_length=3)
    max_iterations: int = Field(ge=1, le=2)
    needs_human: Text | None


class ReconDecision(StrictModel):
    action: Literal["httpx.probe", "stop"]
    target: Annotated[str, Field(min_length=1, max_length=253)]
    reason: Text


class Asset(StrictModel):
    id: Text
    address: Literal["dvwa.lab.test"]
    source_tool: Literal["fixture.httpx.probe"]
    simulated: Literal[True]


class CorrelationResult(StrictModel):
    candidates: list[dict[str, str]] = Field(max_length=0)
    reason: Text


class AlertReview(StrictModel):
    id: Annotated[str, Field(pattern=r"^bandit-[1-9][0-9]*$", max_length=24)]
    status: Literal["needs_review", "possible_false_positive", "inconclusive"]
    recommendation: Annotated[str, Field(min_length=1, max_length=300)]


class BanditAnalysis(StrictModel):
    reviews: list[AlertReview] = Field(max_length=20)


class DemoReport(StrictModel):
    simulated: Literal[True]
    status: Literal["draft"]
    conclusion: Literal["coordination_only_not_a_pentest"]
    executive_summary: Text
    assets: list[Literal["dvwa.lab.test"]] = Field(max_length=1)
    findings: list[dict[str, str]] = Field(max_length=0)
    limitations: list[Text] = Field(min_length=1, max_length=5)
    evidence_refs: list[Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]] = Field(max_length=4)
