"""Validated scan, analysis, routing, and provider configuration."""

from __future__ import annotations

from typing import Self
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator

from aegisflow.contracts import ContractModel, Language, Severity


class ScanLimits(ContractModel):
    max_files: int = Field(default=10_000, ge=1, le=1_000_000)
    max_total_bytes: int = Field(default=100 * 1024 * 1024, ge=1)
    max_file_bytes: int = Field(default=2 * 1024 * 1024, ge=1)
    max_depth: int = Field(default=32, ge=1, le=256)

    @model_validator(mode="after")
    def validate_byte_limits(self) -> Self:
        if self.max_file_bytes > self.max_total_bytes:
            raise ValueError("max_file_bytes may not exceed max_total_bytes")
        return self


class AnalysisConfig(ContractModel):
    languages: list[Language] = Field(
        default_factory=lambda: [Language.JAVASCRIPT, Language.PYTHON, Language.TYPESCRIPT]
    )
    enabled_rule_ids: list[str] = Field(default_factory=list)
    max_snippet_bytes: int = Field(default=8_192, ge=256, le=1_000_000)

    @field_validator("languages")
    @classmethod
    def validate_languages(cls, value: list[Language]) -> list[Language]:
        if not value:
            raise ValueError("at least one language must be enabled")
        if len(set(value)) != len(value):
            raise ValueError("languages must not contain duplicates")
        return sorted(value, key=lambda language: language.value)

    @field_validator("enabled_rule_ids")
    @classmethod
    def validate_rule_ids(cls, value: list[str]) -> list[str]:
        normalized = [rule_id.strip() for rule_id in value]
        if any(not rule_id for rule_id in normalized):
            raise ValueError("enabled_rule_ids may not contain empty values")
        if len(set(normalized)) != len(normalized):
            raise ValueError("enabled_rule_ids must not contain duplicates")
        return sorted(normalized)


class RoutingPolicy(ContractModel):
    auto_confirm_confidence: float = Field(default=0.90, ge=0.0, le=1.0)
    auto_reject_confidence: float = Field(default=0.95, ge=0.0, le=1.0)
    agent_review_severities: list[Severity] = Field(
        default_factory=lambda: [Severity.CRITICAL, Severity.HIGH]
    )

    @field_validator("agent_review_severities")
    @classmethod
    def validate_severities(cls, value: list[Severity]) -> list[Severity]:
        if len(set(value)) != len(value):
            raise ValueError("agent_review_severities must not contain duplicates")
        severity_order = {severity: index for index, severity in enumerate(Severity)}
        return sorted(value, key=severity_order.__getitem__)


class ProviderConfig(ContractModel):
    base_url: str
    model: str
    api_key_env: str = "OPENAI_API_KEY"
    timeout_seconds: float = Field(default=30.0, gt=0.0, le=300.0)
    max_context_bytes: int = Field(default=32_768, ge=1_024, le=1_000_000)
    input_cost_per_million_tokens: float = Field(default=0.0, ge=0.0)
    output_cost_per_million_tokens: float = Field(default=0.0, ge=0.0)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        value = value.rstrip("/")
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ValueError("base_url must not contain credentials")
        return value

    @field_validator("model", "api_key_env")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be empty")
        return value


class AppConfig(ContractModel):
    scan: ScanLimits = Field(default_factory=ScanLimits)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    routing: RoutingPolicy = Field(default_factory=RoutingPolicy)
    provider: ProviderConfig | None = None


__all__ = [
    "AnalysisConfig",
    "AppConfig",
    "ProviderConfig",
    "RoutingPolicy",
    "ScanLimits",
]
