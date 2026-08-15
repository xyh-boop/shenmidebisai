"""Validated scan, analysis, routing, and provider configuration."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Self
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from aegisflow.contracts import ContractModel, Language, Severity

_MAX_FILES_HARD_LIMIT = 1_000_000
_MAX_TOTAL_BYTES_HARD_LIMIT = 10 * 1024**3
_MAX_FILE_BYTES_HARD_LIMIT = 100 * 1024**2
_MAX_DEPTH_HARD_LIMIT = 256
_MAX_ENTRIES_HARD_LIMIT = 2_000_000
_MAX_DIRECTORIES_HARD_LIMIT = 100_000
_MAX_PATH_BYTES_HARD_LIMIT = 64 * 1024
_MAX_CONTEXT_BYTES_HARD_LIMIT = 1_000_000
_MAX_RESPONSE_BYTES_HARD_LIMIT = 16 * 1024**2


def _is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    normalized = host.rstrip(".").casefold()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


class ScanLimits(ContractModel):
    max_files: int = Field(default=10_000, ge=1, le=_MAX_FILES_HARD_LIMIT)
    max_total_bytes: int = Field(
        default=100 * 1024 * 1024,
        ge=1,
        le=_MAX_TOTAL_BYTES_HARD_LIMIT,
    )
    max_file_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=1,
        le=_MAX_FILE_BYTES_HARD_LIMIT,
    )
    max_depth: int = Field(default=32, ge=1, le=_MAX_DEPTH_HARD_LIMIT)
    max_entries: int = Field(default=100_000, ge=1, le=_MAX_ENTRIES_HARD_LIMIT)
    max_directories: int = Field(default=10_000, ge=1, le=_MAX_DIRECTORIES_HARD_LIMIT)
    max_path_bytes: int = Field(default=4_096, ge=1, le=_MAX_PATH_BYTES_HARD_LIMIT)

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
    allow_insecure_http: bool = False
    timeout_seconds: float = Field(default=30.0, gt=0.0, le=300.0)
    max_context_bytes: int = Field(default=32_768, ge=1_024, le=_MAX_CONTEXT_BYTES_HARD_LIMIT)
    max_response_bytes: int = Field(
        default=1 * 1024 * 1024,
        ge=1_024,
        le=_MAX_RESPONSE_BYTES_HARD_LIMIT,
    )
    input_cost_per_million_tokens: float = Field(default=0.0, ge=0.0)
    output_cost_per_million_tokens: float = Field(default=0.0, ge=0.0)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        value = value.strip()
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("base_url must be a valid absolute URL") from exc
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc or not hostname:
            raise ValueError("base_url must be an absolute HTTPS or loopback HTTP URL")
        if any(character.isspace() for character in value):
            raise ValueError("base_url must not contain whitespace")
        if parsed.username or parsed.password:
            raise ValueError("base_url must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain a query or fragment")
        return value.rstrip("/")

    @model_validator(mode="after")
    def validate_transport(self) -> Self:
        parsed = urlsplit(self.base_url)
        scheme = parsed.scheme.casefold()
        if scheme == "https":
            if self.allow_insecure_http:
                raise ValueError("allow_insecure_http is only valid for loopback HTTP")
            return self
        if not self.allow_insecure_http:
            raise ValueError("HTTP providers require explicit allow_insecure_http=true")
        if not _is_loopback_host(parsed.hostname):
            raise ValueError("insecure HTTP providers must use a loopback host")
        return self

    @property
    def uses_insecure_http(self) -> bool:
        return urlsplit(self.base_url).scheme.casefold() == "http"

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
    require_agent_success: bool = False

    @model_validator(mode="after")
    def validate_agent_policy(self) -> Self:
        if self.require_agent_success and self.provider is None:
            raise ValueError("strict Agent mode requires provider configuration")
        return self


__all__ = [
    "AnalysisConfig",
    "AppConfig",
    "ProviderConfig",
    "RoutingPolicy",
    "ScanLimits",
]
