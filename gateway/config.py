"""
AIDDS Gateway — Application settings.

Every setting can be overridden with an environment variable prefixed ``AIDDS_``
(for example ``AIDDS_ANALYST_API_KEY``).
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    app_name: str = "AIDDS"
    debug: bool = False
    database_url: str = Field(
        default="sqlite+aiosqlite:///aidds.db",
        description="SQLAlchemy connection string for the event store",
    )
    manifests_dir: str = Field(
        default="manifests",
        description="Path to directory containing signed role manifest YAML files",
    )
    trusted_keys_file: str = Field(
        default="manifests/trusted_keys.json",
        description="JSON file of trusted Ed25519 public keys used to verify manifest signatures",
    )
    agent_registry_file: str = Field(
        default="registry/agents.yaml",
        description="Optional YAML mapping of agent_id -> role (binds identity to role)",
    )
    baselines_dir: str = Field(
        default="baselines",
        description="Directory holding per-role behaviour baselines (JSON)",
    )
    gateway_port: int = 8000
    inline_timeout_ms: int = Field(
        default=10,
        description="Target p95 for inline rule decisions (milliseconds)",
    )

    # --- security -----------------------------------------------------------
    gateway_api_key: str | None = Field(
        default=None,
        description="If set, POST /v1/tool-calls requires header X-Gateway-Key with this value",
    )
    analyst_api_key: str | None = Field(
        default=None,
        description=(
            "If set, every other /v1 endpoint (events, alerts, approvals, release, manifests) "
            "requires header X-API-Key with this value. Leave unset ONLY for local development."
        ),
    )
    require_signed_manifests: bool = Field(
        default=True,
        description="Reject manifests whose Ed25519 signature does not verify",
    )

    # --- behaviour ----------------------------------------------------------
    demo_mode: bool = Field(
        default=False,
        description="Enable /v1/demo/* endpoints and pre-listed demo agents (never in production)",
    )
    learn_baselines: bool = Field(
        default=True,
        description="Update per-role baselines online from clean, in-role, low-risk traffic",
    )
    persist_baselines: bool = Field(
        default=False,
        description="Write learned baselines back to baselines_dir on shutdown",
    )
    enable_embeddings: bool = Field(
        default=False,
        description="Enable the optional sentence-embedding semantic-drift signal "
        "(needs: pip install sentence-transformers)",
    )

    model_config = {"env_prefix": "AIDDS_"}


settings = Settings()
