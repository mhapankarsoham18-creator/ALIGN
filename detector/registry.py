"""
AIDDS Detector — Agent identity registry.

A tool-call event carries the *role the agent claims*.  Left alone, a compromised or
mis-configured agent could simply claim a more permissive role.  The registry binds an
``agent_id`` to the role it was provisioned with; the detector then evaluates the agent
against the **bound** role no matter what the event says, and raises an
``identity_mismatch`` signal when the claim differs.

Binding sources, in order:
1. ``registry/agents.yaml`` (explicit, owner-controlled)::

       agents:
         procurement-bot-04: procurement-agent

2. First-seen binding: the first role an unregistered agent presents is remembered by the
   gateway (stored with the agent's state) and enforced from then on.
"""

from __future__ import annotations

import pathlib
from functools import lru_cache

import yaml

from gateway.config import settings


def load_registry(path: str | pathlib.Path) -> dict[str, str]:
    p = pathlib.Path(path)
    if not p.exists():
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    agents = data.get("agents", {}) or {}
    return {str(a): str(r) for a, r in agents.items()}


@lru_cache(maxsize=1)
def get_registry() -> dict[str, str]:
    return load_registry(settings.agent_registry_file)


def registered_role(agent_id: str) -> str | None:
    return get_registry().get(agent_id)


def reload_registry() -> None:
    get_registry.cache_clear()
