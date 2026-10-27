"""
AIDDS Detector — Manifest loader.

Reads signed YAML role manifests from the manifests directory and provides lookup by role
name.  Loaded once at startup and cached for the lifetime of the process.

When ``settings.require_signed_manifests`` is true (the default) a manifest is only accepted if
its Ed25519 signature verifies against ``manifests/trusted_keys.json``.  Rejected manifests are
**not** loaded, so their role is treated as unknown and fails closed.
"""

from __future__ import annotations

import logging
import pathlib
from functools import lru_cache

import yaml

from detector.schemas import RoleManifest
from detector.signing import load_trusted_keys, verify_manifest
from gateway.config import settings

logger = logging.getLogger("aidds.manifests")

# role -> reason, for manifests that were found but rejected
_rejected: dict[str, str] = {}


def _load_manifests_from_dir(
    manifests_dir: pathlib.Path,
    trusted_keys: dict[str, str] | None = None,
) -> dict[str, RoleManifest]:
    """
    Parse every .yaml file in *manifests_dir* into a RoleManifest.

    If ``trusted_keys`` is given, manifests whose signature does not verify are skipped and
    recorded in ``_rejected``; otherwise no signature check is made.
    """
    manifests: dict[str, RoleManifest] = {}
    _rejected.clear()

    if not manifests_dir.exists():
        return manifests

    for path in sorted(manifests_dir.glob("*.yaml")):
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        if raw is None:
            continue
        manifest = RoleManifest.model_validate(raw)
        if trusted_keys is not None:
            ok, reason = verify_manifest(manifest, trusted_keys)
            if not ok:
                _rejected[manifest.role] = reason
                logger.error("manifest %s REJECTED: %s", path.name, reason)
                continue
        manifests[manifest.role] = manifest

    return manifests


@lru_cache(maxsize=1)
def get_manifests() -> dict[str, RoleManifest]:
    """Return all manifests keyed by role, loading from disk on first call."""
    manifests_dir = pathlib.Path(settings.manifests_dir)
    trusted = (
        load_trusted_keys(settings.trusted_keys_file) if settings.require_signed_manifests else None
    )
    return _load_manifests_from_dir(manifests_dir, trusted)


def get_manifest(role: str) -> RoleManifest | None:
    """Look up a single manifest by role name."""
    return get_manifests().get(role)


def rejected_manifests() -> dict[str, str]:
    """Roles whose manifest failed signature verification, with the reason."""
    get_manifests()
    return dict(_rejected)


def get_all_honeypots() -> dict[str, list[str]]:
    """Return {role: [honeypot_resource, ...]} for all loaded manifests."""
    return {role: m.honeypots for role, m in get_manifests().items() if m.honeypots}


def reload_manifests() -> None:
    """Clear the cache so manifests are re-read from disk on next access."""
    get_manifests.cache_clear()
