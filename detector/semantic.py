"""
AIDDS Detector — Optional semantic-drift signal (sentence embeddings).

Embeds the role description and a text rendering of the agent's most recent actions and
measures cosine similarity.  A low similarity means the agent's recent activity no longer
"sounds like" its role.

This is **off by default**: it needs the optional ``sentence-transformers`` package (large
download) and embedding similarity on short tool/resource strings is noisy, so it only ever
contributes a small, capped number of points.  Enable with ``AIDDS_ENABLE_EMBEDDINGS=true``.
An ``encoder`` callable can be injected for tests::

    SemanticDrift(encoder=lambda texts: [[...], ...])
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence

from detector.schemas import RoleManifest
from gateway.schemas import Reason, ToolCallEvent

WEIGHT_SEMANTIC_DRIFT = 10
MIN_WINDOW = 5
LOW_SIMILARITY = 0.10  # at or below this -> full points
HIGH_SIMILARITY = 0.30  # at or above this -> no points

Encoder = Callable[[Sequence[str]], Sequence[Sequence[float]]]


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def event_text(event: ToolCallEvent) -> str:
    return f"{event.action.value} {event.tool} {event.resource} {event.data_class.value}"


def role_text(manifest: RoleManifest) -> str:
    return (
        f"{manifest.description} tools: {', '.join(manifest.allowed_tools)}. "
        f"data: {', '.join(manifest.allowed_data_classes)}."
    )


class SemanticDrift:
    def __init__(self, encoder: Encoder | None = None) -> None:
        self._encoder = encoder
        self._role_vecs: dict[str, Sequence[float]] = {}

    def _encode(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
        if self._encoder is None:
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:  # pragma: no cover - optional dependency
                raise RuntimeError(
                    "AIDDS_ENABLE_EMBEDDINGS needs: pip install sentence-transformers"
                ) from exc
            model = SentenceTransformer("all-MiniLM-L6-v2")
            self._encoder = lambda t: model.encode(list(t)).tolist()
        return self._encoder(texts)

    def similarity(self, manifest: RoleManifest, window: Sequence[str]) -> float:
        if manifest.role not in self._role_vecs:
            self._role_vecs[manifest.role] = self._encode([role_text(manifest)])[0]
        vecs = self._encode(["; ".join(window)])
        return _cosine(self._role_vecs[manifest.role], vecs[0])


def check_semantic_drift(
    manifest: RoleManifest | None, window: Sequence[str], drift: SemanticDrift
) -> Reason | None:
    if manifest is None or len(window) < MIN_WINDOW:
        return None
    sim = drift.similarity(manifest, window)
    if sim >= HIGH_SIMILARITY:
        return None
    frac = min(1.0, (HIGH_SIMILARITY - sim) / (HIGH_SIMILARITY - LOW_SIMILARITY))
    points = max(1, round(WEIGHT_SEMANTIC_DRIFT * frac))
    return Reason(
        signal="semantic_drift",
        points=points,
        text=f"recent actions have cosine similarity {sim:.2f} to the role description",
    )
