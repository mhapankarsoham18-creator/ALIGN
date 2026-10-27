"""
AIDDS Detector — Learned per-role behaviour baselines.

What is learned
---------------
For every role we keep a bigram (Markov) model over *tool names*:

    P(tool_t | tool_{t-1})

plus a unigram tool distribution.  Counts are exponentially weighted (EWMA), so the
baseline follows slow, legitimate change but a sudden shift still looks rare.

How the baseline is used
------------------------
* ``sequence_rarity``  - a transition that is very unlikely under the role's Markov model.
* ``distribution_drift`` - Jensen-Shannon divergence between the agent's recent tool mix and
  the role's learned tool mix.

Cold start
----------
A role with fewer than ``MIN_OBS`` effective observations produces *no* statistical signal;
the manifest rules carry the decision until enough data accumulates.  New agents of a known
role are covered immediately because baselines are per role, not per agent.

Seeding and poisoning
---------------------
Baselines are seeded from synthetic random walks over the manifest's allowed tools
(``python -m detector.baseline train``).  At runtime the engine only updates a baseline from
events that were allowed, in-role, untainted and scored in the ``observe`` tier, so an
attacker cannot teach the model that their behaviour is normal by repeating it.
"""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import random
from collections import Counter
from collections.abc import Iterable, Sequence

START = "<start>"

MIN_OBS = 50.0  # effective observations before statistical signals are trusted
SMOOTHING = 1.0  # bigram -> unigram interpolation strength
UNIGRAM_ALPHA = 0.5  # additive smoothing on unigram counts
RARE_P = 0.03  # a transition below this probability is "rare"
DRIFT_MIN_WINDOW = 10  # events needed before the JS divergence is meaningful
DRIFT_THRESHOLD = 0.30  # JS divergence (base 2, range 0..1) above which drift is flagged


class RoleBaseline:
    """EWMA-weighted bigram model over a role's tool sequence."""

    def __init__(self, role: str, decay: float = 0.9995) -> None:
        self.role = role
        self.decay = decay
        self._bigrams: dict[str, dict[str, float]] = {}
        self._unigrams: dict[str, float] = {}
        self._total = 0.0
        self._w = 1.0  # growing weight == exponential forgetting without touching old counts

    # -- learning ---------------------------------------------------------

    def update(self, prev: str, cur: str) -> None:
        """Record one observed transition prev -> cur."""
        self._w /= self.decay
        row = self._bigrams.setdefault(prev, {})
        row[cur] = row.get(cur, 0.0) + self._w
        self._unigrams[cur] = self._unigrams.get(cur, 0.0) + self._w
        self._total += self._w
        if self._w > 1e9:  # renormalise to keep floats healthy
            scale = 1.0 / self._w
            for r in self._bigrams.values():
                for k in r:
                    r[k] *= scale
            for k in self._unigrams:
                self._unigrams[k] *= scale
            self._total *= scale
            self._w = 1.0

    # -- querying ---------------------------------------------------------

    @property
    def n_obs(self) -> float:
        """Effective (decay-weighted) number of observed transitions."""
        return self._total / self._w if self._w else 0.0

    def _unigram_p(self, tool: str) -> float:
        vocab = len(self._unigrams) + 1
        return (self._unigrams.get(tool, 0.0) + UNIGRAM_ALPHA * self._w) / (
            self._total + UNIGRAM_ALPHA * self._w * vocab
        )

    def prob(self, prev: str, cur: str) -> float:
        """Smoothed P(cur | prev), interpolated with the unigram distribution."""
        row = self._bigrams.get(prev, {})
        row_total = sum(row.values())
        uni = self._unigram_p(cur)
        return (row.get(cur, 0.0) + SMOOTHING * self._w * uni) / (row_total + SMOOTHING * self._w)

    def surprisal_bits(self, prev: str, cur: str) -> float:
        return -math.log2(max(self.prob(prev, cur), 1e-12))

    def tool_distribution(self) -> dict[str, float]:
        """Normalised unigram distribution over known tools."""
        if self._total <= 0:
            return {}
        return {t: c / self._total for t, c in self._unigrams.items()}

    # -- persistence ------------------------------------------------------

    def to_dict(self) -> dict[str, object]:
        scale = 1.0 / self._w if self._w else 1.0
        return {
            "role": self.role,
            "decay": self.decay,
            "bigrams": {
                p: {c: round(v * scale, 6) for c, v in row.items()}
                for p, row in self._bigrams.items()
            },
            "unigrams": {t: round(v * scale, 6) for t, v in self._unigrams.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> RoleBaseline:
        b = cls(str(data["role"]), float(data.get("decay", 0.9995)))  # type: ignore[arg-type]
        bigrams = data.get("bigrams", {})
        unigrams = data.get("unigrams", {})
        assert isinstance(bigrams, dict) and isinstance(unigrams, dict)
        b._bigrams = {
            str(p): {str(c): float(v) for c, v in row.items()} for p, row in bigrams.items()
        }
        b._unigrams = {str(t): float(v) for t, v in unigrams.items()}
        b._total = sum(b._unigrams.values())
        return b


# ---------------------------------------------------------------------------
# Distances
# ---------------------------------------------------------------------------


def js_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    """Jensen-Shannon divergence (log base 2): 0 = identical, 1 = disjoint."""
    keys = set(p) | set(q)
    if not keys:
        return 0.0
    m = {k: 0.5 * (p.get(k, 0.0) + q.get(k, 0.0)) for k in keys}

    def kl(a: dict[str, float]) -> float:
        return sum(a[k] * math.log2(a[k] / m[k]) for k in keys if a.get(k, 0.0) > 0)

    return max(0.0, min(1.0, 0.5 * kl(p) + 0.5 * kl(q)))


def empirical_distribution(items: Iterable[str]) -> dict[str, float]:
    counts = Counter(items)
    n = sum(counts.values())
    return {k: v / n for k, v in counts.items()} if n else {}


# ---------------------------------------------------------------------------
# Store (one baseline per role)
# ---------------------------------------------------------------------------


class BaselineStore:
    def __init__(self) -> None:
        self._by_role: dict[str, RoleBaseline] = {}

    def get(self, role: str) -> RoleBaseline | None:
        return self._by_role.get(role)

    def ensure(self, role: str) -> RoleBaseline:
        if role not in self._by_role:
            self._by_role[role] = RoleBaseline(role)
        return self._by_role[role]

    def put(self, baseline: RoleBaseline) -> None:
        self._by_role[baseline.role] = baseline

    def roles(self) -> list[str]:
        return sorted(self._by_role)

    def load_dir(self, path: str | pathlib.Path) -> int:
        d = pathlib.Path(path)
        n = 0
        if d.is_dir():
            for f in sorted(d.glob("*.json")):
                self.put(RoleBaseline.from_dict(json.loads(f.read_text(encoding="utf-8"))))
                n += 1
        return n

    def save_dir(self, path: str | pathlib.Path) -> None:
        d = pathlib.Path(path)
        d.mkdir(parents=True, exist_ok=True)
        for role, b in self._by_role.items():
            (d / f"{role}.json").write_text(json.dumps(b.to_dict(), indent=1), encoding="utf-8")


_store: BaselineStore | None = None


def get_baselines() -> BaselineStore:
    """Return the process-wide baseline store, loading it from disk on first use."""
    global _store
    if _store is None:
        from gateway.config import settings

        _store = BaselineStore()
        _store.load_dir(settings.baselines_dir)
    return _store


def reset_baselines(store: BaselineStore | None = None) -> None:
    """Replace the process-wide store (tests / eval); ``None`` forces a reload from disk."""
    global _store
    _store = store


# ---------------------------------------------------------------------------
# Synthetic seeding
# ---------------------------------------------------------------------------


def synthetic_walk(
    tools: Sequence[str], rng: random.Random, length: int, transition: dict[str, list[float]]
) -> list[str]:
    cur = rng.choice(list(tools))
    seq = [cur]
    for _ in range(length - 1):
        cur = rng.choices(list(tools), weights=transition[cur])[0]
        seq.append(cur)
    return seq


def make_transition(tools: Sequence[str], rng: random.Random) -> dict[str, list[float]]:
    """A random but fully-connected Markov chain: 70% random structure, 30% uniform."""
    n = len(tools)
    rows: dict[str, list[float]] = {}
    for t in tools:
        raw = [rng.random() + 0.2 for _ in tools]
        s = sum(raw)
        rows[t] = [0.7 * r / s + 0.3 / n for r in raw]
    return rows


def train_from_manifests(
    manifests_dir: str | pathlib.Path,
    sessions: int = 400,
    seed: int = 7,
) -> BaselineStore:
    """Seed one baseline per role from synthetic benign walks over its allowed tools."""
    from detector.manifest_loader import _load_manifests_from_dir

    rng = random.Random(seed)
    store = BaselineStore()
    for role, manifest in _load_manifests_from_dir(pathlib.Path(manifests_dir)).items():
        tools = list(manifest.allowed_tools)
        if not tools:
            continue
        transition = make_transition(tools, rng)
        b = store.ensure(role)
        for _ in range(sessions):
            seq = synthetic_walk(tools, rng, rng.randint(6, 20), transition)
            prev = START
            for t in seq:
                b.update(prev, t)
                prev = t
    return store


def main() -> None:
    parser = argparse.ArgumentParser(description="AIDDS baseline tools")
    sub = parser.add_subparsers(dest="cmd", required=True)
    tr = sub.add_parser("train", help="Seed baselines from the manifests")
    tr.add_argument("--manifests", default="manifests")
    tr.add_argument("--out", default="baselines")
    tr.add_argument("--sessions", type=int, default=400)
    tr.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    store = train_from_manifests(args.manifests, args.sessions, args.seed)
    store.save_dir(args.out)
    for role in store.roles():
        b = store.get(role)
        assert b is not None
        print(f"{role}: {b.n_obs:.0f} observations, tools={sorted(b.tool_distribution())}")
    print(f"Saved to {args.out}/")


if __name__ == "__main__":
    main()
