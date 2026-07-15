"""Archive Management and State Transposition Table.

This module implements the state archive, mapping unique state hashes to environment snapshots
and metadata (Exemplars). It implements the selection policy that balances exploration and exploitation.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping


@dataclass
class Exemplar:
    """Represents a unique visited state in the search tree.

    Contains the snapshot of the environment and logs of messages and execution depth.
    """

    snapshot: dict[str, Any]  # Serializable state snapshot from env.snapshot()
    user_messages: list[str]  # Replay prompt history
    cell_hash: str            # Unique trace-based state signature hash
    score_hint: float = 0.0   # Diagnostic severity and novelty score
    visits: int = 0           # Count of selection times during search
    depth: int = 0            # Exploration depth (hops/turns)
    real_attacks: list[dict[str, Any]] = field(default_factory=list)


class Archive:
    """Manages the explored state-space, preventing duplicate evaluations (Transposition Table)."""

    def __init__(self) -> None:
        self._cells: Dict[str, Exemplar] = {}

    def __len__(self) -> int:
        return len(self._cells)

    def contains(self, cell_hash: str) -> bool:
        """Check if a state signature is already in the archive."""
        return cell_hash in self._cells

    def add(self, exemplar: Exemplar) -> bool:
        """Add an exemplar to the archive.

        Returns:
            True if it is a new cell, False if it was updated or skipped.
        """
        h = exemplar.cell_hash
        if h in self._cells:
            # Update only if the new path to the same cell is shorter (lower depth)
            if exemplar.depth < self._cells[h].depth:
                self._cells[h] = exemplar
                return True
            return False
        self._cells[h] = exemplar
        return True

    def get(self, cell_hash: str) -> Exemplar | None:
        """Retrieve an exemplar by its signature hash."""
        return self._cells.get(cell_hash)

    def values(self) -> List[Exemplar]:
        """Return all exemplars in the archive."""
        return list(self._cells.values())

    def select_cell(self, rng: random.Random) -> Exemplar:
        """Select a cell from the archive to branch from.

        Implements a selection policy:
        - Favors less-visited cells (exploration).
        - Favors higher-scoring cells (exploitation).
        - Prefers moderate depths.
        """
        candidates = self.values()
        if not candidates:
            raise ValueError("Cannot select from an empty archive.")

        max_visits = max(e.visits for e in candidates) + 1
        max_score = max(e.score_hint for e in candidates) + 1

        weights = []
        for ex in candidates:
            # Favor less-visited cells
            visit_weight = (max_visits - ex.visits) / max_visits
            # Favor higher-scoring cells
            score_weight = (ex.score_hint + 1) / max_score
            # Slight preference for moderate depth
            depth_weight = 1.0 / (1.0 + abs(ex.depth - 3))

            # Combine weights
            weight = visit_weight * 2.0 + score_weight * 1.5 + depth_weight * 0.5
            weights.append(weight)

        total_weight = sum(weights)
        if total_weight <= 0.0:
            return rng.choice(candidates)

        r = rng.uniform(0, total_weight)
        cumsum = 0.0
        for ex, w in zip(candidates, weights):
            cumsum += w
            if r <= cumsum:
                return ex

        return candidates[-1]
