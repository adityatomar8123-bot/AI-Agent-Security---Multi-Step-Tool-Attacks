"""Transposition Table — State Cache (ported from Stockfish tt.cpp).

In Stockfish, the transposition table caches previously evaluated positions
so the engine never re-evaluates the same position twice. Here, we cache
cell_hash → TTEntry(score, depth, best_move, bound_type) to avoid redundant
environment interactions.

Stockfish Mapping:
    tt.cpp:TranspositionTable → TranspositionTable
    tt.cpp:TTEntry             → TTEntry
    tt.cpp:Bound               → BoundType (EXACT, LOWER, UPPER)
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Final


class BoundType(enum.Enum):
    """Stockfish Bound enum: EXACT, LOWER_BOUND, UPPER_BOUND."""
    EXACT = "exact"
    LOWER = "lower"
    UPPER = "upper"


@dataclass(slots=True)
class TTEntry:
    """Single transposition table entry.

    Stockfish stores: key, move, value, eval, depth, bound, generation.
    We store: cell_hash, best_prompt, score, depth, bound, predicates.
    """
    cell_hash: str
    best_prompt: str | None = None
    score: float = 0.0
    depth: int = 0
    bound: BoundType = BoundType.EXACT
    predicates: list[str] = field(default_factory=list)
    visit_count: int = 0


class TranspositionTable:
    """Cell-hash keyed state cache (from Stockfish tt.cpp).

    Prevents redundant environment interactions by caching:
    - Previously evaluated cell states
    - The best prompt that led to a high-scoring state
    - The score and depth at which the state was evaluated

    Stockfish tt.cpp equivalents:
        probe()  → lookup()
        store()  → store()
        clear()  → clear()
        hashfull → occupancy()
    """

    MAX_SIZE: Final[int] = 100_000

    def __init__(self, max_size: int = MAX_SIZE) -> None:
        self._table: dict[str, TTEntry] = {}
        self._max_size = max_size

    def lookup(self, cell_hash: str) -> TTEntry | None:
        """Probe the table for a cached entry (Stockfish: tt.probe())."""
        entry = self._table.get(cell_hash)
        if entry is not None:
            entry.visit_count += 1
        return entry

    def store(
        self,
        cell_hash: str,
        *,
        score: float,
        depth: int,
        best_prompt: str | None = None,
        bound: BoundType = BoundType.EXACT,
        predicates: list[str] | None = None,
    ) -> None:
        """Store or update an entry (Stockfish: tt.store()).

        Replace-if-deeper strategy: only overwrite if new depth >= old depth.
        """
        existing = self._table.get(cell_hash)
        if existing is not None:
            # Stockfish replacement scheme: prefer deeper searches
            if depth < existing.depth and score <= existing.score:
                return
            existing.score = max(existing.score, score)
            existing.depth = max(existing.depth, depth)
            if best_prompt is not None:
                existing.best_prompt = best_prompt
            existing.bound = bound
            if predicates:
                existing.predicates = predicates
        else:
            if len(self._table) >= self._max_size:
                # Evict lowest-score entry (Stockfish uses generation-based eviction)
                worst_key = min(self._table, key=lambda k: self._table[k].score)
                del self._table[worst_key]
            self._table[cell_hash] = TTEntry(
                cell_hash=cell_hash,
                best_prompt=best_prompt,
                score=score,
                depth=depth,
                bound=bound,
                predicates=predicates or [],
            )

    def contains(self, cell_hash: str) -> bool:
        """Check if a state has been visited."""
        return cell_hash in self._table

    def clear(self) -> None:
        """Reset the table (Stockfish: tt.clear())."""
        self._table.clear()

    def occupancy(self) -> float:
        """Return table fill ratio 0.0-1.0 (Stockfish: hashfull)."""
        return len(self._table) / max(1, self._max_size)

    def best_entries(self, n: int = 10) -> list[TTEntry]:
        """Return top-N entries by score."""
        sorted_entries = sorted(self._table.values(), key=lambda e: e.score, reverse=True)
        return sorted_entries[:n]

    def __len__(self) -> int:
        return len(self._table)
