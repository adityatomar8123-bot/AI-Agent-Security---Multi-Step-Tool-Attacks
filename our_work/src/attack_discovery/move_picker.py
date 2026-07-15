"""Move Picker — Move Ordering (ported from Stockfish movepick.cpp).

In Stockfish, MovePicker orders moves to maximize alpha-beta pruning:
1. TT move (best known move)
2. Good captures (winning material)
3. Killer moves (caused beta cutoffs in siblings)
4. Quiet moves (ordered by history heuristic)

Here, we order candidate prompts to try the most promising ones first:
1. TT move (best prompt from transposition table)
2. Known scoring prompts (triggered predicates before)
3. High-priority prompts (direct tool triggers)
4. Exploration prompts (web opens, searches)

Stockfish Mapping:
    movepick.cpp:MovePicker  → MovePicker
    movepick.cpp:Stages      → PickStage
    history.h:ButterflyHistory → PromptHistory
"""

from __future__ import annotations

import enum
from typing import Final

from attack_discovery.move_generator import CandidateMove
from attack_discovery.transposition_table import TranspositionTable


class PickStage(enum.IntEnum):
    """Move picking stages (from Stockfish movepick.cpp stages)."""
    TT_MOVE = 0           # Best move from transposition table
    KNOWN_SCORING = 1     # Previously scored moves
    HIGH_PRIORITY = 2     # Direct tool triggers
    MULTI_STEP = 3        # Multi-step chains
    EXPLORATION = 4       # Web opens, searches
    FUZZING = 5           # URL/payload fuzzing
    DONE = 6


class PromptHistory:
    """Track which prompt patterns historically score well.

    Stockfish equivalent: ButterflyHistory (history.h).
    Maps prompt pattern → cumulative score bonus.
    """

    def __init__(self) -> None:
        self._history: dict[str, float] = {}

    def update(self, prompt_key: str, bonus: float) -> None:
        """Update history score for a prompt pattern."""
        current = self._history.get(prompt_key, 0.0)
        # Stockfish gravity: bonus decays toward 0 as it grows
        self._history[prompt_key] = current + bonus - current * abs(bonus) / 16384.0

    def score(self, prompt_key: str) -> float:
        """Get history score for a prompt pattern."""
        return self._history.get(prompt_key, 0.0)

    def clear(self) -> None:
        self._history.clear()


class MovePicker:
    """Order candidate prompts for maximum search efficiency.

    Stockfish equivalent: movepick.cpp:MovePicker
    Yields candidates in priority order, interleaving TT moves,
    known-good patterns, and exploration.
    """

    def __init__(
        self,
        candidates: list[CandidateMove],
        *,
        tt: TranspositionTable | None = None,
        history: PromptHistory | None = None,
    ) -> None:
        self._candidates = candidates
        self._tt = tt
        self._history = history
        self._stage = PickStage.TT_MOVE
        self._yielded_keys: set[str] = set()

    def pick_ordered(self) -> list[CandidateMove]:
        """Return all candidates in optimized order.

        Stockfish picks moves one at a time; we batch for simplicity.
        """
        ordered: list[CandidateMove] = []
        seen: set[str] = set()

        # Stage 1: TT moves (from transposition table)
        if self._tt is not None:
            tt_entries = self._tt.best_entries(20)
            for entry in tt_entries:
                if entry.best_prompt:
                    for c in self._candidates:
                        if c.key not in seen and entry.best_prompt in c.user_messages:
                            ordered.append(c)
                            seen.add(c.key)

        # Stage 2: Known scoring moves (from history heuristic)
        if self._history is not None:
            scored = [
                (c, self._history.score(c.key))
                for c in self._candidates
                if c.key not in seen
            ]
            scored.sort(key=lambda x: x[1], reverse=True)
            for c, h_score in scored:
                if h_score > 0 and c.key not in seen:
                    ordered.append(c)
                    seen.add(c.key)

        # Stage 3: Remaining by priority
        remaining = [c for c in self._candidates if c.key not in seen]
        remaining.sort(key=lambda c: c.priority, reverse=True)
        ordered.extend(remaining)

        return ordered
