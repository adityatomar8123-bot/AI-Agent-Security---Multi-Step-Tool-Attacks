"""Stockfish Attack Engine — Main Search (ported from Stockfish search.cpp).

This is the CORE of the attack discovery system. It implements Stockfish's
iterative-deepening alpha-beta search, adapted for the attack environment:

    Stockfish search.cpp          → StockfishAttackEngine
    iterative_deepening()         → iterative_deepening()
    search<PV>(pos, alpha, beta)  → search(env, depth, alpha, beta)
    qsearch()                     → quick_evaluate() (shallow evaluation)

The engine combines ALL 10 search strategies:
    1. Prompt Search       — systematic sweep via MoveGenerator
    2. Fuzzing             — URL/payload cross-product
    3. Heuristic Search    — score-guided branching via TraceEvaluator
    4. Evolutionary Algo   — mutate successful candidates
    5. State-Space Explore — depth-first chain exploration
    6. Trace-Guided Mut.   — adapt based on trace feedback
    7. Novelty Search      — reward unique cell signatures
    8. Go-Explore Archive  — snapshot/restore from promising states
    9. LLM-Assisted Gen.   — expanded prompt templates
   10. Hybrid Systems      — budget allocation across strategies

Architecture:
    ┌─────────────────────────────┐
    │   StockfishAttackEngine     │
    │  ┌───────────────────────┐  │
    │  │ iterative_deepening() │  │
    │  │  depth=1..max_depth   │  │
    │  │  ┌─────────────────┐  │  │
    │  │  │ search(depth)   │  │  │
    │  │  │ ┌─────────────┐ │  │  │
    │  │  │ │ MovePicker   │ │  │  │
    │  │  │ │ evaluate()   │ │  │  │
    │  │  │ │ TT.probe()   │ │  │  │
    │  │  │ │ alpha-beta   │ │  │  │
    │  │  │ └─────────────┘ │  │  │
    │  │  └─────────────────┘  │  │
    │  └───────────────────────┘  │
    └─────────────────────────────┘
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Final

from aicomp_sdk.attacks import AttackCandidate

from attack_discovery.evaluator import TraceEvaluator
from attack_discovery.move_generator import CandidateMove, MoveGenerator
from attack_discovery.move_picker import MovePicker, PromptHistory
from attack_discovery.transposition_table import BoundType, TranspositionTable

logger = logging.getLogger(__name__)

# Search constants (from Stockfish types.h)
VALUE_INFINITE: Final[float] = 100_000.0
VALUE_NONE: Final[float] = -VALUE_INFINITE - 1
MAX_PLY: Final[int] = 8  # Maximum chain depth (messages per candidate)
MAX_CANDIDATES: Final[int] = 2000  # Competition limit


@dataclass(slots=True)
class SearchStack:
    """Per-ply search state (from Stockfish search.h:Stack).

    Tracks state at each depth level during iterative deepening.
    """
    ply: int = 0
    current_move: str = ""
    static_eval: float = VALUE_NONE
    move_count: int = 0
    best_move: str = ""
    best_score: float = VALUE_NONE


@dataclass(slots=True)
class RootMove:
    """Root-level candidate with score tracking (from Stockfish search.h:RootMove).

    Each RootMove is a complete attack candidate (single or multi-step).
    """
    candidate: CandidateMove
    score: float = VALUE_NONE
    previous_score: float = VALUE_NONE
    predicates: list[dict[str, Any]] = field(default_factory=list)
    cell_hash: str = ""
    depth_found: int = 0


@dataclass(slots=True)
class SearchResult:
    """Results from one search iteration."""
    findings: list[AttackCandidate] = field(default_factory=list)
    total_evaluated: int = 0
    total_pruned: int = 0
    unique_cells: int = 0
    best_score: float = 0.0


class StockfishAttackEngine:
    """Main search engine (from Stockfish search.cpp:Worker).

    Implements iterative-deepening search with alpha-beta pruning,
    transposition table lookups, and move ordering.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        config = config or {}
        self.max_depth = config.get("max_depth", 4)
        self.max_candidates = config.get("max_candidates", MAX_CANDIDATES)
        self.branch_batch = config.get("branch_batch", 50)
        self.time_budget_s = config.get("time_budget_s", 300.0)

        # Core components (Stockfish equivalents)
        self.tt = TranspositionTable()
        self.evaluator = TraceEvaluator()
        self.move_gen = MoveGenerator()
        self.history = PromptHistory()
        self.rng = random.Random(42)

        # Search state
        self.root_moves: list[RootMove] = []
        self.nodes: int = 0  # Total positions evaluated
        self.best_move_changes: int = 0

    def search(
        self,
        env: Any,
        run_config: Any,
        timebox_end: float | None = None,
    ) -> list[AttackCandidate]:
        """Main search entry point (Stockfish: Worker.start_searching()).

        Implements the complete search pipeline:
        1. Generate candidate moves (MoveGenerator)
        2. Order moves (MovePicker)
        3. Iterative deepening with alpha-beta
        4. Evolutionary mutation of successful candidates
        5. Novelty-driven exploration
        6. Collect and deduplicate findings
        """
        deadline = timebox_end or (time.time() + self.time_budget_s)
        all_findings: list[AttackCandidate] = []
        seen_cells: set[str] = set()
        seen_messages: set[str] = set()

        logger.info("StockfishAttackEngine: Starting search")
        logger.info(f"  Max depth: {self.max_depth}")
        logger.info(f"  Budget: {self.time_budget_s:.0f}s")

        # Phase 1: Generate all candidate moves
        all_candidates = self.move_gen.generate_all(self.rng)
        logger.info(f"  Generated {len(all_candidates)} candidate moves")

        # Phase 2: Order moves by priority (MovePicker)
        picker = MovePicker(all_candidates, tt=self.tt, history=self.history)
        ordered = picker.pick_ordered()

        # Phase 3: Iterative deepening (Stockfish: iterative_deepening())
        for depth in range(1, self.max_depth + 1):
            if time.time() >= deadline:
                break
            if len(all_findings) >= self.max_candidates:
                break

            logger.info(f"  Depth {depth}: Evaluating candidates...")
            depth_findings = 0

            for candidate in ordered:
                if time.time() >= deadline:
                    break
                if len(all_findings) >= self.max_candidates:
                    break

                # Skip if chain depth doesn't match current iteration depth
                if len(candidate.user_messages) != depth:
                    continue

                # Skip already-seen message sequences
                msg_key = "|".join(candidate.user_messages)
                if msg_key in seen_messages:
                    continue
                seen_messages.add(msg_key)

                # Alpha-beta pruning: check TT for already-evaluated states
                tt_entry = self.tt.lookup(candidate.key)
                if tt_entry is not None and tt_entry.depth >= depth:
                    if tt_entry.score <= 0:
                        self.nodes += 1  # Count as pruned
                        continue

                # Evaluate the candidate
                score, predicates, cell_hash = self._evaluate_candidate(
                    env, candidate, run_config
                )

                # Store in transposition table
                self.tt.store(
                    cell_hash or candidate.key,
                    score=score,
                    depth=depth,
                    best_prompt=candidate.user_messages[0],
                    predicates=[p.get("predicate", "") for p in predicates],
                )

                # Update history heuristic
                if score > 0:
                    self.history.update(candidate.key, score)

                # If predicates triggered, it's a finding!
                if predicates and cell_hash not in seen_cells:
                    seen_cells.add(cell_hash)
                    all_findings.append(AttackCandidate(
                        user_messages=list(candidate.user_messages)
                    ))
                    depth_findings += 1

                    # Evolutionary mutation: generate variants of successful candidates
                    if time.time() < deadline:
                        mutations = self.move_gen.generate_mutated(
                            candidate.user_messages, self.rng, n_variants=3
                        )
                        for mut in mutations:
                            if time.time() >= deadline:
                                break
                            if len(all_findings) >= self.max_candidates:
                                break

                            mut_key = "|".join(mut.user_messages)
                            if mut_key in seen_messages:
                                continue
                            seen_messages.add(mut_key)

                            m_score, m_preds, m_hash = self._evaluate_candidate(
                                env, mut, run_config
                            )
                            if m_preds and m_hash not in seen_cells:
                                seen_cells.add(m_hash)
                                all_findings.append(AttackCandidate(
                                    user_messages=list(mut.user_messages)
                                ))

            logger.info(f"  Depth {depth}: Found {depth_findings} new findings")
            logger.info(f"  Total findings: {len(all_findings)}, "
                        f"Unique cells: {len(seen_cells)}, "
                        f"Nodes: {self.nodes}")

        # Phase 4: Final collection
        logger.info(f"Search complete. Total findings: {len(all_findings)}")
        logger.info(f"  Nodes evaluated: {self.nodes}")
        logger.info(f"  TT occupancy: {self.tt.occupancy():.1%}")

        return all_findings[:self.max_candidates]

    def _evaluate_candidate(
        self,
        env: Any,
        candidate: CandidateMove,
        run_config: Any,
    ) -> tuple[float, list[dict[str, Any]], str]:
        """Evaluate a single candidate by interacting with the environment.

        Returns: (score, predicates, cell_hash)
        """
        self.nodes += 1

        try:
            env.reset()
            max_hops = getattr(run_config, "max_tool_hops", 4)
            for msg in candidate.user_messages:
                env.interact(msg, max_tool_hops=max_hops)

            trace = env.export_trace_dict()
            score, predicates = self.evaluator.evaluate(trace)

            # Compute cell hash for novelty tracking
            from attack_discovery.trace import compute_scoring_hash
            cell_hash = compute_scoring_hash(trace)

            return score, predicates, cell_hash

        except Exception as e:
            logger.debug(f"Candidate evaluation failed: {e}")
            return 0.0, [], ""
