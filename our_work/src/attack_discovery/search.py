"""Algorithmic Search Engines.

This module implements the core search strategies:
1. Go-Explore: Novelty-driven archiving with random exploration from restored checkpoints.
2. Heuristic Search: Priority-guided exploration maximizing threat scoring.
3. Novelty Search: Exploration focused strictly on path coverage and cell diversity.
"""

from __future__ import annotations

import logging
import random
from abc import ABC, abstractmethod
from typing import Any, Final, Mapping, Sequence

from aicomp_sdk.attacks.contracts import AttackCandidate, AttackRunConfig
from aicomp_sdk.attacks.real_attack_detection import detect_real_attacks
from aicomp_sdk.core.cells import cell_signature
from aicomp_sdk.core.env.api import AttackEnvProtocol
from aicomp_sdk.core.predicates import eval_predicates

from attack_discovery.archive import Archive, Exemplar
from attack_discovery.candidate import FindingMetadata, calculate_raw_predicate_weight, calculate_trace_cell_count
from attack_discovery.mutation import MutationEngine
from attack_discovery.trace import compute_state_hash, compute_scoring_hash
from attack_discovery.utils import Timebox

logger = logging.getLogger(__name__)


class SearchStrategy(ABC):
    """Abstract base class for all search strategies."""

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        self.config: dict[str, Any] = dict(config or {})
        self.mutator: MutationEngine = MutationEngine()

    @abstractmethod
    def search(
        self,
        env: AttackEnvProtocol,
        run_config: AttackRunConfig,
        timebox: Timebox,
    ) -> tuple[list[AttackCandidate], list[FindingMetadata]]:
        """Execute the search algorithm within timebox constraints.

        Returns:
            A tuple of (discovered_candidates, candidate_metadatas).
        """
        pass


class GoExploreSearch(SearchStrategy):
    """Go-Explore search engine.

    Phase 1: Go - Select an promising cell state from the archive and restore its snapshot.
    Phase 2: Explore - Mutate prompts, branch, detect novel states, and archive them.
    """

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        super().__init__(config)
        self.max_turns: int = int(self.config.get("max_turns", 20))
        self.branch_batch: int = int(self.config.get("branch_batch", 12))
        self.causality_bonus: float = float(self.config.get("causality_bonus", 100.0))
        self.high_bonus: float = float(self.config.get("high_bonus", 75.0))
        self.critical_bonus: float = float(self.config.get("critical_bonus", 150.0))

    def search(
        self,
        env: AttackEnvProtocol,
        run_config: AttackRunConfig,
        timebox: Timebox,
    ) -> tuple[list[AttackCandidate], list[FindingMetadata]]:
        rng = random.Random(env.seed)
        archive = Archive()

        findings: list[AttackCandidate] = []
        metadatas: list[FindingMetadata] = []

        # 1. Initialize archive with a seed interaction
        env.reset()
        env.interact("open demo", max_tool_hops=run_config.max_tool_hops)
        snapshot = env.snapshot()
        trace = env.export_trace_dict()
        cell_hash = compute_state_hash(trace)

        seed_exemplar = Exemplar(
            snapshot=snapshot,
            user_messages=list(trace.get("user_messages", [])),
            cell_hash=cell_hash,
            depth=1,
        )
        archive.add(seed_exemplar)

        step = 0
        while not timebox.expired(buffer_s=3.0) and step < run_config.max_steps:
            # Phase 1: Go (Select Cell)
            ex = archive.select_cell(rng)
            ex.visits += 1

            # Phase 2: Explore (Branching)
            for _ in range(self.branch_batch):
                if timebox.expired(buffer_s=3.0):
                    break

                env.restore(ex.snapshot)

                # Generate a mutated prompt
                action_type = rng.random()
                if action_type < 0.35:
                    raw_action = self.mutator.generate_exfil_prompt(rng)
                elif action_type < 0.60:
                    raw_action = self.mutator.generate_deputy_prompt(rng)
                elif action_type < 0.75:
                    raw_action = self.mutator.generate_destructive_prompt(rng)
                else:
                    raw_action = self.mutator.get_random_bank_prompt(rng)

                action = self.mutator.mutate_prompt(raw_action, rng)

                # Interact
                result = env.interact(action, max_tool_hops=run_config.max_tool_hops)

                # Pruning: If the agent refused or didn't trigger any tool usage, prune this branch.
                if result.agent_refused or result.total_tool_events == 0:
                    continue

                trace = env.export_trace_dict()
                preds = eval_predicates(trace)
                cell_hash = compute_state_hash(trace)

                # Check state novelty
                if not archive.contains(cell_hash):
                    # Compute novelty score
                    severity_weight = calculate_raw_predicate_weight(preds)
                    real_attacks = detect_real_attacks(trace.get("tool_events", []))

                    # Compute real attack bonuses
                    attack_bonus = 0.0
                    for attack in real_attacks:
                        attack_bonus += self.causality_bonus
                        impact = attack.get("impact", "LOW")
                        if impact == "CRITICAL":
                            attack_bonus += self.critical_bonus
                        elif impact == "HIGH":
                            attack_bonus += self.high_bonus

                    score = (
                        10.0  # Novelty base
                        + 5.0 * severity_weight
                        + attack_bonus
                        + 0.001 * len(trace.get("tool_events", []))
                    )

                    new_snapshot = env.snapshot()
                    new_exemplar = Exemplar(
                        snapshot=new_snapshot,
                        user_messages=list(trace.get("user_messages", [])),
                        cell_hash=cell_hash,
                        score_hint=score,
                        depth=ex.depth + 1,
                        real_attacks=real_attacks,
                    )
                    archive.add(new_exemplar)

                    # Store finding if predicates are triggered
                    if preds:
                        candidate = AttackCandidate.from_messages(trace.get("user_messages", []))
                        metadata = FindingMetadata(
                            family="goexplore_breach",
                            phase="explore",
                            verified=True,
                            predicate_count=len(preds),
                            predicates=[p.get("predicate", "") for p in preds],
                            raw_predicate_weight=severity_weight,
                            trace_cell_count=calculate_trace_cell_count(trace),
                            chain_len=len(candidate.user_messages),
                            url_count=sum(len(action.split("http")) for action in candidate.user_messages),
                            priority=score,
                        )
                        findings.append(candidate)
                        metadatas.append(metadata)

            step += 1

        return findings, metadatas


class HeuristicSearch(SearchStrategy):
    """Heuristic search engine.

    Explores branches that maximize threat predicate severity and tool execution.
    Prioritizes exploiting promising lines over discovering novel state signatures.
    """

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        super().__init__(config)
        self.branch_batch: int = int(self.config.get("branch_batch", 8))

    def search(
        self,
        env: AttackEnvProtocol,
        run_config: AttackRunConfig,
        timebox: Timebox,
    ) -> tuple[list[AttackCandidate], list[FindingMetadata]]:
        rng = random.Random(env.seed)
        findings: list[AttackCandidate] = []
        metadatas: list[FindingMetadata] = []

        # Keep a list of active paths, each represented by their snapshot and prompt chain.
        # Format: (snapshot, user_messages, score)
        env.reset()
        initial_snap = env.snapshot()
        active_paths = [(initial_snap, [], 0.0)]

        while not timebox.expired(buffer_s=3.0) and active_paths:
            # Sort paths and pick the highest-scoring one (Heuristic priority).
            active_paths.sort(key=lambda x: x[2], reverse=True)
            current_snap, current_msgs, _ = active_paths.pop(0)

            # Restrict depth to avoid excessive chain sizes.
            if len(current_msgs) >= 4:
                continue

            for _ in range(self.branch_batch):
                if timebox.expired(buffer_s=3.0):
                    break

                env.restore(current_snap)
                # Mutate from mutator
                action_type = rng.random()
                if action_type < 0.5:
                    raw_action = self.mutator.generate_exfil_prompt(rng)
                elif action_type < 0.8:
                    raw_action = self.mutator.generate_deputy_prompt(rng)
                else:
                    raw_action = self.mutator.get_random_bank_prompt(rng)

                action = self.mutator.mutate_prompt(raw_action, rng)

                result = env.interact(action, max_tool_hops=run_config.max_tool_hops)
                if result.agent_refused:
                    continue

                trace = env.export_trace_dict()
                preds = eval_predicates(trace)
                severity = calculate_raw_predicate_weight(preds)

                # Heuristic Score: based on predicates and successful tool execution
                path_score = severity * 50.0 + result.successful_tool_calls * 10.0

                new_msgs = current_msgs + [action]
                new_snap = env.snapshot()
                active_paths.append((new_snap, new_msgs, path_score))

                if preds:
                    candidate = AttackCandidate.from_messages(new_msgs)
                    metadata = FindingMetadata(
                        family="heuristic_breach",
                        phase="search",
                        verified=True,
                        predicate_count=len(preds),
                        predicates=[p.get("predicate", "") for p in preds],
                        raw_predicate_weight=severity,
                        trace_cell_count=calculate_trace_cell_count(trace),
                        chain_len=len(new_msgs),
                        url_count=sum(len(msg.split("http")) for msg in new_msgs),
                        priority=path_score,
                    )
                    findings.append(candidate)
                    metadatas.append(metadata)

        return findings, metadatas


class NoveltySearch(SearchStrategy):
    """Novelty Search engine.

    Directly seeks to maximize the number of unique cell signatures visited.
    Does not optimize for predicate scores, but uses cell hashes to discover path coverage.
    """

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        super().__init__(config)
        self.branch_batch: int = int(self.config.get("branch_batch", 8))

    def search(
        self,
        env: AttackEnvProtocol,
        run_config: AttackRunConfig,
        timebox: Timebox,
    ) -> tuple[list[AttackCandidate], list[FindingMetadata]]:
        rng = random.Random(env.seed)
        visited_hashes: set[str] = set()
        findings: list[AttackCandidate] = []
        metadatas: list[FindingMetadata] = []

        env.reset()
        initial_snap = env.snapshot()
        active_paths = [(initial_snap, [], cell_signature([]).get("hash"))]

        while not timebox.expired(buffer_s=3.0) and active_paths:
            # Selection: random selection of active paths to ensure diversity.
            current_snap, current_msgs, _ = active_paths.pop(rng.randint(0, len(active_paths) - 1))

            if len(current_msgs) >= 4:
                continue

            for _ in range(self.branch_batch):
                if timebox.expired(buffer_s=3.0):
                    break

                env.restore(current_snap)
                raw_action = self.mutator.get_random_bank_prompt(rng)
                action = self.mutator.mutate_prompt(raw_action, rng)

                result = env.interact(action, max_tool_hops=run_config.max_tool_hops)
                if result.agent_refused:
                    continue

                trace = env.export_trace_dict()
                cell_hash = compute_state_hash(trace)

                if cell_hash not in visited_hashes:
                    visited_hashes.add(cell_hash)
                    new_msgs = current_msgs + [action]
                    new_snap = env.snapshot()
                    active_paths.append((new_snap, new_msgs, cell_hash))

                    preds = eval_predicates(trace)
                    if preds:
                        candidate = AttackCandidate.from_messages(new_msgs)
                        metadata = FindingMetadata(
                            family="novelty_breach",
                            phase="search",
                            verified=True,
                            predicate_count=len(preds),
                            predicates=[p.get("predicate", "") for p in preds],
                            raw_predicate_weight=calculate_raw_predicate_weight(preds),
                            trace_cell_count=calculate_trace_cell_count(trace),
                            chain_len=len(new_msgs),
                            url_count=sum(len(msg.split("http")) for msg in new_msgs),
                            priority=100.0,
                        )
                        findings.append(candidate)
                        metadatas.append(metadata)

        return findings, metadatas
