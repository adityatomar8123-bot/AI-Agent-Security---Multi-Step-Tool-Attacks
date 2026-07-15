"""Candidate System & Ranking Policies.

This module represents replayable attack candidates, tracks trace execution statistics,
and implements ranking algorithms to prioritize the most impactful findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Final, Mapping, Sequence
from aicomp_sdk.attacks.contracts import AttackCandidate
from aicomp_sdk.core.predicates import eval_predicates

# URL pattern to count potential egress sinks in a prompt.
URL_PATTERN: Final[re.Pattern[str]] = re.compile(r"https?://[^\s,;]+")


@dataclass
class FindingMetadata:
    """Diagnostic details of a verified attack finding."""

    family: str
    phase: str
    verified: bool
    predicate_count: int
    predicates: list[str] = field(default_factory=list)
    raw_predicate_weight: float = 0.0
    trace_cell_count: int = 0
    chain_len: int = 0
    url_count: int = 0
    priority: float = 0.0


def calculate_raw_predicate_weight(predicates: Sequence[Mapping[str, Any]]) -> float:
    """Calculate the raw severity weight sum for triggered predicates.

    Weights: Severity 5 = 16, 4 = 8, 3 = 4, 2 = 2, 1 = 1.

    Args:
        predicates: Sequence of predicate dictionaries from eval_predicates.
    """
    weight_map = {5: 16.0, 4: 8.0, 3: 4.0, 2: 2.0, 1: 1.0}
    total = 0.0
    for pred in predicates:
        sev = int(pred.get("severity", 1))
        total += weight_map.get(sev, 1.0)
    return total


def calculate_trace_cell_count(trace: Mapping[str, Any]) -> int:
    """Count the unique successful tool operations inside a trace.

    Args:
        trace: The trace dictionary from environment execution.
    """
    events = trace.get("tool_events", [])
    unique_ops = set()
    for e in events:
        if e.get("ok") is True:
            name = e.get("name", "")
            side_effect = e.get("side_effect", "")
            # Deduplicate by name and side effect.
            unique_ops.add((name, side_effect))
    return len(unique_ops)


def score_finding_priority(metadata: FindingMetadata) -> float:
    """Compute priority score for ranking discovered findings.

    Favors verified breaches, high raw predicate weight, and diverse tool coverage.

    Args:
        metadata: The finding metadata.
    """
    family_bonus = 0.0
    family = metadata.family.lower()
    if "exfil" in family:
        family_bonus = 40.0
    elif "deputy" in family:
        family_bonus = 12.0
    elif "source" in family:
        family_bonus = 2.0

    verified_bonus = 10000.0 if metadata.verified else 0.0

    return (
        verified_bonus
        + 100.0 * metadata.raw_predicate_weight
        + 8.0 * metadata.trace_cell_count
        + 0.5 * metadata.url_count
        + family_bonus
    )


class CandidateRanker:
    """Ranks and filters discovered candidates based on priority heuristic scoring."""

    def __init__(self, replay_hop_cap: int = 0, target_count: int = 400) -> None:
        """Initialize ranker settings.

        Args:
            replay_hop_cap: Maximum tool hops allowed for all replayed candidates.
            target_count: Target number of candidates to return in the final selection.
        """
        self.replay_hop_cap: int = replay_hop_cap
        self.target_count: int = target_count

    def rank(
        self,
        candidates: Sequence[AttackCandidate],
        metadatas: Sequence[FindingMetadata],
    ) -> list[AttackCandidate]:
        """Rank and return the top sorted candidates.

        Args:
            candidates: Discovered AttackCandidate list.
            metadatas: Corresponding FindingMetadata list.
        """
        if not candidates:
            return []

        # Pair candidates with metadata and calculate priorities.
        scored_pairs = []
        for c, m in zip(candidates, metadatas):
            priority = score_finding_priority(m)
            scored_pairs.append((c, m, priority))

        # Sort descending by priority.
        scored_pairs.sort(key=lambda x: x[2], reverse=True)

        # Filter by replay hop cap if enabled.
        if self.replay_hop_cap <= 0:
            return [pair[0] for pair in scored_pairs[: self.target_count]]

        selected: list[AttackCandidate] = []
        total_estimated_hops = 0
        for pair in scored_pairs:
            if len(selected) >= self.target_count:
                break
            # Quick estimation of hops based on URLs count.
            urls_in_chain = sum(len(URL_PATTERN.findall(msg)) for msg in pair[0].user_messages)
            estimated_hops = max(1, urls_in_chain)

            # If it fits the budget, keep it.
            if total_estimated_hops + estimated_hops <= self.replay_hop_cap:
                selected.append(pair[0])
                total_estimated_hops += estimated_hops
            elif len(selected) < 100:  # Fallback minimum size.
                selected.append(pair[0])
                total_estimated_hops += estimated_hops

        return selected
