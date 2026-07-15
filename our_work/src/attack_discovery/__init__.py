"""Attack Discovery Engine package.

Exposes algorithmic search strategies, archive transposition tables, trace analyzers,
candidate ranking policies, and the Stockfish-inspired search engine for
Multi-Step Tool Attacks.
"""

from __future__ import annotations

from attack_discovery.archive import Archive, Exemplar
from attack_discovery.candidate import CandidateRanker, FindingMetadata, score_finding_priority
from attack_discovery.evaluator import TraceEvaluator
from attack_discovery.move_generator import CandidateMove, MoveGenerator
from attack_discovery.move_picker import MovePicker, PromptHistory
from attack_discovery.mutation import MutationEngine
from attack_discovery.replay import ReplayHarness
from attack_discovery.search import GoExploreSearch, HeuristicSearch, NoveltySearch, SearchStrategy
from attack_discovery.stockfish_engine import StockfishAttackEngine
from attack_discovery.trace import compute_scoring_hash, compute_state_hash
from attack_discovery.transposition_table import TranspositionTable
from attack_discovery.utils import Timebox, setup_logger

__all__ = [
    "Archive",
    "Exemplar",
    "CandidateRanker",
    "FindingMetadata",
    "score_finding_priority",
    "TraceEvaluator",
    "MoveGenerator",
    "CandidateMove",
    "MovePicker",
    "PromptHistory",
    "MutationEngine",
    "ReplayHarness",
    "GoExploreSearch",
    "HeuristicSearch",
    "NoveltySearch",
    "SearchStrategy",
    "StockfishAttackEngine",
    "TranspositionTable",
    "compute_scoring_hash",
    "compute_state_hash",
    "Timebox",
    "setup_logger",
]
