"""Replay Validation & Verification Harness.

This module validates discovered attack candidates by replaying them on a reset environment
and evaluating if the target predicates are successfully triggered.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping, Sequence
from aicomp_sdk.attacks.contracts import AttackCandidate, AttackRunConfig
from aicomp_sdk.core.env.api import AttackEnvProtocol
from aicomp_sdk.core.predicates import eval_predicates

logger = logging.getLogger(__name__)


class ReplayHarness:
    """Harness to run candidates against the environment and evaluate outputs."""

    @staticmethod
    def replay_candidate(
        env: AttackEnvProtocol,
        candidate: AttackCandidate,
        max_tool_hops: int = AttackRunConfig.max_tool_hops,
    ) -> dict[str, Any] | None:
        """Replay candidate messages on a reset environment and return the trace.

        Args:
            env: The environment proxy to interact with.
            candidate: The attack candidate chain to replay.
            max_tool_hops: Hops limit per message.

        Returns:
            The exported trace dictionary, or None if execution failed.
        """
        try:
            env.reset()
            for msg in candidate.user_messages:
                env.interact(msg, max_tool_hops=max_tool_hops)
            return env.export_trace_dict()
        except Exception as e:
            logger.error("Failed to replay candidate %s: %s", candidate.user_messages, e)
            return None

    @staticmethod
    def verify_candidate(
        env: AttackEnvProtocol,
        candidate: AttackCandidate,
        max_tool_hops: int = AttackRunConfig.max_tool_hops,
    ) -> list[dict[str, Any]]:
        """Replay and return triggered predicates.

        Args:
            env: The environment proxy to interact with.
            candidate: The attack candidate to verify.
            max_tool_hops: Hops limit.

        Returns:
            List of triggered predicate dictionaries (empty if none).
        """
        trace = ReplayHarness.replay_candidate(env, candidate, max_tool_hops)
        if trace is None:
            return []
        return eval_predicates(trace)
