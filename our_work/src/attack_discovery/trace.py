"""Trace System and State Representation.

This module analyzes execution traces from the agent environment, extracts tool calls
and egress outputs, and computes signature hashes to identify unique states in the state space.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence
from aicomp_sdk.core.cells import cell_signature, CellSignature


def extract_trace_events(trace_dict: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract tool events and egress events from a trace dictionary.

    Args:
        trace_dict: The exported environment trace.

    Returns:
        A tuple of (tool_events, egress_events).
    """
    tool_events = list(trace_dict.get("tool_events", []))
    egress_events = list(trace_dict.get("egress", []))
    return tool_events, egress_events


def compute_state_hash(
    trace_dict: Mapping[str, Any],
    use_intent: bool = True,
    use_args: bool = True,
    use_outputs: bool = True,
    args_count: int = 5,
) -> str:
    """Compute the short hash of the environment state for Go-Explore.

    Uses `cell_signature` from the SDK to map execution paths to CellSignature
    dictionaries and extracts the uniquely identifying hash.

    Args:
        trace_dict: The trace dictionary from the env.
        use_intent: Whether to include user messages in the state signature.
        use_args: Whether to include tool arguments in the signature.
        use_outputs: Whether to include output samples in the signature.
        args_count: Number of recent tool arguments to track.

    Returns:
        A hex string hash identifying the cell state.
    """
    tool_events, egress_data = extract_trace_events(trace_dict)
    user_messages = list(trace_dict.get("user_messages", [])) if use_intent else []

    sig: CellSignature = cell_signature(
        tool_events,
        egress_data=egress_data,
        user_messages=user_messages,
        use_args=use_args,
        use_outputs=use_outputs,
        args_count=args_count,
    )
    return str(sig["hash"])


def compute_scoring_hash(trace_dict: Mapping[str, Any]) -> str:
    """Compute the official score cell hash, matching the evaluator's rule.

    The evaluator computes score cell signatures using ONLY tool_events,
    which collapses different prompt chains that produce identical tool sequences.

    Args:
        trace_dict: The trace dictionary from the env.

    Returns:
        A hex string hash for scoring evaluation.
    """
    tool_events = list(trace_dict.get("tool_events", []))
    sig: CellSignature = cell_signature(tool_events)
    return str(sig["hash"])
