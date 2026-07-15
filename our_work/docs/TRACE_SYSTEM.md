# Trace System and Signature Analyzer

This document details how environment traces are parsed and compiled into compact signatures to identify states in the search space.

## State Representation and Equivalence Classes

An agent interaction trace can be verbose, containing exact timestamps, standard output logs, and session IDs. If we used raw traces as state keys, every single run would be classified as "novel," leading to state-space explosion.

To prevent this, the `trace.py` module aggregates the trace into a structured `CellSignature` containing only critical behavioral features:
1.  **Tool n-gram Sequence**: The last $N$ called tool names (e.g. `['fs.read', 'http.post']`).
2.  **Side Effects**: The scopes of the called tools (e.g. `['READ', 'SHARE']`).
3.  **Outcomes**: Whether the last 3 tool calls succeeded (`ok`) or errored (`err`).
4.  **Egress Sinks**: Number of successfully completed network exfiltration posts.
5.  **Sensitive File Access**: A boolean flag checking if `secret.txt` was read.
6.  **Tool Arguments**: Normalized sandbox paths and destination domains.
7.  **Guardrail Blocks**: Blocks triggered by the safety guardrail.
8.  **User Intent**: Hashed representation of the last 3 user messages.

## Signature Construction

We serialize the signature values into a unified string separated by markers and hash it using SHA-256:

$$\text{Signature String} = \text{tools} \mid \text{effects} \mid \text{outcomes} \mid \text{secret\_read} \mid \text{egress\_count} \mid \text{args} \mid \text{outputs} \mid \text{intent} \mid \text{blocks}$$

$$\text{Cell Hash} = \text{SHA256}(\text{Signature String})[:16]$$

This hash partitions the continuous state-space into discrete equivalence classes (cells). 

## Score Cell vs State Cell

Our engine maintains two distinct cell signatures:
*   **State Cell Signature**: Includes user intent hashes. This ensures that when the user inputs different prompts, they create different cells even if the agent produces the same tool sequence. This is optimized for Phase 2 exploration (Go-Explore).
*   **Score Cell Signature**: Excludes user intent and egress details, focusing purely on tool call sequences. This matches the competition evaluator's scoring metric, preventing double-scoring of structurally identical attacks.
