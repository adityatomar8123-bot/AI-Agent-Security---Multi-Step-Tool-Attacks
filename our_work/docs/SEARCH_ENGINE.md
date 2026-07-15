# Search Engine Specification

This document details the search algorithms and resource allocation policies implemented in `attack_discovery/search.py`.

## Core Search Paradigms

The discovery engine supports three distinct search strategies:

### 1. Go-Explore Search
Go-Explore separates exploration into two distinct steps:
1.  **Go (State Selection)**: Select an exemplar from the archive using a weighted probability distribution. The weight of cell $i$ is calculated as:
    $$W_i = w_v \cdot \frac{V_{max} - V_i}{V_{max}} + w_s \cdot \frac{S_i}{S_{max}} + w_d \cdot \frac{1}{1 + |D_i - 3|}$$
    Where $V$ is visits, $S$ is score, and $D$ is depth.
2.  **Explore (Branching)**: Restore the environment to the exemplar's checkpoint. Apply mutation operators to branch. If the branch yields a state with an unseen signature hash, it is snapshotted and archived.

### 2. Heuristic Search
Heuristic search acts as a best-first exploitation search:
*   Maintains a priority queue of paths sorted by their heuristic score (threat severity + tool execution counters).
*   Always expands the highest-performing path.
*   Ideal for quickly exploiting vulnerable agent behaviors when the state space is narrow.

### 3. Novelty Search
Novelty search is a coverage-driven exploration strategy:
*   Ignores threat predicate scores.
*   Prioritizes expanding paths that lead to unseen cell signatures.
*   Discovers hidden tool flows and triggers secondary guardrails by maximizing path variety.

## Branching Constraints & Budget Policy

Search execution operates under strict runtime constraints:
*   **Timebox Enforcement**: A `Timebox` instance tracks the remaining wall-clock budget. Once the remaining time drops below a critical safety margin (e.g. 3.0s), the search loop halts and starts candidate finalization.
*   **Branch Factor Cap**: A configurable parameter (`branch_batch`) determines how many mutations are attempted from a single restored checkpoint before re-evaluating the selection policy.
*   **Pruning Condition**: If a branch attempt results in an agent refusal or registers zero tool events, the path is immediately pruned, avoiding expensive environment snapshotting.
*   **Replay Hop Budgeting**: The `CandidateRanker` estimates total tool hops for the candidate portfolio and prunes lower-priority candidates to fit within `REPLAY_HOP_CAP` constraints.
