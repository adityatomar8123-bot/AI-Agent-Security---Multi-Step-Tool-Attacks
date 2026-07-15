# Go-Explore Algorithmic Specification

This document details the two-phase Go-Explore search loop implemented in `attack_discovery/search.py`.

## Phase 1: Go (State Restoration)

In complex environments, taking random actions from the start of an episode rarely reaches deep states. The agent is highly likely to fail or get blocked early, creating a "bottleneck" in the state space.

Go-Explore solves this by separating exploration from retrieval:
1.  **Retrieve state**: Select a target cell $c$ from the `Archive` using the weighted selection policy.
2.  **Restore environment**: Call `env.restore(snapshot)` to physically set the sandbox filesystem, mailbox, and history to the target cell state.

This is a critical advantage: it bypasses the need to replay all previous actions from scratch, avoiding intermediate failures and saving time.

## Phase 2: Explore (Branching & Archiving)

Once the environment state is restored:
1.  **Apply Action**: Generate a mutated prompt from the template banks.
2.  **Step**: Call `env.interact(prompt)`.
3.  **Evaluate**: Extract the trace and calculate the state signature hash:
    *   If the hash is already in the `Archive`, update it only if the new path to this state is shorter.
    *   If the hash is new, mark the cell as **novel**, snapshot the new environment state, and add it to the `Archive` as a new exemplar.
    *   If predicates (breaches) are triggered, save the prompt chain as a successful attack candidate.
4.  **Repeat**: Execute $K$ branch attempts (`branch_batch`) before selecting a new target cell from the archive.
