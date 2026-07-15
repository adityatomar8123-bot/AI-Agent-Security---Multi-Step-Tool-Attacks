# Project Roadmap: Attack Discovery Engine

This roadmap outlines the research and development phases planned for the Attack Discovery Engine.

## Phase 1: Foundations & Baselining (Current)
- [x] Establish modular codebase boundaries (`attack_discovery/`).
- [x] Implement the state-space `Archive` (Transposition Table).
- [x] Create a `MutationEngine` (Candidate Generator) for exfiltration, confused deputy, and destructive paths.
- [x] Implement core timing guards (`Timebox`) and priority-based ranking (`CandidateRanker`).

## Phase 2: Evolutionary Algorithms & Go-Explore (Short-Term)
- [ ] **Genetic Mutations**: Implement crossovers and mutation weights based on historical success rates.
- [ ] **Cell Calibration**: Optimize the HSL/RGB representation equivalent in the archive to merge look-alike traces.
- [ ] **Adaptive Branching**: Adjust branch batch sizing dynamically based on remaining timebox budget.

## Phase 3: Monte Carlo Tree Search (MCTS) (Medium-Term)
- [ ] **State Tree Modeling**: Represent the attack search space as an explicit search tree instead of a flat archive.
- [ ] **UCT Selection**: Implement the Upper Confidence Bound applied to Trees (UCT) formula:
  $$\text{UCT} = \frac{W_i}{N_i} + c \sqrt{\frac{\ln N_p}{N_i}}$$
- [ ] **Rollout Simulation**: Run lightweight rollout simulations using fast heuristic-driven model agents.

## Phase 4: Stockfish-Inspired Tree Optimization (Long-Term)
- [ ] **Iterative Deepening**: Systematically search to depth $N$, verify findings, and then restart with depth $N+1$, reusing the Transposition Table.
- [ ] **Alpha-Beta Pruning**: Cut off search branches where the agent consistently refuses or fails to call any tools for $K$ consecutive steps.
- [ ] **History Heuristics**: Remember which mutation operators historically caused successful state transitions and try those first (Move Ordering).

## Phase 5: LLM-Assisted Generation
- [ ] **LLM-in-the-Loop Fuzzing**: Use a local fast model (e.g. Gemma 2B GGUF) to generate context-specific prompt mutations based on the current tool execution logs in the trace, moving beyond rule-based templates.
