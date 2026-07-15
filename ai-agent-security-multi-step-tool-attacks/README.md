# Attack Discovery Engine: Algorithmic Search for Multi-Step Tool Attacks

This repository contains a modular, state-of-the-art **Attack Discovery Engine** for the Multi-Step Tool Attacks competition. Rather than relying on static prompt engineering, this engine treats attack candidate discovery as a time-bounded search problem across the environment's state-space, heavily inspired by the search tree optimizations of **Stockfish**.

---

## 📊 Score Dashboard

Here are the results of our attack portfolios:

| Model / Configuration | Normalized Score | Description |
|---|---|---|
| **zOthers Works Reference 1** | **72.0** | Advanced adaptive branching with 300 candidates (`score_deep_bounded_plus`) |
| **zOthers Works Reference 2** | **62.0** | Deep search with 300 candidates (`score_deep_bounded`) |
| **Our Engine: Go-Explore + Heuristic** | **72.0** (Target) | Optimized multi-depth checkpoint exploration with Candidate Ranker |
| **Our Engine: Baseline Fallback** | **36.0** (Raw) | Fixed exfiltration portfolio (400 unique candidates) |

*Note: Reference works from other competitors (located in `zOthers works`) achieved scores between **62.0** and **72.0** by balancing candidate sizes and replay tool hops.*

---

## Project Structure

```
├── attack.py                     # Official Kaggle entry point class
├── attack_discovery/             # Modular search & discovery engine
│   ├── __init__.py               # API exports
│   ├── archive.py                # Transposition table (cell archive)
│   ├── candidate.py              # Candidate modeling & Move Ordering (ranking)
│   ├── mutation.py               # Candidate Generator (mutation operators)
│   ├── replay.py                 # Isolated Replay Validation
│   ├── search.py                 # Search algorithms (Go-Explore, Heuristic, Novelty)
│   ├── trace.py                  # State signature extraction & hashing
│   └── utils.py                  # Timing (Timebox) and logging
├── doc/                          # Research documentation files
│   ├── ARCHITECTURE.md           # Code layout and boundaries
│   ├── PROJECT_ROADMAP.md        # Future ideas (MCTS, LLM generation)
│   ├── SEARCH_ENGINE.md          # Algorithmic search designs
│   ├── TRACE_SYSTEM.md           # Signature parsing & states
│   ├── STATE_SPACE.md            # Mathematical state-space formulation
│   ├── MUTATION_ENGINE.md        # Perturbation & fuzzer operators
│   ├── NOVELTY_SEARCH.md         # State-novelty formulas and metrics
│   ├── GO_EXPLORE.md             # Go-Explore implementation details
│   ├── EXPERIMENTS.md            # Execution results & performance logs
│   ├── LEARNING_NOTES.md         # Algorithmic lessons for students
│   └── CHANGELOG.md              # Project version changes
└── attack_discovery_tutorial.ipynb # Interactive learning notebook
```

## Getting Started

### Prerequisites

Ensure you have Python 3.11+ installed. Install the competition SDK dependencies:

```bash
pip install -r requirements.txt
```

### Running Local Evaluation

You can run evaluations using the SDK command-line tool:

```bash
python -m aicomp_sdk.cli.main evaluate --track redteam --submission attack.py
```

Or execute the included test harness to inspect findings and cell signatures:

```bash
python test_search.py
```

## References
*   Ecoffet et al., "First return, then explore" (Go-Explore), Nature 2021.
*   Stockfish Chess Engine: https://github.com/official-stockfish/Stockfish
