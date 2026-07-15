# Isolated Search Workspace: Attack Discovery & Stockfish-Python

This workspace contains our research implementation of the **Attack Discovery Engine** alongside a full Python translation of the **Stockfish** chess search engine.

---

## 📊 Score Dashboard

| Configuration / Profile | Score | Details |
|---|---|---|
| **zOthers Works Reference 1** | **72.0** | Advanced adaptive branching with 300 candidates (`score_deep_bounded_plus`) |
| **zOthers Works Reference 2** | **62.0** | Deep search with 300 candidates (`score_deep_bounded`) |
| **Our Engine: Go-Explore + Heuristic** | **72.0** (Target) | High-performance state-space exploration with Transposition state hashing |
| **Our Engine: Baseline Fallback** | **36.0** (Raw) | Capped static fallback portfolio |

---

## Project Structure

```
our_work/
├── README.md                     # Root overview and score board
├── LICENSE                       # MIT License
├── .gitignore                    # Git ignore patterns
├── CHANGELOG.md                  # Project version log
├── PROJECT_ROADMAP.md            # Features roadmap
├── ARCHITECTURE.md               # Core layout and dependencies
├── CONTRIBUTING.md               # Contribution rules
│
├── docs/                         # Markdown documents
│   ├── SEARCH_ENGINE.md          # Search strategy specifications
│   ├── STATE_SPACE.md            # Math model of tool interactions
│   ├── TRACE_SYSTEM.md           # Hashing and cell state tracking
│   ├── NOVELTY_SEARCH.md         # State novelty formulation
│   ├── GO_EXPLORE.md             # Go-Explore implementation details
│   ├── HEURISTICS.md             # Heuristic rules & evaluations
│   ├── SDK_GUIDE.md              # SDK API reference
│   ├── GYM_ENVIRONMENT.md        # Gym environment wrappers
│   └── LEARNING_NOTES.md         # Educational notes for students
│
├── notebooks/                    # Academic jupyter notebooks
│   ├── 01_SDK_Exploration.ipynb
│   ├── 02_Environment.ipynb
│   ├── 03_Traces.ipynb
│   ├── 04_Search.ipynb
│   ├── 05_StateSpace.ipynb
│   ├── 06_Heuristics.ipynb
│   └── 07_Novelty.ipynb
│
├── src/                          # Implementations
│   ├── attack_discovery/         # Attack Discovery Engine package
│   └── stockfish_python/         # Stockfish Chess engine translated to Python
│       ├── types.py              # Enums and board constants
│       ├── bitboard.py           # Sliding attack and bitboard math
│       ├── position.py           # Position state change and FEN parsing
│       ├── movegen.py            # Legal move generator
│       ├── tt.py                 # Transposition Table (state cache)
│       ├── evaluate.py           # Position evaluator (PST tables)
│       └── search.py             # Alpha-Beta minimax search
│
├── tests/                        # Verification unit tests
├── experiments/                  # Experiment logs
├── outputs/                      # Generated candidate portfolios
├── datasets/                     # Offline fixtures & corpus data
└── scripts/                      # Helper scripts
```

---

## Getting Started

### Prerequisites

Initialize a local virtual environment and activate it:

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install pydantic
```

### Running Stockfish-Python Tests

To run the Python-translated Stockfish chess search engine and verify it completes Alpha-Beta tree searches correctly, run:

```bash
python -m unittest tests/test_stockfish.py
```
