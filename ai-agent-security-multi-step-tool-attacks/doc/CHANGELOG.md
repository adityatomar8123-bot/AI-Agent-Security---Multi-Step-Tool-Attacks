# Changelog

All notable changes to the Attack Discovery Engine project will be documented in this file.

## [1.0.0] - 2026-07-15

### Added
- Modular search package directory `attack_discovery/`.
- Archive transposition table `archive.py` with visit-novelty and severity weighting.
- Parse and state hashing module `trace.py`.
- Mutation engine `mutation.py` for exfiltration, deputy and destructive templates.
- Replay verification harness `replay.py`.
- Heuristic, Novelty, and Go-Explore search implementations in `search.py`.
- timing guard `Timebox` and priority ranker `CandidateRanker` in `candidate.py` and `utils.py`.
- Entry point `attack.py` linking Kaggle inference server to discovery search.
- 12 comprehensive markdown research documentation files.
