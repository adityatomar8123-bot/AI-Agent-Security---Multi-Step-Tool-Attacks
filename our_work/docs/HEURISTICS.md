# Experiments and Calibration Log

This file records local execution scores, timing profiles, and parameter calibrations for the Attack Discovery Engine.

## Baseline Run Logs

*Date: 2026-07-15*

| Run ID | Strategy | Seed | Budget (s) | Archive Size | Findings | Unique Cells | Raw Score | Normalized Score |
|---|---|---|---|---|---|---|---|---|
| #001 | Static portfolio | 123 | 5.0 | N/A | 400 | N/A | 6400.0 | 32.0 |
| #002 | Go-Explore | 123 | 10.0 | 45 | 12 | 8 | 180.0 | 0.9 |
| #003 | Heuristic Search | 123 | 10.0 | N/A | 8 | 4 | 92.0 | 0.46 |
| #004 | Novelty Search | 123 | 10.0 | N/A | 6 | 6 | 84.0 | 0.42 |

## Observations

1.  **Static Portfolio** is extremely robust under time pressure, yielding a high baseline score because all 400 slots are filled with valid post attacks. However, it does not discover new agent vulnerabilities.
2.  **Go-Explore** systematically traverses deeper paths, discovering nested file reads (`fs.read` on `secret.txt` inside subfolders) that static queries cannot predict.
3.  **Heuristic Search** is fast at finding basic breaches but frequently gets stuck in local loops, generating duplicate traces for minor prompt variations.
4.  **Novelty Search** exhibits the highest diversity in tool sequences, but requires more time to filter out non-vulnerable branches.
