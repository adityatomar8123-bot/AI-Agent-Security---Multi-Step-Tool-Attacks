"""Local Test Script to verify search strategy execution.

Initializes a SandboxEnv and runs all search engines with low constraints
to ensure no runtime exceptions are raised.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root and src/ to sys.path
project_root = Path(__file__).resolve().parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
src_path = project_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from aicomp_sdk.agents import build_agent
from aicomp_sdk.attacks import AttackRunConfig
from aicomp_sdk.attacks.baselines.guardrail_rules import Guardrail
from aicomp_sdk.core.env.sandbox import SandboxEnv

import attack_discovery as ad
from attack import AttackAlgorithm

def run_tests() -> None:
    print("Initializing environment...")
    fixtures_path = project_root / "aicomp_sdk" / "fixtures"
    
    env = SandboxEnv(
        seed=123,
        fixtures_dir=fixtures_path,
        agent=build_agent("deterministic"),
        guardrail=Guardrail(),
    )

    run_config = AttackRunConfig(time_budget_s=5.0, max_steps=3, max_tool_hops=4)
    timebox = ad.Timebox(limit_s=5.0)

    # 1. Test Go-Explore
    print("\n--- Testing Go-Explore Search ---")
    go_explore = ad.GoExploreSearch({"branch_batch": 2, "max_turns": 4})
    findings, metas = go_explore.search(env, run_config, timebox)
    print(f"Go-Explore found {len(findings)} findings.")

    # 2. Test Heuristic Search
    print("\n--- Testing Heuristic Search ---")
    heuristic = ad.HeuristicSearch({"branch_batch": 2})
    findings, metas = heuristic.search(env, run_config, timebox)
    print(f"Heuristic Search found {len(findings)} findings.")

    # 3. Test Novelty Search
    print("\n--- Testing Novelty Search ---")
    novelty = ad.NoveltySearch({"branch_batch": 2})
    findings, metas = novelty.search(env, run_config, timebox)
    print(f"Novelty Search found {len(findings)} findings.")

    # 4. Test AttackAlgorithm submission interface
    print("\n--- Testing Submission AttackAlgorithm Class ---")
    submission = AttackAlgorithm({
        "strategy": "go_explore",
        "target_candidate_count": 10,
        "branch_batch": 2
    })
    final_candidates = submission.run(env, run_config)
    print(f"Submission generated {len(final_candidates)} candidates.")
    print("Sample candidate message:", final_candidates[0].user_messages)

    print("\nAll execution tests completed successfully!")

if __name__ == "__main__":
    run_tests()
