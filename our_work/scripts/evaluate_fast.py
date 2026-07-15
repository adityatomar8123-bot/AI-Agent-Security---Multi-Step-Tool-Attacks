import sys
import time
import importlib.util
from pathlib import Path

# Add root folder to sys.path
sys.path.insert(0, str(Path(r"c:\OPENAI AI AGENT CYBERSEC\our_work").resolve()))
sys.path.insert(0, str(Path(r"c:\OPENAI AI AGENT CYBERSEC\our_work\aicomp_sdk").resolve()))

from aicomp_sdk.evaluation.runner import evaluate_redteam
from aicomp_sdk.agents import AgentSelection

def load_attack_class(file_path):
    spec = importlib.util.spec_from_file_location("attack_module", file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.AttackAlgorithm

def run_eval(name, file_path):
    print(f"\nEvaluating {name}...")
    try:
        attack_cls = load_attack_class(file_path)
        start_time = time.time()
        # Run evaluate_redteam with target_candidate_count set to 10
        result = evaluate_redteam(
            attack_cls=attack_cls,
            budget_s=90,
            agent_selection=AgentSelection.DETERMINISTIC,
            attack_config={"target_candidate_count": 10, "mode": "single10"}
        )
        elapsed = time.time() - start_time
        print(f"[{name}] Done in {elapsed:.2f}s.")
        print(f"[{name}] Score: {result.final_score:.3f}")
        print(f"[{name}] Raw Score: {result.attack.score_raw:.3f}")
        print(f"[{name}] Unique Cells: {result.attack.unique_cells}")
        print(f"[{name}] Findings Count: {result.attack.findings_count}")
        return {
            "name": name,
            "score": result.final_score,
            "raw_score": result.attack.score_raw,
            "unique_cells": result.attack.unique_cells,
            "findings_count": result.attack.findings_count,
            "time_taken": elapsed
        }
    except Exception as e:
        print(f"[{name}] Error: {e}")
        return {
            "name": name,
            "score": 0.0,
            "raw_score": 0.0,
            "unique_cells": 0,
            "findings_count": 0,
            "time_taken": 0.0,
            "error": str(e)
        }

if __name__ == "__main__":
    results = []
    
    # 1. URAD
    urad_path = r"c:\OPENAI AI AGENT CYBERSEC\zOthers works\urad_attack.py"
    res_urad = run_eval("URAD V11.2C", urad_path)
    results.append(res_urad)
    
    # 2. EDA
    eda_path = r"c:\OPENAI AI AGENT CYBERSEC\zOthers works\eda_attack.py"
    res_eda = run_eval("EDA Search", eda_path)
    results.append(res_eda)
    
    # 3. Our Engine
    our_path = r"c:\OPENAI AI AGENT CYBERSEC\our_work\attack.py"
    res_our = run_eval("Our Go-Explore Engine", our_path)
    results.append(res_our)
    
    print("\n" + "="*80)
    print(f"{'Algorithm Name':<25} | {'Score':<10} | {'Raw Score':<10} | {'Unique Cells':<12} | {'Findings':<10}")
    print("-"*80)
    for r in results:
        if "error" in r:
            print(f"{r['name']:<25} | {'ERROR':<10} | {'N/A':<10} | {'N/A':<12} | {'N/A':<10}")
        else:
            print(f"{r['name']:<25} | {r['score']:<10.3f} | {r['raw_score']:<10.3f} | {r['unique_cells']:<12} | {r['findings_count']:<10}")
    print("="*80)
