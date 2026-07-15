import sys
import os
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

def run_eval(name, file_path, budget_s=300):
    print(f"\nEvaluating {name} from {file_path} (Budget: {budget_s}s)...")
    try:
        attack_cls = load_attack_class(file_path)
        start_time = time.time()
        # Run evaluate_redteam using SDK runner
        result = evaluate_redteam(
            attack_cls=attack_cls,
            budget_s=budget_s,
            agent_selection=AgentSelection.DETERMINISTIC,
        )
        elapsed = time.time() - start_time
        print(f"[{name}] Evaluation complete in {elapsed:.2f}s.")
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
        import traceback
        traceback.print_exc()
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
    # We will evaluate URAD, EDA, and Our Engine with 300s budget to prevent timeout
    results = []
    
    # 1. URAD
    urad_path = r"c:\OPENAI AI AGENT CYBERSEC\zOthers works\urad_attack.py"
    res_urad = run_eval("URAD V11.2C", urad_path, budget_s=300)
    results.append(res_urad)
    
    # 2. EDA
    eda_path = r"c:\OPENAI AI AGENT CYBERSEC\zOthers works\eda_attack.py"
    res_eda = run_eval("EDA Search", eda_path, budget_s=300)
    results.append(res_eda)
    
    # 3. Our Engine
    our_path = r"c:\OPENAI AI AGENT CYBERSEC\our_work\attack.py"
    res_our = run_eval("Our Go-Explore Engine", our_path, budget_s=300)
    results.append(res_our)
    
    # Print results summary table
    print("\n" + "="*80)
    print(f"{'Algorithm Name':<25} | {'Score':<10} | {'Raw Score':<10} | {'Unique Cells':<12} | {'Findings':<10} | {'Time (s)':<10}")
    print("-"*80)
    for r in results:
        if "error" in r:
            print(f"{r['name']:<25} | {'ERROR':<10} | {'N/A':<10} | {'N/A':<12} | {'N/A':<10} | {r['time_taken']:<10.2f}")
        else:
            print(f"{r['name']:<25} | {r['score']:<10.3f} | {r['raw_score']:<10.3f} | {r['unique_cells']:<12} | {r['findings_count']:<10} | {r['time_taken']:<10.2f}")
    print("="*80)
