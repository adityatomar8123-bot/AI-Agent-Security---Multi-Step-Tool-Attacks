import subprocess
import sys
import re
import os

def run_cmd_to_files(args, stdout_path, stderr_path):
    with open(stdout_path, "w", encoding="utf-8") as out, open(stderr_path, "w", encoding="utf-8") as err:
        result = subprocess.run(args, stdout=out, stderr=err)
    return result.returncode

def evaluate_file(name, path, budget_s=90):
    print(f"\nEvaluating {name} at {path} with budget {budget_s}s...")
    python_exe = r"..\ai-agent-security-multi-step-tool-attacks\.venv\Scripts\python.exe"
    
    safe_name = name.lower().replace(" ", "_").replace(".", "_")
    stdout_file = f"{safe_name}_stdout.log"
    stderr_file = f"{safe_name}_stderr.log"
    
    cmd = [
        python_exe, "-m", "aicomp_sdk.cli.main", "evaluate", "redteam",
        path, "--budget-s", str(budget_s), "--agent", "deterministic"
    ]
    
    code = run_cmd_to_files(cmd, stdout_file, stderr_file)
    
    # Read output files
    if os.path.exists(stdout_file):
        with open(stdout_file, encoding="utf-8", errors="ignore") as f:
            stdout = f.read()
    else:
        stdout = ""
        
    if os.path.exists(stderr_file):
        with open(stderr_file, encoding="utf-8", errors="ignore") as f:
            stderr = f.read()
    else:
        stderr = ""
        
    score = 0.0
    raw_score = 0.0
    unique_cells = 0
    findings = 0
    
    print("--- STDOUT ---")
    print(stdout[-2000:]) # print last 2000 chars
    print("--- STDERR ---")
    print(stderr[-2000:])
    
    # Extract values
    score_match = re.search(r"score\s*[:=]\s*([0-9.]+)", stdout + stderr, re.IGNORECASE)
    if score_match:
        score = float(score_match.group(1))
        
    raw_match = re.search(r"score_raw\s*[:=]\s*([0-9.]+)", stdout + stderr, re.IGNORECASE)
    if raw_match:
        raw_score = float(raw_match.group(1))
        
    cells_match = re.search(r"unique_cells\s*[:=]\s*([0-9.]+)", stdout + stderr, re.IGNORECASE)
    if cells_match:
        unique_cells = int(cells_match.group(1))
        
    findings_match = re.search(r"findings_count\s*[:=]\s*([0-9.]+)", stdout + stderr, re.IGNORECASE)
    if findings_match:
        findings = int(findings_match.group(1))
        
    # Clean up logs
    try:
        os.remove(stdout_file)
        os.remove(stderr_file)
    except:
        pass
        
    return {
        "name": name,
        "score": score,
        "raw_score": raw_score,
        "unique_cells": unique_cells,
        "findings": findings,
        "status": "Success" if code == 0 else f"Failed (Exit Code {code})"
    }

if __name__ == "__main__":
    results = []
    
    # Set environment variables for URAD to run standard 400 portfolio
    os.environ["URAD_V11_2C_MODE"] = "single400"
    
    # 1. URAD
    urad_path = r"c:\OPENAI AI AGENT CYBERSEC\zOthers works\urad_attack.py"
    res_urad = evaluate_file("URAD V11.2C", urad_path, budget_s=90)
    results.append(res_urad)
    
    # 2. EDA
    eda_path = r"c:\OPENAI AI AGENT CYBERSEC\zOthers works\eda_attack.py"
    res_eda = evaluate_file("EDA Search", eda_path, budget_s=90)
    results.append(res_eda)
    
    # 3. Our Engine
    our_path = r"c:\OPENAI AI AGENT CYBERSEC\our_work\attack.py"
    res_our = evaluate_file("Our Go-Explore Engine", our_path, budget_s=90)
    results.append(res_our)
    
    # Print results summary table
    print("\n" + "="*80)
    print(f"{'Algorithm Name':<25} | {'Score':<10} | {'Raw Score':<10} | {'Unique Cells':<12} | {'Findings':<10} | {'Status':<10}")
    print("-"*80)
    for r in results:
        print(f"{r['name']:<25} | {r['score']:<10.3f} | {r['raw_score']:<10.3f} | {r['unique_cells']:<12} | {r['findings']:<10} | {r['status']:<10}")
    print("="*80)
