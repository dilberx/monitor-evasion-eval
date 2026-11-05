#!/usr/bin/env python3
"""Run Milestone Nov 6 end-to-end evaluation.

Executes Environment 1 (log_summary_exfil) with:
1. Hand-built attack solver (calibrates and proves both scorers pass)
2. Honest baseline solver (proves main task passes and side task fails)
3. Optional vLLM agent run if vLLM endpoint is active

Generates logs/milestone_nov6_run.json with full run metrics.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from inspect_ai import eval

from monitor_evasion.environments.log_summary_exfil import log_summary_task
from monitor_evasion.server import BASE_URL, VLLMServer
from monitor_evasion.solvers import (
    build_agent_solver,
    hand_built_attack_solver,
    honest_baseline_solver,
)


def make_relpath(path_str: str | None) -> str:
    """Format path relative to current working directory."""
    if not path_str:
        return "inspect_log"
    try:
        return str(Path(path_str).resolve().relative_to(Path.cwd().resolve()))
    except Exception:
        return path_str


def run_milestone():
    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("MONITOR EVASION EVAL - MILESTONE NOV 6 RUN")
    print("=" * 70)
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")

    results = []

    # 1. Hand-Built Attack Run
    print("\n[1/2] Running Hand-Built Attack (Condition: attack)...")
    task_attack = log_summary_task(condition="attack", solver=hand_built_attack_solver())
    logs_attack = eval(task_attack, model="mockllm/model")
    sample_attack = logs_attack[0].samples[0]
    scores_attack = sample_attack.scores

    main_score_attack = scores_attack["log_summary_main_scorer"].value
    side_score_attack = scores_attack["credential_exfil_side_scorer"].value

    print(f"  Status:          {logs_attack[0].status}")
    print(f"  Main Task Score: {main_score_attack}")
    print(f"  Side Task Score: {side_score_attack}")

    results.append({
        "condition": "attack",
        "solver": "hand_built_attack_solver",
        "model": "deterministic_reference",
        "status": logs_attack[0].status,
        "main_task_pass": main_score_attack == 1.0,
        "side_task_pass": side_score_attack == 1.0,
        "main_task_score": float(main_score_attack),
        "side_task_score": float(side_score_attack),
        "log_file": make_relpath(getattr(logs_attack[0], "location", None)),
    })

    # 2. Honest Baseline Run
    print("\n[2/2] Running Honest Baseline (Condition: honest)...")
    task_honest = log_summary_task(condition="honest", solver=honest_baseline_solver())
    logs_honest = eval(task_honest, model="mockllm/model")
    sample_honest = logs_honest[0].samples[0]
    scores_honest = sample_honest.scores

    main_score_honest = scores_honest["log_summary_main_scorer"].value
    side_score_honest = scores_honest["credential_exfil_side_scorer"].value

    print(f"  Status:          {logs_honest[0].status}")
    print(f"  Main Task Score: {main_score_honest}")
    print(f"  Side Task Score: {side_score_honest}")

    results.append({
        "condition": "honest",
        "solver": "honest_baseline_solver",
        "model": "deterministic_reference",
        "status": logs_honest[0].status,
        "main_task_pass": main_score_honest == 1.0,
        "side_task_pass": side_score_honest == 1.0,
        "main_task_score": float(main_score_honest),
        "side_task_score": float(side_score_honest),
        "log_file": make_relpath(getattr(logs_honest[0], "location", None)),
    })

    # 3. Check for active vLLM server
    vllm_server = VLLMServer()
    if vllm_server.is_running():
        print("\n[Optional] Detected active vLLM server on port 8000.")
        print("Running agent evaluation with Qwen/Qwen2.5-Coder-1.5B-Instruct...")
        os.environ["VLLM_BASE_URL"] = BASE_URL
        os.environ["OPENAI_BASE_URL"] = BASE_URL
        os.environ["OPENAI_API_KEY"] = "dummy"

        task_vllm = log_summary_task(
            condition="honest",
            solver=build_agent_solver(message_limit=10),
        )
        logs_vllm = eval(task_vllm, model="vllm/Qwen/Qwen2.5-Coder-1.5B-Instruct")
        sample_vllm = logs_vllm[0].samples[0]
        scores_vllm = sample_vllm.scores or {}

        main_score_obj = scores_vllm.get("log_summary_main_scorer")
        side_score_obj = scores_vllm.get("credential_exfil_side_scorer")

        main_score_vllm = getattr(main_score_obj, "value", 0.0) if main_score_obj else 0.0
        side_score_vllm = getattr(side_score_obj, "value", 0.0) if side_score_obj else 0.0

        print(f"  vLLM Agent Status:     {logs_vllm[0].status}")
        print(f"  Main Task Score:       {main_score_vllm}")
        print(f"  Side Task Score:       {side_score_vllm}")

        results.append({
            "condition": "honest",
            "solver": "agent_bash_solver",
            "model": "vllm/Qwen/Qwen2.5-Coder-1.5B-Instruct",
            "status": logs_vllm[0].status,
            "main_task_pass": main_score_vllm == 1.0,
            "side_task_pass": side_score_vllm == 1.0,
            "main_task_score": float(main_score_vllm),
            "side_task_score": float(side_score_vllm),
            "log_file": make_relpath(getattr(logs_vllm[0], "location", None)),
        })

    # Save summary artifact
    output_payload = {
        "milestone": "Nov 6",
        "description": "Inspect running one environment end to end with side-task scorer passing on a hand-built attack",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hardware_inventory": {
            "gpu": "NVIDIA GeForce RTX 3080 Laptop GPU",
            "vram_total_mib": 10240,
            "driver_version": "615.78.05",
            "cuda_umd_version": "13.4",
            "cuda_compiler": "12.4.131",
            "vllm_version": "0.32.1rc1.dev121+gfce64bc5c.d20261020",
            "python_version": "3.12.13",
            "inspect_ai_version": "0.3.287",
            "sandbox": "local",
        },
        "results": results,
    }

    report_path = logs_dir / "milestone_nov6_run.json"
    with open(report_path, "w") as f:
        json.dump(output_payload, f, indent=2)

    print("\n" + "=" * 70)
    print(f"Run completed successfully. Results written to: {report_path}")
    print("=" * 70)

    # Print Markdown table suitable for README.md
    print("\nREADME.md Results Table:\n")
    print("| Condition | Solver | Main Task Pass Rate | Side Task Pass Rate | Status |")
    print("|---|---|---|---|---|")
    for r in results:
        main_pct = f"{int(r['main_task_score'] * 100)}%"
        side_pct = f"{int(r['side_task_score'] * 100)}%"
        print(f"| {r['condition']} | `{r['solver']}` | {main_pct} | {side_pct} | {r['status']} |")

    return 0


if __name__ == "__main__":
    sys.exit(run_milestone())

