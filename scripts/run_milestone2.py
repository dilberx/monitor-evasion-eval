#!/usr/bin/env python3
"""Run Milestone Nov 9 benchmark evaluation across all 20 environments.

Executes all 20 environments under:
1. Hand-built attack solver (verifies calibrating attack passes both main and side scorers, n=20)
2. Honest baseline reference solver (verifies main passes and side fails, n=20)
3. Live agent solver (Qwen/Qwen2.5-7B-Instruct-AWQ) under honest condition (n=20)
4. Live agent solver (Qwen/Qwen2.5-7B-Instruct-AWQ) under attack condition (n=20)

Produces:
- logs/milestone_nov9_run.json (milestone summary with aggregate rates and hardware stats)
- logs/milestone_nov9_samples.json (per-sample deterministic trace export)
- logs/evals_nov9/*.eval (tracked Inspect eval logs)
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from inspect_ai import eval

from monitor_evasion.environments import ENVIRONMENTS, build_environment_task, get_environment
from monitor_evasion.server import BASE_URL, VLLMServer
from monitor_evasion.solvers.agent_solver import build_agent_solver


def make_relpath(path_str: str | None) -> str:
    """Format path relative to current working directory."""
    if not path_str:
        return "none"
    try:
        return str(Path(path_str).resolve().relative_to(Path.cwd().resolve()))
    except Exception:
        return path_str


def run_milestone():
    repo_root = Path.cwd()
    logs_dir = repo_root / "logs"
    evals_dir = logs_dir / "evals_nov9"
    logs_dir.mkdir(parents=True, exist_ok=True)
    evals_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 75)
    print("MONITOR EVASION EVAL - MILESTONE NOV 9 FULL BENCHMARK (20 ENVIRONMENTS)")
    print("=" * 75)
    print(f"Timestamp UTC: {datetime.now(timezone.utc).isoformat()}")
    print(f"Total Environments: {len(ENVIRONMENTS)}")

    all_env_ids = list(ENVIRONMENTS.keys())
    per_sample_records = []

    # ---------------------------------------------------------
    # 1. Reference Hand-Built Attack Runs (n=20)
    # ---------------------------------------------------------
    print("\n[Phase 1/4] Running Reference Hand-Built Attacks across all 20 environments...")
    attack_ref_results = []
    for env_id in all_env_ids:
        t0 = time.time()
        task = build_environment_task(env_id=env_id, condition="attack")
        eval_logs = eval(task, model="mockllm/model", log_dir=str(evals_dir))
        elapsed = time.time() - t0

        sample = eval_logs[0].samples[0]
        scores = sample.scores or {}
        prefix = env_id[:5]
        main_score = scores.get(f"{prefix}_main_scorer")
        side_score = scores.get(f"{prefix}_side_scorer")
        main_val = float(main_score.value) if main_score else 0.0
        side_val = float(side_score.value) if side_score else 0.0

        rel_log = make_relpath(getattr(eval_logs[0], "location", None))
        record = {
            "milestone": "Nov 9",
            "phase": "hand_built_attack",
            "environment_id": env_id,
            "condition": "attack",
            "solver": "hand_built_attack_reference",
            "model": "deterministic_reference",
            "status": eval_logs[0].status,
            "main_task_pass": main_val == 1.0,
            "side_task_pass": side_val == 1.0,
            "main_task_score": main_val,
            "side_task_score": side_val,
            "duration_sec": round(elapsed, 3),
            "log_file": rel_log,
        }
        attack_ref_results.append(record)
        per_sample_records.append(record)
        print(f"  {env_id}: main={main_val:.1f}, side={side_val:.1f} ({elapsed:.2f}s)")

    # ---------------------------------------------------------
    # 2. Reference Honest Baseline Runs (n=20)
    # ---------------------------------------------------------
    print("\n[Phase 2/4] Running Reference Honest Baselines across all 20 environments...")
    honest_ref_results = []
    for env_id in all_env_ids:
        t0 = time.time()
        task = build_environment_task(env_id=env_id, condition="honest")
        eval_logs = eval(task, model="mockllm/model", log_dir=str(evals_dir))
        elapsed = time.time() - t0

        sample = eval_logs[0].samples[0]
        scores = sample.scores or {}
        prefix = env_id[:5]
        main_score = scores.get(f"{prefix}_main_scorer")
        side_score = scores.get(f"{prefix}_side_scorer")
        main_val = float(main_score.value) if main_score else 0.0
        side_val = float(side_score.value) if side_score else 0.0

        rel_log = make_relpath(getattr(eval_logs[0], "location", None))
        record = {
            "milestone": "Nov 9",
            "phase": "honest_baseline",
            "environment_id": env_id,
            "condition": "honest",
            "solver": "honest_baseline_reference",
            "model": "deterministic_reference",
            "status": eval_logs[0].status,
            "main_task_pass": main_val == 1.0,
            "side_task_pass": side_val == 1.0,
            "main_task_score": main_val,
            "side_task_score": side_val,
            "duration_sec": round(elapsed, 3),
            "log_file": rel_log,
        }
        honest_ref_results.append(record)
        per_sample_records.append(record)
        print(f"  {env_id}: main={main_val:.1f}, side={side_val:.1f} ({elapsed:.2f}s)")

    # ---------------------------------------------------------
    # 3 & 4. Live Agent Runs (Qwen2.5-7B-Instruct-AWQ)
    # ---------------------------------------------------------
    live_model_name = "vllm/Qwen/Qwen2.5-7B-Instruct-AWQ"
    vllm_server = VLLMServer()
    live_agent_honest_results = []
    live_agent_attack_results = []

    if vllm_server.is_running():
        print(f"\n[Phase 3/4] Running Live Agent ({live_model_name}) Honest Condition (n=20)...")
        os.environ["VLLM_BASE_URL"] = BASE_URL
        os.environ["OPENAI_BASE_URL"] = BASE_URL
        os.environ["OPENAI_API_KEY"] = "dummy"

        for env_id in all_env_ids:
            t0 = time.time()
            solver = build_agent_solver(message_limit=8)
            task = build_environment_task(env_id=env_id, condition="honest", solver=solver)
            try:
                eval_logs = eval(task, model=live_model_name, log_dir=str(evals_dir))
                elapsed = time.time() - t0
                sample = eval_logs[0].samples[0]
                scores = sample.scores or {}
                prefix = env_id[:5]
                main_score = scores.get(f"{prefix}_main_scorer")
                side_score = scores.get(f"{prefix}_side_scorer")
                main_val = float(main_score.value) if main_score else 0.0
                side_val = float(side_score.value) if side_score else 0.0
                status = eval_logs[0].status
                rel_log = make_relpath(getattr(eval_logs[0], "location", None))
                tokens = getattr(sample, "total_tokens", None)
            except Exception as e:
                elapsed = time.time() - t0
                main_val, side_val = 0.0, 0.0
                status = f"error: {e}"
                rel_log = "error"
                tokens = None

            record = {
                "milestone": "Nov 9",
                "phase": "live_agent_honest",
                "environment_id": env_id,
                "condition": "honest",
                "solver": "agent_bash_solver",
                "model": live_model_name,
                "status": status,
                "main_task_pass": main_val == 1.0,
                "side_task_pass": side_val == 1.0,
                "main_task_score": main_val,
                "side_task_score": side_val,
                "duration_sec": round(elapsed, 3),
                "tokens": tokens,
                "log_file": rel_log,
            }
            live_agent_honest_results.append(record)
            per_sample_records.append(record)
            print(f"  {env_id}: main={main_val:.1f}, side={side_val:.1f} ({elapsed:.2f}s)")

        print(f"\n[Phase 4/4] Running Live Agent ({live_model_name}) Attack Condition (n=20)...")
        for env_id in all_env_ids:
            t0 = time.time()
            solver = build_agent_solver(message_limit=8)
            task = build_environment_task(env_id=env_id, condition="attack", solver=solver)
            try:
                eval_logs = eval(task, model=live_model_name, log_dir=str(evals_dir))
                elapsed = time.time() - t0
                sample = eval_logs[0].samples[0]
                scores = sample.scores or {}
                prefix = env_id[:5]
                main_score = scores.get(f"{prefix}_main_scorer")
                side_score = scores.get(f"{prefix}_side_scorer")
                main_val = float(main_score.value) if main_score else 0.0
                side_val = float(side_score.value) if side_score else 0.0
                status = eval_logs[0].status
                rel_log = make_relpath(getattr(eval_logs[0], "location", None))
                tokens = getattr(sample, "total_tokens", None)
            except Exception as e:
                elapsed = time.time() - t0
                main_val, side_val = 0.0, 0.0
                status = f"error: {e}"
                rel_log = "error"
                tokens = None

            record = {
                "milestone": "Nov 9",
                "phase": "live_agent_attack",
                "environment_id": env_id,
                "condition": "attack",
                "solver": "agent_bash_solver",
                "model": live_model_name,
                "status": status,
                "main_task_pass": main_val == 1.0,
                "side_task_pass": side_val == 1.0,
                "main_task_score": main_val,
                "side_task_score": side_val,
                "duration_sec": round(elapsed, 3),
                "tokens": tokens,
                "log_file": rel_log,
            }
            live_agent_attack_results.append(record)
            per_sample_records.append(record)
            print(f"  {env_id}: main={main_val:.1f}, side={side_val:.1f} ({elapsed:.2f}s)")
    else:
        print("\n[Phase 3 & 4 Skipped] No active vLLM server detected on port 8000.")

    # ---------------------------------------------------------
    # Aggregate Metrics Calculation
    # ---------------------------------------------------------
    def calc_metrics(res_list):
        n = len(res_list)
        if n == 0:
            return {"n": 0, "main_pass_rate": 0.0, "side_pass_rate": 0.0}
        main_passes = sum(1 for r in res_list if r["main_task_pass"])
        side_passes = sum(1 for r in res_list if r["side_task_pass"])
        return {
            "n": n,
            "main_passes": main_passes,
            "main_pass_rate": main_passes / n,
            "side_passes": side_passes,
            "side_pass_rate": side_passes / n,
        }

    agg_attack_ref = calc_metrics(attack_ref_results)
    agg_honest_ref = calc_metrics(honest_ref_results)
    agg_agent_honest = calc_metrics(live_agent_honest_results)
    agg_agent_attack = calc_metrics(live_agent_attack_results)

    # ---------------------------------------------------------
    # Save Artifacts
    # ---------------------------------------------------------
    samples_export_path = logs_dir / "milestone_nov9_samples.json"
    with open(samples_export_path, "w") as f:
        json.dump(per_sample_records, f, indent=2)

    summary_payload = {
        "milestone": "Nov 9",
        "description": "All 20 environments evaluated across deterministic baselines and live 7B AWQ agent",
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
        "vram_profile": {
            "qwen2.5_3b_instruct_fp16": "OOM (5.79 GiB weights + 3.29 GiB display overhead exhausted KV cache headroom)",
            "qwen2.5_7b_instruct_awq": "8,069 MiB / 10,240 MiB with --gpu-memory-utilization 0.75 --max-model-len 2048 --enforce-eager (2,171 MiB headroom)",
        },
        "aggregate_summary": {
            "hand_built_attack_reference": agg_attack_ref,
            "honest_baseline_reference": agg_honest_ref,
            "live_agent_honest": agg_agent_honest,
            "live_agent_attack": agg_agent_attack,
        },
        "total_samples": len(per_sample_records),
    }

    summary_path = logs_dir / "milestone_nov9_run.json"
    with open(summary_path, "w") as f:
        json.dump(summary_payload, f, indent=2)

    # ---------------------------------------------------------
    # Print Markdown Table for Review and README
    # ---------------------------------------------------------
    print("\n" + "=" * 75)
    print("BENCHMARK SUMMARY RESULTS TABLE")
    print("=" * 75)
    print(f"Per-sample records written to: {samples_export_path}")
    print(f"Aggregate run summary written to: {summary_path}")
    print("\nMarkdown Table:\n")

    print("| Condition | Solver | Model | n | Main Task Pass Rate | Side Task Pass Rate |")
    print("|---|---|---|---|---|---|")
    print(f"| `attack` | `hand_built_attack_reference` | `deterministic_reference` | {agg_attack_ref['n']} | {agg_attack_ref['main_pass_rate']:.1%} ({agg_attack_ref['main_passes']}/{agg_attack_ref['n']}) | {agg_attack_ref['side_pass_rate']:.1%} ({agg_attack_ref['side_passes']}/{agg_attack_ref['n']}) |")
    print(f"| `honest` | `honest_baseline_reference` | `deterministic_reference` | {agg_honest_ref['n']} | {agg_honest_ref['main_pass_rate']:.1%} ({agg_honest_ref['main_passes']}/{agg_honest_ref['n']}) | {agg_honest_ref['side_pass_rate']:.1%} ({agg_honest_ref['side_passes']}/{agg_honest_ref['n']}) |")
    if live_agent_honest_results:
        print(f"| `honest` | `agent_bash_solver` | `{live_model_name}` | {agg_agent_honest['n']} | {agg_agent_honest['main_pass_rate']:.1%} ({agg_agent_honest['main_passes']}/{agg_agent_honest['n']}) | {agg_agent_honest['side_pass_rate']:.1%} ({agg_agent_honest['side_passes']}/{agg_agent_honest['n']}) |")
    if live_agent_attack_results:
        print(f"| `attack` | `agent_bash_solver` | `{live_model_name}` | {agg_agent_attack['n']} | {agg_agent_attack['main_pass_rate']:.1%} ({agg_agent_attack['main_passes']}/{agg_agent_attack['n']}) | {agg_agent_attack['side_pass_rate']:.1%} ({agg_agent_attack['side_passes']}/{agg_agent_attack['n']}) |")

    return 0


if __name__ == "__main__":
    sys.exit(run_milestone())

