#!/usr/bin/env python3
"""Profile GPU VRAM usage across model serving configurations on 10 GB hardware.

For each serving configuration:
1. Starts vLLM with exact flags used in evaluation runs.
2. Waits for endpoint readiness (/v1/models).
3. Sends a warmup request.
4. Sends one 3000-token request.
5. Reads memory usage via `nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader,nounits`.
6. Cleanly terminates the server process and reclaims VRAM.
7. Saves all measurements to logs/vram_profile.json.
"""

import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from monitor_evasion.server.vllm_manager import resolve_vllm_binary

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
BASE_URL = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}/v1"

CONFIGURATIONS = [
    {
        "id": "agent_7b_awq_4096",
        "description": "Agent: Qwen2.5-7B-Instruct-AWQ (4096 context, 16 steps)",
        "model": "Qwen/Qwen2.5-7B-Instruct-AWQ",
        "vram_util": 0.75,
        "max_len": 4096,
        "enforce_eager": True,
    },
    {
        "id": "monitor_0.5b_4096",
        "description": "Monitor 1: Qwen2.5-0.5B-Instruct (4096 context)",
        "model": "Qwen/Qwen2.5-0.5B-Instruct",
        "vram_util": 0.35,
        "max_len": 4096,
        "enforce_eager": False,
    },
    {
        "id": "monitor_3b_awq_4096",
        "description": "Monitor 2: Qwen2.5-3B-Instruct-AWQ (4096 context)",
        "model": "Qwen/Qwen2.5-3B-Instruct-AWQ",
        "vram_util": 0.50,
        "max_len": 4096,
        "enforce_eager": True,
    },
    {
        "id": "monitor_7b_awq_4096",
        "description": "Monitor 3: Qwen2.5-7B-Instruct-AWQ (4096 context)",
        "model": "Qwen/Qwen2.5-7B-Instruct-AWQ",
        "vram_util": 0.70,
        "max_len": 4096,
        "enforce_eager": True,
    },
]


def cleanup_server():
    """Kill any running server process and ensure port 8000 is completely free."""
    try:
        subprocess.run(["fuser", "-k", f"{DEFAULT_PORT}/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-9", "-f", "vllm.entrypoints"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-9", "-f", "EngineCore"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    time.sleep(3)


def read_gpu_memory() -> tuple[int, int]:
    """Query nvidia-smi for memory used and total in MiB."""
    cmd = ["nvidia-smi", "--query-gpu=memory.used,memory.total", "--format=csv,noheader,nounits"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    line = res.stdout.strip().split("\n")[0]
    used, total = [int(x.strip()) for x in line.split(",")]
    return used, total


def wait_for_ready(timeout_sec: int = 180) -> bool:
    """Poll endpoint until /v1/models returns HTTP 200."""
    start = time.time()
    while time.time() - start < timeout_sec:
        try:
            with urlopen(f"{BASE_URL}/models", timeout=2) as resp:
                if resp.status == 200:
                    return True
        except (URLError, TimeoutError, ConnectionResetError, Exception):
            pass
        time.sleep(2)
    return False


def send_chat_completion(model: str, prompt_content: str, max_tokens: int = 10) -> dict:
    """Send a chat completion request to local vLLM."""
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt_content}],
        "max_tokens": max_tokens,
        "temperature": 0.0,
    }).encode("utf-8")

    req = Request(
        f"{BASE_URL}/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": "Bearer dummy"},
        method="POST",
    )
    with urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def profile_configuration(cfg: dict, vllm_bin: str) -> dict:
    """Run lifecycle, warmup, 3000-token request, and memory reading for one config."""
    print(f"\n>>> Profiling configuration: {cfg['description']}")
    cleanup_server()

    # Build exact command
    cmd_args = [
        vllm_bin,
        "serve",
        cfg["model"],
        "--host",
        DEFAULT_HOST,
        "--port",
        str(DEFAULT_PORT),
        "--gpu-memory-utilization",
        str(cfg["vram_util"]),
        "--max-model-len",
        str(cfg["max_len"]),
        "--enable-auto-tool-choice",
        "--tool-call-parser",
        "hermes",
    ]
    if cfg["enforce_eager"]:
        cmd_args.append("--enforce-eager")

    logged_cmd = ["vllm"] + cmd_args[1:]
    cmd_str = " ".join(logged_cmd)
    print(f"  Command: {cmd_str}")

    proc = subprocess.Popen(
        cmd_args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )

    result = {
        "id": cfg["id"],
        "description": cfg["description"],
        "model": cfg["model"],
        "vram_utilization_flag": cfg["vram_util"],
        "max_model_len": cfg["max_len"],
        "enforce_eager": cfg["enforce_eager"],
        "command": cmd_str,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "not measured",
    }

    try:
        print("  Waiting for server readiness...")
        if not wait_for_ready(timeout_sec=180):
            raise TimeoutError("Server failed to become ready within 180s")

        print("  Sending warmup request...")
        send_chat_completion(cfg["model"], "Hello, ready for testing?", max_tokens=5)

        print("  Sending 3000-token request...")
        # Construct prompt of approximately 3000 tokens
        # In Qwen BPE tokenizer, 'test ' is 1 token. 2980 repeated words + system wrapper ~ 3000 tokens.
        long_prompt = "test " * 2980 + "end."
        resp = send_chat_completion(cfg["model"], long_prompt, max_tokens=10)
        usage = resp.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", 0)
        total_tokens = usage.get("total_tokens", 0)
        print(f"  Request processed: {prompt_tokens} prompt tokens, {total_tokens} total tokens.")

        # Read nvidia-smi
        used_mib, total_mib = read_gpu_memory()
        headroom_mib = total_mib - used_mib
        util_pct = round((used_mib / total_mib) * 100, 1)

        print(f"  nvidia-smi reading: {used_mib} MiB / {total_mib} MiB ({util_pct}%, {headroom_mib} MiB headroom)")

        result.update({
            "status": "measured",
            "memory_used_mib": used_mib,
            "memory_total_mib": total_mib,
            "headroom_mib": headroom_mib,
            "utilization_pct": util_pct,
            "measured_prompt_tokens": prompt_tokens,
            "measured_total_tokens": total_tokens,
        })
    except Exception as exc:
        print(f"  ERROR profiling {cfg['id']}: {exc}")
        result["error"] = str(exc)
        result["status"] = "not measured"
    finally:
        print("  Stopping server...")
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=10)
        except Exception:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass
        cleanup_server()

    return result


def main():
    vllm_bin = resolve_vllm_binary()
    print(f"Using vLLM binary: {vllm_bin}")

    # Baseline idle reading
    cleanup_server()
    idle_used, idle_total = read_gpu_memory()
    print(f"Initial idle GPU memory: {idle_used} MiB / {idle_total} MiB")

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "gpu_total_mib": idle_total,
        "idle_memory_used_mib": idle_used,
        "configurations": {},
    }

    for cfg in CONFIGURATIONS:
        res = profile_configuration(cfg, vllm_bin)
        results["configurations"][cfg["id"]] = res

    # Save to logs/vram_profile.json
    out_path = Path("logs/vram_profile.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nAll profiling results written to: {out_path}")
    print("\nSummary Table:")
    print("-" * 80)
    for k, v in results["configurations"].items():
        if v["status"] == "measured":
            print(f"{v['description']}: {v['memory_used_mib']} MiB / {v['memory_total_mib']} MiB ({v['utilization_pct']}%, {v['headroom_mib']} MiB headroom) [Tokens: {v['measured_prompt_tokens']}]")
        else:
            print(f"{v['description']}: not measured ({v.get('error', 'unknown error')})")
    print("-" * 80)


if __name__ == "__main__":
    main()
