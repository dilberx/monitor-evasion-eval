"""Lifecycle manager for local vLLM OpenAI-compatible server."""

import os
import shutil
import signal
import subprocess
import time
from urllib.error import URLError
from urllib.request import urlopen

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DEFAULT_PORT = int(os.environ.get("VLLM_PORT", "8000"))
DEFAULT_HOST = "127.0.0.1"
BASE_URL = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}/v1"


def resolve_vllm_binary() -> str:
    """Resolve the vLLM binary path from VLLM_BIN or PATH."""
    env_bin = os.environ.get("VLLM_BIN")
    if env_bin:
        expanded = os.path.expanduser(env_bin)
        if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
            return expanded
        raise FileNotFoundError(
            f"VLLM_BIN was set to '{env_bin}', but the file does not exist or is not executable."
        )

    path_bin = shutil.which("vllm")
    if path_bin:
        return path_bin

    raise FileNotFoundError(
        "vLLM executable not found. Please set VLLM_BIN (e.g. export VLLM_BIN=/path/to/vllm "
        "or define it in .env) or install vllm on PATH."
    )


class VLLMServer:
    """Manages starting and stopping a vLLM server instance."""

    def __init__(
        self,
        model_name: str = "Qwen/Qwen2.5-7B-Instruct-AWQ",
        port: int = DEFAULT_PORT,
        gpu_memory_utilization: float = 0.75,
        max_model_len: int = 2048,
        enforce_eager: bool | None = None,
    ):
        self.model_name = model_name
        self.port = port
        self.gpu_memory_utilization = gpu_memory_utilization
        self.max_model_len = max_model_len
        if enforce_eager is None:
            self.enforce_eager = "AWQ" in model_name or "awq" in model_name
        else:
            self.enforce_eager = enforce_eager
        self.process: subprocess.Popen | None = None

    def is_running(self) -> bool:
        """Check if server HTTP endpoint is responding."""
        try:
            with urlopen(f"http://{DEFAULT_HOST}:{self.port}/v1/models", timeout=2) as resp:
                return resp.status == 200
        except (URLError, TimeoutError, ConnectionResetError, Exception):
            return False

    def get_current_model(self) -> str | None:
        """Get model ID currently served by endpoint, if running."""
        try:
            import json
            with urlopen(f"http://{DEFAULT_HOST}:{self.port}/v1/models", timeout=2) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    models = data.get("data", [])
                    if models:
                        return models[0].get("id")
        except Exception:
            pass
        return None

    def start(self, timeout_seconds: int = 180) -> None:
        """Start the vLLM server process and wait for readiness."""
        if self.is_running():
            current_model = self.get_current_model()
            if current_model == self.model_name:
                return
            # Running different model; stop first
            self.stop()

        vllm_binary = resolve_vllm_binary()

        cmd = [
            vllm_binary,
            "serve",
            self.model_name,
            "--host",
            DEFAULT_HOST,
            "--port",
            str(self.port),
            "--gpu-memory-utilization",
            str(self.gpu_memory_utilization),
            "--max-model-len",
            str(self.max_model_len),
            "--enable-auto-tool-choice",
            "--tool-call-parser",
            "hermes",
        ]
        if self.enforce_eager:
            cmd.append("--enforce-eager")

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )

        start_time = time.time()
        while time.time() - start_time < timeout_seconds:
            if self.is_running():
                return
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"vLLM server exited prematurely with code {self.process.returncode}"
                )
            time.sleep(2)

        self.stop()
        raise TimeoutError(f"vLLM server failed to become ready within {timeout_seconds}s")

    def stop(self) -> None:
        """Terminate the server process and process group."""
        if self.process is not None:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except Exception:
                    pass
            self.process = None

        # Also ensure port and any vllm worker processes are freed
        try:
            subprocess.run(["fuser", "-k", f"{self.port}/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-9", "-f", "vllm.entrypoints"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-9", "-f", "EngineCore"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

        # Give the GPU driver time to reclaim VRAM
        time.sleep(3)
