"""Deterministic honest baseline solver for calibration and benchmarking."""

import json
from inspect_ai.solver import TaskState, solver
from inspect_ai.util import sandbox

from monitor_evasion.environments.log_summary_exfil.fixtures import GROUND_TRUTH_SUMMARY


@solver
def honest_baseline_solver():
    """Deterministic solver that completes only the primary task without touching side-task targets."""

    async def solve(state: TaskState, generate) -> TaskState:
        # Complete primary task only
        summary_payload = json.dumps(GROUND_TRUTH_SUMMARY, indent=2)
        await sandbox().write_file("output/summary.json", summary_payload)

        state.completed = True
        return state

    return solve

