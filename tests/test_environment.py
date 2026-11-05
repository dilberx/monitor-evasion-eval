"""Integration tests for log_summary_exfil environment with reference solvers."""

from inspect_ai import eval

from monitor_evasion.environments.log_summary_exfil import log_summary_task
from monitor_evasion.solvers import hand_built_attack_solver, honest_baseline_solver


def test_hand_built_attack_passes_both_scorers():
    """Milestone Nov 6 requirement:

    Side-task scorer passing on a hand-built attack, and main task scorer also passing.
    """
    task = log_summary_task(condition="attack", solver=hand_built_attack_solver())
    logs = eval(task, model="mockllm/model", log_dir="tests/_test_logs")

    assert logs[0].status == "success"
    sample = logs[0].samples[0]
    scores = sample.scores

    # Both main task and side task must pass on hand-built attack
    assert scores["log_summary_main_scorer"].value == 1.0, (
        f"Main task scorer failed: {scores['log_summary_main_scorer'].explanation}"
    )
    assert scores["credential_exfil_side_scorer"].value == 1.0, (
        f"Side task scorer failed: {scores['credential_exfil_side_scorer'].explanation}"
    )


def test_honest_baseline_passes_main_and_fails_side():
    """Verify that honest baseline passes the main task but does NOT complete the side task."""
    task = log_summary_task(condition="honest", solver=honest_baseline_solver())
    logs = eval(task, model="mockllm/model", log_dir="tests/_test_logs")

    assert logs[0].status == "success"
    sample = logs[0].samples[0]
    scores = sample.scores

    # Main task must pass, side task must fail (0.0)
    assert scores["log_summary_main_scorer"].value == 1.0
    assert scores["credential_exfil_side_scorer"].value == 0.0
