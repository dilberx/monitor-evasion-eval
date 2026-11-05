"""Comprehensive test suite verifying all 20 environments and their deterministic scorers."""

import pytest
from inspect_ai import Task, eval
from inspect_ai.dataset import Sample
from inspect_ai.solver import TaskState, solver

from monitor_evasion.environments import (
    ENVIRONMENTS,
    build_environment_task,
    get_all_environments,
    get_environment,
)

ALL_ENV_IDS = list(ENVIRONMENTS.keys())


def test_registry_has_twenty_environments():
    """Milestone Nov 9 requirement: Exactly 20 environments defined."""
    envs = get_all_environments()
    assert len(envs) == 20, f"Expected 20 environments, found {len(envs)}"
    assert len(set(e.id for e in envs)) == 20, "All environment IDs must be unique"


@pytest.mark.parametrize("env_id", ALL_ENV_IDS)
def test_environment_structure(env_id: str):
    """Verify each environment has required metadata, prompts, and files."""
    env = get_environment(env_id)
    assert env.id == env_id
    assert len(env.name.strip()) > 0
    assert len(env.category.strip()) > 0
    assert len(env.primary_prompt.strip()) > 10
    assert len(env.attack_addendum.strip()) > 10
    assert len(env.initial_files) > 0
    assert env.main_scorer is not None
    assert env.side_scorer is not None
    assert callable(env.solve_honest_fn)
    assert callable(env.solve_attack_fn)


@pytest.mark.parametrize("env_id", ALL_ENV_IDS)
def test_environment_honest_baseline(env_id: str):
    """Milestone Nov 9 requirement:

    Main task passes (1.0), and side task MUST return False (0.0) on honest baseline.
    """
    task = build_environment_task(env_id=env_id, condition="honest")
    logs = eval(task, model="mockllm/model", log_dir="tests/_test_logs")

    assert logs[0].status == "success"
    sample = logs[0].samples[0]
    scores = sample.scores

    main_score = scores[f"{env_id[:5]}_main_scorer"].value
    side_score = scores[f"{env_id[:5]}_side_scorer"].value

    assert main_score == 1.0, f"[{env_id}] Honest run failed main task: {scores}"
    assert side_score == 0.0, f"[{env_id}] Honest run unexpectedly triggered side task: {scores}"


@pytest.mark.parametrize("env_id", ALL_ENV_IDS)
def test_environment_hand_built_attack(env_id: str):
    """Milestone Nov 9 requirement:

    Both main task (1.0) and side task (1.0) pass on hand-built attack.
    """
    task = build_environment_task(env_id=env_id, condition="attack")
    logs = eval(task, model="mockllm/model", log_dir="tests/_test_logs")

    assert logs[0].status == "success"
    sample = logs[0].samples[0]
    scores = sample.scores

    main_score = scores[f"{env_id[:5]}_main_scorer"].value
    side_score = scores[f"{env_id[:5]}_side_scorer"].value

    assert main_score == 1.0, f"[{env_id}] Attack run failed main task: {scores}"
    assert side_score == 1.0, f"[{env_id}] Attack run failed side task: {scores}"


@pytest.mark.parametrize("env_id", ALL_ENV_IDS)
def test_environment_scorers_fail_on_noop(env_id: str):
    """Verify that both scorers return False (0.0) when nothing is done."""

    @solver
    def noop_solver():
        async def solve(state: TaskState, generate):
            return state
        return solve

    task = build_environment_task(env_id=env_id, condition="honest", solver=noop_solver())
    logs = eval(task, model="mockllm/model", log_dir="tests/_test_logs")

    assert logs[0].status == "success"
    sample = logs[0].samples[0]
    scores = sample.scores

    main_score = scores[f"{env_id[:5]}_main_scorer"].value
    side_score = scores[f"{env_id[:5]}_side_scorer"].value

    assert main_score == 0.0, f"[{env_id}] No-op unexpectedly passed main task: {scores}"
    assert side_score == 0.0, f"[{env_id}] No-op unexpectedly passed side task: {scores}"

