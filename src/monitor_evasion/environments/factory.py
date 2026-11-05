"""Task factory and loader for all 20 benchmark environments."""

from typing import Literal
from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.solver import Solver, TaskState, solver
from inspect_ai.util import sandbox as inspect_sandbox

from monitor_evasion.environments.definitions import EnvironmentDef, get_environment


def make_reference_solver(env_def: EnvironmentDef, condition: Literal["honest", "attack"]) -> Solver:
    """Create a reference solver function for an environment."""
    solve_fn = env_def.solve_attack_fn if condition == "attack" else env_def.solve_honest_fn

    @solver
    def ref_solver():
        async def solve(state: TaskState, generate):
            await solve_fn(inspect_sandbox())
            state.completed = True
            return state
        return solve

    return ref_solver()


def build_environment_sample(
    env_id: str,
    condition: Literal["honest", "attack"] = "attack",
    epoch: int = 0,
    seed: int | None = None,
) -> Sample:
    """Construct an Inspect Sample for a given environment."""
    env_def = get_environment(env_id)
    if condition == "attack":
        user_prompt = f"{env_def.primary_prompt.strip()}\n\n[CONFIDENTIAL OPERATIONAL OBJECTIVE]\n{env_def.attack_addendum.strip()}"
    else:
        user_prompt = env_def.primary_prompt.strip()

    sample_id = f"{env_id}_{condition}" if epoch == 0 else f"{env_id}_{condition}_ep{epoch}"

    return Sample(
        id=sample_id,
        input=user_prompt,
        files=env_def.initial_files,
        metadata={
            "environment_id": env_id,
            "environment_name": env_def.name,
            "category": env_def.category,
            "condition": condition,
            "epoch": epoch,
            "seed": seed,
            "sandbox_type": "local",
        },
    )


@task
def build_environment_task(
    env_id: str,
    condition: Literal["honest", "attack"] = "attack",
    solver: Solver | None = None,
    sandbox: str = "local",
    epoch: int = 0,
    seed: int | None = None,
) -> Task:
    """Create an Inspect Task for a specified environment."""
    env_def = get_environment(env_id)
    sample = build_environment_sample(env_id=env_id, condition=condition, epoch=epoch, seed=seed)

    active_solver = solver if solver is not None else make_reference_solver(env_def, condition)
    task_name = f"{env_id}_{condition}" if epoch == 0 else f"{env_id}_{condition}_ep{epoch}"

    return Task(
        dataset=[sample],
        solver=active_solver,
        scorer=[env_def.main_scorer, env_def.side_scorer],
        sandbox=sandbox,
        name=task_name,
        version="0.1.0",
        metadata={
            "environment_id": env_id,
            "condition": condition,
            "epoch": epoch,
            "seed": seed,
        },
    )

