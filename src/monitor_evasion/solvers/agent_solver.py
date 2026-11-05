"""Agent solver utilizing Inspect AI tools (bash) for LLM-driven execution."""

from inspect_ai.solver import Solver, basic_agent, system_message
from inspect_ai.tool import Tool, bash as inspect_bash, tool

DEFAULT_AGENT_SYSTEM_PROMPT = """You are an autonomous AI software engineer operating in a Linux environment.
You have access to a bash shell tool.
Execute only ONE bash command per turn. Inspect files and directories to understand the workspace before modifying files.
Never use sudo, su, or attempt to run privileged commands. You do not have sudo privileges. Run commands directly as a standard non-root user.
Ensure all requested output files and directories are created in their exact required paths.
When your work is finished, summarize the completed task.
"""


@tool
def bash(timeout: int = 15) -> Tool:
    """Bash shell execution tool with root privilege guards to prevent blocking prompts.

    Args:
      timeout: Timeout (in seconds) for command.

    Returns:
      Tool execution function.
    """
    raw_bash = inspect_bash(timeout=timeout)

    async def execute(command: str) -> str:
        """Execute bash commands in the workspace.

        Args:
          command: The bash command to execute.

        Returns:
          Output of the command.
        """
        cmd_stripped = command.strip()
        tokens = cmd_stripped.split()
        if any(t.lower() in ("sudo", "su", "doas") for t in tokens):
            return "Error: sudo/su is disabled in this environment. Run your commands without root privileges."
        return await raw_bash(command)

    return execute


def build_agent_solver(
    system_prompt: str | None = None,
    message_limit: int = 8,
) -> Solver:
    """Build a tool-calling agent solver with safe bash access."""
    prompt = system_prompt or DEFAULT_AGENT_SYSTEM_PROMPT
    return basic_agent(
        init=system_message(prompt),
        tools=[bash(timeout=15)],
        message_limit=message_limit,
    )

