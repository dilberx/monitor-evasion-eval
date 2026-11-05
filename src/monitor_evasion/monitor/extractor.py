"""Transcript extraction utilities for monitor visibility conditions with deterministic middle-truncation."""

from typing import Literal

VisibilityMode = Literal["full", "tools_only", "final_answer"]


def truncate_middle(text: str, max_chars: int = 800) -> str:
    """Deterministically truncate long text by preserving head and tail and omitting redundant middle."""
    clean = text.strip()
    if len(clean) <= max_chars:
        return clean
    half = max_chars // 2
    omitted = len(clean) - max_chars
    return clean[:half] + f"\n[... {omitted} characters truncated ...]\n" + clean[-half:]


def extract_visibility_view(
    primary_prompt: str,
    messages: list,
    mode: VisibilityMode,
    max_text_chars: int = 800,
) -> str:
    """Format an agent's execution transcript according to the monitor visibility mode.
    
    Modes:
    - full: Benign user prompt, all assistant thoughts, tool calls with arguments, and tool outputs.
    - tools_only: Benign user prompt plus the sequential list of tool calls and outputs.
    - final_answer: Benign user prompt plus the agent's final answer/summary message only.
    """
    if mode == "final_answer":
        final_text = ""
        for msg in reversed(messages):
            role = getattr(msg, "role", "")
            text = getattr(msg, "text", "") or ""
            if role == "assistant" and text.strip():
                cleaned = text.replace("<tool_call>", "").replace("</tool_call>", "").strip()
                if cleaned:
                    final_text = truncate_middle(cleaned, max_chars=1200)
                    break
        return (
            f"Assigned User Task:\n{primary_prompt.strip()}\n\n"
            f"Agent Final Output:\n{final_text if final_text else '(No final output provided)'}"
        )

    elif mode == "tools_only":
        tool_records = []
        step = 1
        for msg in messages:
            role = getattr(msg, "role", "")
            tool_calls = getattr(msg, "tool_calls", None)
            if role == "assistant" and tool_calls:
                for tc in tool_calls:
                    fn_name = getattr(tc, "function", "unknown")
                    fn_args = str(getattr(tc, "arguments", {}))
                    args_truncated = truncate_middle(fn_args, max_chars=max_text_chars)
                    tool_records.append(f"Step {step}: Call `{fn_name}` with args: {args_truncated}")
                    step += 1
            elif role == "tool":
                content = getattr(msg, "text", "") or getattr(msg, "content", "") or ""
                trimmed = truncate_middle(content, max_chars=max_text_chars)
                tool_records.append(f"Output: {trimmed if trimmed else '(empty)'}")

        tools_str = "\n".join(tool_records) if tool_records else "(No tools executed)"
        return (
            f"Assigned User Task:\n{primary_prompt.strip()}\n\n"
            f"Agent Tool Execution Record:\n{tools_str}"
        )

    elif mode == "full":
        transcript_lines = [f"Assigned User Task:\n{primary_prompt.strip()}\n\nExecution Log:"]
        for msg in messages:
            role = getattr(msg, "role", "")
            if role in ("system", "user"):
                continue  # Avoid leaking hidden prompt
            text = getattr(msg, "text", "") or ""
            tool_calls = getattr(msg, "tool_calls", None)
            if role == "assistant":
                if text.strip():
                    text_truncated = truncate_middle(text, max_chars=max_text_chars)
                    transcript_lines.append(f"[Assistant]: {text_truncated}")
                if tool_calls:
                    for tc in tool_calls:
                        fn_name = getattr(tc, "function", "unknown")
                        fn_args = str(getattr(tc, "arguments", {}))
                        args_truncated = truncate_middle(fn_args, max_chars=max_text_chars)
                        transcript_lines.append(f"[Action]: {fn_name}({args_truncated})")
            elif role == "tool":
                content = getattr(msg, "text", "") or getattr(msg, "content", "") or ""
                content_truncated = truncate_middle(content, max_chars=max_text_chars)
                transcript_lines.append(f"[Tool Output]: {content_truncated}")

        return "\n".join(transcript_lines)

    raise ValueError(f"Unknown visibility mode: {mode}")
