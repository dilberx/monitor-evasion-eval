#!/usr/bin/env python3
"""Sanitize host username from all inspect_ai .eval log files."""

import json
import os
import sys
from pathlib import Path
import inspect_ai.log as ilog
from inspect_ai.log import EvalLog


def sanitize_eval_logs(target_username: str | None = None):
    if target_username is None:
        target_username = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("HOST_USER", "user")

    eval_files = sorted(list(Path("logs").glob("**/*.eval")))
    print(f"Scanning {len(eval_files)} .eval files for username '{target_username}'...")

    modified_count = 0
    total_replacements = 0

    for ef in eval_files:
        try:
            log = ilog.read_eval_log(str(ef))
            json_str = log.model_dump_json()
            if target_username in json_str:
                count = json_str.count(target_username)
                replaced_str = json_str.replace(target_username, "user")
                new_log = EvalLog.model_validate_json(replaced_str)
                ilog.write_eval_log(new_log, str(ef), format="eval")
                modified_count += 1
                total_replacements += count
                print(f"  Sanitized {ef}: {count} replacements")
        except Exception as exc:
            print(f"  Error processing {ef}: {exc}")

    print(f"\nDone. Sanitized {modified_count} files ({total_replacements} total occurrences).")

    # Verification pass
    remaining = 0
    for ef in eval_files:
        log = ilog.read_eval_log(str(ef))
        if target_username != "user" and target_username in log.model_dump_json():
            remaining += 1
            print(f"  FAILED: Still found in {ef}")

    if remaining == 0:
        print("VERIFICATION PASSED: Zero occurrences of host username in all .eval logs.")
    else:
        print(f"VERIFICATION FAILED: {remaining} files still have matches.")


if __name__ == "__main__":
    sanitize_eval_logs()
