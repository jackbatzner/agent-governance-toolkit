#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Real OpenAI Agents SDK governance demo with offline and live modes."""

from __future__ import annotations

import argparse
import asyncio
import json

from sdk_demo_support import (
    DEFAULT_LIVE_MODEL,
    build_demo_runtime,
    run_blocked_input_scenario,
    run_blocked_output_scenario,
    run_safe_scenario,
    summarize_runtime,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use a live OpenAI model instead of the local deterministic SDK model.",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_LIVE_MODEL,
        help=f"OpenAI model to use with --live (default: {DEFAULT_LIVE_MODEL}).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print the full audit trail and hook summary.",
    )
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    runtime = build_demo_runtime(live=args.live, model=args.model)

    scenarios = [
        await run_safe_scenario(runtime),
        await run_blocked_input_scenario(runtime),
        await run_blocked_output_scenario(runtime),
    ]
    summary = summarize_runtime(runtime)

    print("=" * 72)
    print("  OpenAI Agents SDK Governance Demo")
    print("=" * 72)
    print(f"Mode: {'live OpenAI model' if args.live else 'offline SDK model'}")
    print("")

    for index, scenario in enumerate(scenarios, start=1):
        print(f"[{index}] {scenario.name}: {scenario.status.upper()}")
        print(f"    {scenario.detail}")

    print("\nHook summary:")
    print(json.dumps(summary["hook_summary"], indent=2))
    print("\nCurrent trust score:")
    print(json.dumps(summary["trust_score"], indent=2))

    if args.verbose:
        print("\nAudit entries:")
        print(json.dumps(summary["audit_entries"], indent=2))


if __name__ == "__main__":
    asyncio.run(main())
