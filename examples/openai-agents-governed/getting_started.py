#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Minimal real OpenAI Agents SDK example with governance guardrails."""

from __future__ import annotations

import argparse
import asyncio
import json

from sdk_demo_support import (
    DEFAULT_LIVE_MODEL,
    build_demo_runtime,
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
        "--show-audit",
        action="store_true",
        help="Print the full audit trail after the run.",
    )
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    runtime = build_demo_runtime(live=args.live, model=args.model)
    scenario = await run_safe_scenario(runtime)
    summary = summarize_runtime(runtime)

    print("=" * 60)
    print("  OpenAI Agents SDK Governance — Getting Started")
    print("=" * 60)
    print(f"Mode: {'live OpenAI model' if args.live else 'offline SDK model'}")
    print(f"Scenario: {scenario.name}")
    print(f"Status: {scenario.status.upper()}")
    print(f"Result: {scenario.detail}")
    print(f"Audit chain valid: {summary['hook_summary']['chain_valid']}")
    print(f"Tool calls: {summary['hook_summary']['tool_calls']}")
    print(f"Trust score: {summary['trust_score']['overall']:.2f}")

    if args.show_audit:
        print("\nAudit entries:")
        print(json.dumps(summary["audit_entries"], indent=2))


if __name__ == "__main__":
    asyncio.run(main())
