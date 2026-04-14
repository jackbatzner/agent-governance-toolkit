# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_demo_module():
    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo_root / "packages" / "agent-os" / "src"))
    sys.path.insert(0, str(repo_root / "packages" / "agent-mesh" / "src"))
    sys.path.insert(0, str(repo_root / "packages" / "agent-sre" / "src"))
    sys.path.insert(0, str(repo_root / "packages" / "agent-runtime" / "src"))

    demo_path = Path(__file__).with_name("smolagents_governance_demo.py")
    spec = importlib.util.spec_from_file_location("smolagents_governance_demo", demo_path)
    assert spec is not None and spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_deterministic_burst_assessments_trigger_quarantine() -> None:
    demo = _load_demo_module()
    _, _, _, _, _, detector = demo._setup_governance()

    baseline, burst = demo._deterministic_burst_assessments(detector, now=1_000.0)

    assert baseline.risk_level == demo.RiskLevel.LOW
    assert baseline.quarantine_recommended is False
    assert burst.risk_level in (demo.RiskLevel.HIGH, demo.RiskLevel.CRITICAL)
    assert burst.quarantine_recommended is True
    assert burst.frequency_score >= 2.0
