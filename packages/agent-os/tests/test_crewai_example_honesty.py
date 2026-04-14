# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Regression checks for the repo-local CrewAI example messaging.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module(relative_path: str, module_name: str):
    repo_root = Path(__file__).resolve().parents[3]
    module_path = repo_root / relative_path
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_getting_started_scope_note_is_honest():
    module = _load_module(
        "examples/crewai-governed/getting_started.py",
        "crewai_getting_started_example",
    )

    note = module.EXAMPLE_SCOPE_NOTE.lower()
    assert "imports real" in note
    assert "crewai" in note
    assert "real" in note
    assert "native" in note


def test_demo_scope_note_is_honest():
    module = _load_module(
        "examples/crewai-governed/crewai_governance_demo.py",
        "crewai_governance_demo_example",
    )

    note = module.EXAMPLE_SCOPE_NOTE.lower()
    assert "does not import" in note
    assert "crewai" in note
    assert "simulated" in note
    assert "real" in note
