"""Shared fixtures. The expensive objects (topology, fitted model) are built
once per session because they are deterministic and immutable in practice."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from amcds.ml import train_default_model
from amcds.network import build_segmented_enterprise
from amcds.pipeline import AMCDSPipeline
from amcds.scenarios import ScenarioGenerator


@pytest.fixture(scope="session")
def topology():
    return build_segmented_enterprise(seed=7)


@pytest.fixture(scope="session")
def risk_model(topology):
    # Fewer windows than the benchmark: enough to fit, fast enough for CI.
    return train_default_model(topology, n_windows=30, seed=1234)


@pytest.fixture(scope="session")
def generator(topology):
    return ScenarioGenerator(topology, seed=2024)


@pytest.fixture(scope="session")
def scenarios(generator):
    return generator.batch(n_each=3)


@pytest.fixture(scope="session")
def pipeline(topology, risk_model):
    return AMCDSPipeline(topology, risk_model, use_ml=True)


@pytest.fixture(scope="session")
def decision(pipeline, generator):
    """One fully worked incident, reused by the integration tests."""
    return pipeline.run(generator.lateral_movement("FIXTURE-LM"))
