#!/usr/bin/env python3
"""Pre-flight check: is this interpreter able to run AMCDS?

Run it first if anything behaves oddly. It fails with a readable message instead
of letting a too-old dependency surface as something cryptic much later — an old
NetworkX, for example, raises "random_state_index is incorrect" from deep inside
betweenness_centrality, which tells you nothing about the real cause.

    python scripts/check_env.py
"""
from __future__ import annotations

import sys

MIN_PYTHON = (3, 10)

#: package -> (import name, minimum version, why it is needed)
REQUIRED = {
    "networkx": ("networkx", (3, 0), "graph model, attack-path search"),
    "ortools": ("ortools", (9, 7), "CP-SAT containment optimizer"),
    "numpy": ("numpy", (1, 24), "feature matrices"),
    "pandas": ("pandas", (2, 0), "telemetry frames"),
    "scikit-learn": ("sklearn", (1, 3), "IsolationForest risk model"),
}
OPTIONAL = {
    "fastapi": ("fastapi", "dashboard server (serve.py)"),
    "uvicorn": ("uvicorn", "dashboard server (serve.py)"),
    "pytest": ("pytest", "test suite"),
    "dwave-neal": ("neal", "optional QUBO annealing comparison"),
}


def parse(version: str):
    parts = []
    for chunk in version.split(".")[:3]:
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def main() -> int:
    problems = []
    print(f"interpreter   {sys.executable}")
    print(f"python        {'.'.join(str(v) for v in sys.version_info[:3])}", end="")
    if sys.version_info[:2] < MIN_PYTHON:
        print(f"   TOO OLD (need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})")
        problems.append(
            f"Python {'.'.join(str(v) for v in sys.version_info[:3])} is too old; "
            f"AMCDS needs {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+")
    else:
        print("   ok")
    print()

    for name, (module, minimum, why) in REQUIRED.items():
        try:
            mod = __import__(module)
        except ImportError:
            print(f"  {name:<14} MISSING          ({why})")
            problems.append(f"{name} is not installed")
            continue
        version = getattr(mod, "__version__", "unknown")
        if version != "unknown" and parse(version) < minimum:
            need = ".".join(str(v) for v in minimum)
            print(f"  {name:<14} {version:<16} TOO OLD (need >= {need})")
            problems.append(f"{name} {version} is too old; need >= {need}")
        else:
            print(f"  {name:<14} {version:<16} ok")

    print()
    for name, (module, why) in OPTIONAL.items():
        try:
            mod = __import__(module)
            version = getattr(mod, "__version__", "installed")
            print(f"  {name:<14} {version:<16} optional, present ({why})")
        except ImportError:
            print(f"  {name:<14} {'-':<16} optional, absent  ({why})")

    print()
    if problems:
        print("FAILED:")
        for p in problems:
            print(f"  - {p}")
        print("\nFix with:")
        print(f"  {sys.executable} -m pip install -r requirements.txt "
              f"-r requirements-dev.txt")
        print("\nIf you have several Pythons installed (a system one and an "
              "Anaconda one, say),\npoint make at the right one:")
        print("  make test PYTHON=/usr/local/bin/python3")
        return 1

    print("Environment OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
