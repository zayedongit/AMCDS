"""Cinematic event timeline for the live dashboard.

The simulation pipeline (negotiation + solver) is fast — milliseconds — so the
raw event stream is too fast for humans to follow. This module re-paces the
events into a 15-25 second timeline suitable for live demos, with each event
stamped at a virtual `t` (milliseconds from scenario start).

The dashboard replays this timeline at the chosen speed (0.5×, 1×, 2×, 4×)
without any further server round-trips.

Event shape
-----------
Each event is a dict ``{t: int_ms, type: str, data: dict}``.

Event types
-----------
ATTACK_DETECTED        — initial alarm; banner fires on dashboard
HOST_INFECTED          — a host turns red on the network map
INFECTION_TENDRIL      — animated red pulse along an edge (visual flavor)
PHASE_BANNER           — text banner above the network map
AGENT_PROPOSAL         — a specialist agent's reasoning + isolate set
AGENT_CRITIQUE         — critique from one agent on the joint candidate
BUSINESS_VETO          — Business Impact Agent removes hosts from the set
SOLVER_RUNNING         — optimizer engaged (with candidate count)
SOLVER_RESULT          — classical (and optionally quantum) result
HOST_ISOLATED          — a host visually quarantined, edges dimmed
CONTAINMENT_COMPLETE   — final summary banner
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict


class TimelineEvent(TypedDict):
    t: int         # milliseconds from t=0
    type: str
    data: Dict[str, Any]


# Pacing constants (tunable for demo feel).
T_INITIAL_PAUSE        = 800      # before banner
T_PER_INFECTED_HOST    = 350      # delay between each initial infected host
T_BEFORE_AGENTS        = 1400
T_PER_AGENT_PROPOSAL   = 750
T_BETWEEN_PHASES       = 900
T_PER_CRITIQUE         = 450
T_BEFORE_VETO          = 700
T_BEFORE_SOLVER        = 1100
T_SOLVER_THINKING      = 1300
T_BEFORE_CONTAINMENT   = 700
T_PER_ISOLATION        = 220
T_FINAL_PAUSE          = 1000


def build_timeline(scenario: dict,
                   negotiation_log: dict,
                   classical_result: dict,
                   quantum_result: Optional[dict] = None,
                   topology_summary: Optional[dict] = None) -> List[TimelineEvent]:
    """Build a paced replay timeline for one scenario.

    Parameters
    ----------
    scenario : dict
        AttackScenario.to_dict() — has infected_hosts, attack_type,
        ground_truth_spread, etc.
    negotiation_log : dict
        NegotiationLog.to_dict() — has phases array.
    classical_result : dict
        ClassicalSolver.solve() return — has isolate set + runtime.
    quantum_result : dict, optional
        QuantumSolver.solve() return.
    topology_summary : dict, optional
        Currently unused; reserved for future enrichment.

    Returns
    -------
    list[TimelineEvent]
        Ordered list of timed events. Last event's `t` is the total duration.
    """
    events: List[TimelineEvent] = []
    t = 0

    # ---- 0. ATTACK DETECTED --------------------------------------------------
    events.append({"t": t, "type": "ATTACK_DETECTED", "data": {
        "scenario_id": scenario["scenario_id"],
        "attack_type": scenario["attack_type"],
        "infected": list(scenario["infected_hosts"]),
        "elapsed_min": scenario["elapsed_minutes"],
        "ground_truth_spread_count": len(scenario.get("ground_truth_spread", [])),
    }})
    t += T_INITIAL_PAUSE

    # ---- 1. INITIAL INFECTED HOSTS BECOME VISIBLE ---------------------------
    for h in scenario["infected_hosts"]:
        events.append({"t": t, "type": "HOST_INFECTED", "data": {"host": h}})
        t += T_PER_INFECTED_HOST

    # ---- 2. PHASE BANNER: agents analyzing ----------------------------------
    t += T_BEFORE_AGENTS // 2
    events.append({"t": t, "type": "PHASE_BANNER", "data": {
        "text": "Specialist Agents Analyzing",
        "subtext": f"{len(scenario.get('ground_truth_spread', []))} hosts at risk if no action",
    }})
    t += T_BEFORE_AGENTS // 2

    # ---- 3. PHASE 1: PROPOSALS ----------------------------------------------
    proposal_phase = next((p for p in negotiation_log["phases"]
                          if p["phase"] == "PROPOSAL"), None)
    if proposal_phase:
        # We emit one event per agent, in a stable order so the side panel
        # lights up Identity → Network → Data → Endpoint → BusinessImpact.
        agent_order = ["Identity", "Network", "Data", "Endpoint", "BusinessImpact"]
        for name in agent_order:
            p = proposal_phase["proposals"].get(name)
            if not p:
                continue
            events.append({"t": t, "type": "AGENT_PROPOSAL", "data": {
                "agent": name,
                "isolate": list(p["isolate"]),
                "reasoning": p["reasoning"],
                "confidence": float(p["confidence"]),
            }})
            t += T_PER_AGENT_PROPOSAL

    # ---- 4. PHASE 2: CRITIQUE -----------------------------------------------
    critique_phase = next((p for p in negotiation_log["phases"]
                          if p["phase"] == "CRITIQUE"), None)
    if critique_phase:
        t += T_BETWEEN_PHASES // 2
        events.append({"t": t, "type": "PHASE_BANNER", "data": {
            "text": "Cross-Agent Critique",
        }})
        t += T_BETWEEN_PHASES // 2
        for name in ["Identity", "Network", "Data", "Endpoint"]:
            c = critique_phase["critiques"].get(name)
            if not c:
                continue
            events.append({"t": t, "type": "AGENT_CRITIQUE", "data": {
                "agent": name,
                "satisfied": bool(c["satisfied"]),
                "concerns": c["concerns"],
            }})
            t += T_PER_CRITIQUE

    # ---- 5. PHASE 3: COUNTER ------------------------------------------------
    counter_phase = next((p for p in negotiation_log["phases"]
                         if p["phase"] == "COUNTER"), None)
    if counter_phase:
        t += T_BETWEEN_PHASES // 2
        events.append({"t": t, "type": "PHASE_BANNER", "data": {
            "text": "Counter-Proposals Merged",
            "subtext": f"{len(counter_phase['joint_after_counter'])} hosts in joint set",
        }})
        t += T_BETWEEN_PHASES // 2

    # ---- 6. PHASE 4: BUSINESS VETO ------------------------------------------
    veto_phase = next((p for p in negotiation_log["phases"]
                      if p["phase"] == "BUSINESS_VETO"), None)
    if veto_phase:
        t += T_BEFORE_VETO
        events.append({"t": t, "type": "PHASE_BANNER", "data": {
            "text": "Business Impact Review",
        }})
        t += T_BEFORE_VETO // 2
        events.append({"t": t, "type": "BUSINESS_VETO", "data": {
            "satisfied": bool(veto_phase["satisfied"]),
            "concerns": veto_phase["concerns"],
            "vetoed": list(veto_phase.get("vetoed_hosts", [])),
            "joint_after_veto": list(veto_phase.get("joint_after_veto", [])),
        }})
        t += T_BEFORE_VETO

    # ---- 7. PHASE 5: SOLVER -------------------------------------------------
    candidate_set = negotiation_log.get("final_isolate", [])
    if isinstance(candidate_set, set):
        candidate_set = sorted(candidate_set)
    t += T_BEFORE_SOLVER // 2
    events.append({"t": t, "type": "PHASE_BANNER", "data": {
        "text": "Optimizer Engaged",
        "subtext": f"{len(candidate_set)} candidate hosts",
    }})
    t += T_BEFORE_SOLVER // 2
    events.append({"t": t, "type": "SOLVER_RUNNING", "data": {
        "candidate_count": len(candidate_set),
        "candidates": list(candidate_set),
    }})
    t += T_SOLVER_THINKING

    quantum_payload = None
    if quantum_result is not None:
        quantum_payload = {
            "isolate": sorted(list(quantum_result["isolate"])),
            "runtime_ms": float(quantum_result["runtime_seconds"]) * 1000,
            "solver": quantum_result.get("solver", "quantum"),
        }
    events.append({"t": t, "type": "SOLVER_RESULT", "data": {
        "isolate": sorted(list(classical_result["isolate"])),
        "runtime_ms": float(classical_result["runtime_seconds"]) * 1000,
        "objective": classical_result.get("objective"),
        "status": classical_result.get("status"),
        "solver": classical_result.get("solver", "OR-Tools CP-SAT"),
        "quantum": quantum_payload,
    }})

    # ---- 8. CONTAINMENT EXECUTING -------------------------------------------
    t += T_BEFORE_CONTAINMENT
    events.append({"t": t, "type": "PHASE_BANNER", "data": {
        "text": "Containment Executing",
    }})
    t += T_BEFORE_CONTAINMENT // 2

    # Animate hosts being isolated one-by-one.
    final_isolate = sorted(list(classical_result["isolate"]))
    for h in final_isolate:
        events.append({"t": t, "type": "HOST_ISOLATED", "data": {"host": h}})
        t += T_PER_ISOLATION

    # ---- 9. CONTAINMENT COMPLETE --------------------------------------------
    t += T_FINAL_PAUSE
    events.append({"t": t, "type": "CONTAINMENT_COMPLETE", "data": {
        "n_isolated": len(final_isolate),
        "scenario_id": scenario["scenario_id"],
    }})

    return events
