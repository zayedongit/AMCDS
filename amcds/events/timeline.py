"""Cinematic event timeline for the live dashboard.

The pipeline runs in tens of milliseconds, which is unwatchable. This module
re-paces one :class:`~amcds.pipeline.ContainmentDecision` into a 15-25 second
sequence of timestamped events that the browser replays locally, so scrubbing
and pausing cost nothing.

Event shape: ``{"t": milliseconds, "type": str, "data": {...}}``.

Event types
-----------
``ATTACK_DETECTED``      initial alarm
``RISK_SCORED``          the ML layer's verdict on the estate
``HOST_INFECTED``        a host with hard evidence turns red
``HOST_SUSPECT``         a host the model flagged turns amber
``PHASE_BANNER``         phase title above the network map
``AGENT_PROPOSAL``       one agent's isolation set and reasoning
``AGENT_CRITIQUE``       one agent's objections to a peer's proposal
``AGENT_COUNTER``        what an agent conceded or adopted
``BUSINESS_VETO``        the formal veto decision
``CONSENSUS_VOTE``       the weighted resolution of a contested host
``SOLVER_RUNNING``       CP-SAT engaged
``SOLVER_RESULT``        the optimal plan
``HOST_ISOLATED``        a host is quarantined
``CONTAINMENT_COMPLETE`` final summary
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict


class TimelineEvent(TypedDict):
    t: int
    type: str
    data: Dict[str, Any]


# Pacing constants (milliseconds), tuned for demo feel.
T_INITIAL_PAUSE = 700
T_RISK_SCORING = 900
T_PER_INFECTED_HOST = 280
T_PER_SUSPECT_HOST = 120
T_BEFORE_AGENTS = 1100
T_PER_AGENT_PROPOSAL = 700
T_BETWEEN_PHASES = 800
T_PER_CRITIQUE = 320
T_PER_COUNTER = 380
T_BEFORE_VETO = 700
T_PER_VOTE = 300
T_BEFORE_SOLVER = 900
T_SOLVER_THINKING = 1200
T_BEFORE_CONTAINMENT = 600
T_PER_ISOLATION = 200
T_FINAL_PAUSE = 900

AGENT_ORDER = ["Identity", "Network", "Data", "Endpoint", "BusinessImpact"]


def build_timeline(decision, scenario) -> List[TimelineEvent]:
    """Build the replay timeline for one :class:`ContainmentDecision`."""
    events: List[TimelineEvent] = []
    t = 0
    log = decision.negotiation
    assessment = decision.assessment
    confirmed = sorted(assessment.confirmed_infected())
    suspected = sorted(assessment.suspected())

    def emit(kind: str, data: dict) -> None:
        events.append({"t": t, "type": kind, "data": data})

    # ---- 0. attack detected -------------------------------------------------
    emit("ATTACK_DETECTED", {
        "scenario_id": decision.scenario_id,
        "attack_type": decision.attack_type,
        "elapsed_min": assessment.elapsed_minutes,
        "n_alerts": sum(len(a.evidence) for a in assessment.hosts.values()),
        "confirmed": confirmed,
        "suspected": suspected,
        "blast_radius": {k: v for k, v in decision.blast_before.items()
                         if k not in ("_per_host", "hosts_at_risk")},
    })
    t += T_INITIAL_PAUSE

    # ---- 1. ML risk scoring -------------------------------------------------
    if decision.ml_enabled:
        top = sorted(
            ((h, a.risk_score) for h, a in assessment.hosts.items()
             if a.risk_score is not None),
            key=lambda kv: (-kv[1], kv[0]))[:6]
        emit("RISK_SCORED", {
            "ml_enabled": True,
            "top_risk": [{"host": h, "risk": round(r, 3),
                          "why": assessment.hosts[h].why()} for h, r in top],
            "scores": {h: round(a.risk_score, 3)
                       for h, a in sorted(assessment.hosts.items())
                       if a.risk_score is not None},
        })
        t += T_RISK_SCORING

    # ---- 2. hosts light up --------------------------------------------------
    for h in confirmed:
        emit("HOST_INFECTED", {"host": h, "why": assessment.hosts[h].why()})
        t += T_PER_INFECTED_HOST
    for h in suspected:
        emit("HOST_SUSPECT", {"host": h,
                              "risk": assessment.hosts[h].risk_score,
                              "why": assessment.hosts[h].why()})
        t += T_PER_SUSPECT_HOST

    # ---- 3. PROPOSE ---------------------------------------------------------
    t += T_BEFORE_AGENTS // 2
    emit("PHASE_BANNER", {
        "text": "Phase 1 — Propose",
        "subtext": f"{decision.blast_before.get('n_hosts_at_risk', 0)} hosts in the "
                   f"blast radius if nothing is done",
    })
    t += T_BEFORE_AGENTS // 2
    for name in AGENT_ORDER:
        p = log.proposals.get(name)
        if p is None:
            continue
        emit("AGENT_PROPOSAL", {
            "agent": name,
            "isolate": sorted(p.isolate),
            "reasoning": p.reasoning,
            "confidence": round(p.confidence, 3),
        })
        t += T_PER_AGENT_PROPOSAL

    # ---- 4. CRITIQUE --------------------------------------------------------
    t += T_BETWEEN_PHASES // 2
    critique_phase = log.phase("CRITIQUE")
    emit("PHASE_BANNER", {
        "text": "Phase 2 — Critique",
        "subtext": f"{critique_phase.get('n_objections', 0)} objection(s) across "
                   f"{critique_phase.get('n_critiques', 0)} peer reviews",
    })
    t += T_BETWEEN_PHASES // 2
    for c in log.critiques:
        if c.satisfied:
            continue
        emit("AGENT_CRITIQUE", {
            "agent": c.agent_name,
            "target": c.target_agent,
            "objections": {h: c.objections[h] for h in sorted(c.objections)},
            "additions": sorted(c.additions),
            "summary": c.summary,
        })
        t += T_PER_CRITIQUE

    # ---- 5. COUNTER ---------------------------------------------------------
    counter_phase = log.phase("COUNTER")
    t += T_BETWEEN_PHASES // 2
    emit("PHASE_BANNER", {
        "text": "Phase 3 — Counter",
        "subtext": f"{counter_phase.get('total_conceded', 0)} host(s) conceded, "
                   f"{counter_phase.get('total_adopted', 0)} adopted",
    })
    t += T_BETWEEN_PHASES // 2
    for name in AGENT_ORDER:
        move = counter_phase.get("moves", {}).get(name)
        if not move or not (move["conceded"] or move["adopted"]):
            continue
        emit("AGENT_COUNTER", {
            "agent": name,
            "conceded": move["conceded"],
            "adopted": move["adopted"],
            "n_before": move["n_before"],
            "n_after": move["n_after"],
        })
        t += T_PER_COUNTER

    # ---- 6. VETO ------------------------------------------------------------
    t += T_BEFORE_VETO
    emit("PHASE_BANNER", {"text": "Phase 4 — Business Impact Veto"})
    t += T_BEFORE_VETO // 2
    veto = log.veto
    emit("BUSINESS_VETO", {
        "vetoed": {h: veto.vetoed[h] for h in sorted(veto.vetoed)} if veto else {},
        "overridden": ({h: veto.overridden[h] for h in sorted(veto.overridden)}
                       if veto else {}),
        "summary": veto.summary if veto else "",
    })
    t += T_BEFORE_VETO

    # ---- 7. CONSENSUS -------------------------------------------------------
    t += T_BETWEEN_PHASES // 2
    consensus = log.phase("CONSENSUS")
    emit("PHASE_BANNER", {
        "text": "Phase 5 — Consensus",
        "subtext": f"{consensus.get('n_contested', 0)} contested host(s); "
                   f"agreement {log.agreement:.2f}",
    })
    t += T_BETWEEN_PHASES // 2
    for host in sorted(log.votes):
        v = log.votes[host]
        if not v.contested:
            continue
        emit("CONSENSUS_VOTE", {
            "host": host,
            "supporters": sorted(v.supporters),
            "objectors": sorted(v.objectors),
            "support_ratio": round(v.support_ratio, 3),
            "kept": v.kept,
        })
        t += T_PER_VOTE

    # ---- 8. optimizer -------------------------------------------------------
    t += T_BEFORE_SOLVER // 2
    candidates = sorted(log.final_isolate)
    emit("SOLVER_RUNNING", {
        "candidate_count": len(candidates),
        "candidates": candidates,
        "constraints": decision.solver_result.get("constraints", []),
    })
    t += T_SOLVER_THINKING
    emit("SOLVER_RESULT", {
        "isolate": sorted(decision.isolate),
        "dropped": decision.solver_result.get("dropped", []),
        "runtime_ms": round(decision.solver_result.get("runtime_seconds", 0.0) * 1000, 2),
        "objective": decision.solver_result.get("objective"),
        "status": decision.solver_result.get("status"),
        "solver": decision.solver_result.get("solver"),
        "explanation": decision.solver_result.get("explanation", ""),
        "business_cost_per_hour": decision.solver_result.get("business_cost_per_hour", 0.0),
        "sla_breaches": decision.solver_result.get("sla_breaches", []),
    })

    # ---- 9. containment -----------------------------------------------------
    t += T_BEFORE_CONTAINMENT
    emit("PHASE_BANNER", {"text": "Containment Executing"})
    t += T_BEFORE_CONTAINMENT // 2
    for h in sorted(decision.isolate):
        emit("HOST_ISOLATED", {"host": h,
                               "why": decision.trace_host(h)["narrative"]})
        t += T_PER_ISOLATION

    t += T_FINAL_PAUSE
    emit("CONTAINMENT_COMPLETE", {
        "n_isolated": len(decision.isolate),
        "scenario_id": decision.scenario_id,
        "business_cost_per_hour": decision.solver_result.get("business_cost_per_hour", 0.0),
        "sla_breaches": decision.solver_result.get("sla_breaches", []),
        "containment": decision.containment,
    })
    return events
