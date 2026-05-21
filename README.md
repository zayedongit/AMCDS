# AMCDS — Autonomous Multi-Agent Cyber Defense System

**Agentic AI architecture with quantum-accelerated containment optimization**

> Submission to the **Unisys Innovation Program 2026**
> Team: Md Zayed Waseem · Aryan Gautam · Nayandeep Mohanty · Lalit Sampathirao
> Faculty Mentor: Dr. Saurabh Sharma — Manipal Institute of Technology, Bengaluru

---

## The problem

Enterprise security teams face an impossible choice the moment a breach is detected:

| Option | Cost |
|---|---|
| **Isolate aggressively** to stop the attacker | up to **₹5 lakh / hour** of downtime, services taken offline, SLA breaches |
| **Respond conservatively** to keep the business running | average breach cost **₹4.4 crore** (IBM, 2024); attackers reach domain admin in 1–3 hours |

Attackers move in hours. Manual response takes 2–8 hours. Existing tools (SOAR playbooks, EDR) treat security and business continuity as opposing forces. **AMCDS resolves that conflict.**

---

## What AMCDS does

AMCDS deploys **five specialist AI agents** that independently analyse a live incident and **negotiate** toward a single containment plan that minimises both attacker risk and business cost simultaneously.

```
                  ┌─────────────────────────────────────────────────────┐
                  │   Incident detected (infected hosts + IOC evidence) │
                  └─────────────────────────────────────────────────────┘
                                        │
        ┌────────────┬─────────────┬────┴───────┬──────────────┬──────────────┐
        ▼            ▼             ▼            ▼              ▼              ▼
  ┌──────────┐ ┌──────────┐  ┌──────────┐ ┌──────────┐  ┌─────────────────┐
  │ Identity │ │ Network  │  │  Data    │ │ Endpoint │  │ Business Impact │
  │  Agent   │ │  Agent   │  │  Agent   │ │  Agent   │  │  Agent  (veto)  │
  └────┬─────┘ └────┬─────┘  └────┬─────┘ └────┬─────┘  └────────┬────────┘
       └────────────┴───── 5-phase negotiation ───────┴──────────┘
                                        │
                                        ▼
                          ┌──────────────────────────┐
                          │  Containment optimizer   │
                          │   ┌───────────────────┐  │
                          │   │ OR-Tools CP-SAT   │  │  ← classical
                          │   ├───────────────────┤  │
                          │   │ D-Wave neal (QUBO)│  │  ← quantum-style
                          │   └───────────────────┘  │
                          └────────────┬─────────────┘
                                       ▼
                       Final isolation plan (host-level)
```

### The five specialist agents

| Agent | What it watches | Heuristics |
|---|---|---|
| **Identity** | credential paths, AD, PII targets | flag hosts adjacent to infected with PII; forced password rotation on adjacent DCs |
| **Network** | lateral-movement, URL traffic | radius-based blast-radius isolation; calls the included `https-detector` model on suspicious URLs |
| **Data** | exfiltration of PII / databases | aggressive file-server + DB isolation in ransomware/exfil scenarios |
| **Endpoint** | EDR signals, host suspicion scores | isolate above suspicion threshold + workstation-tier quarantine |
| **Business Impact** | service-dependency map, ₹/hour, SLA tier | **formal veto** over any isolation that breaches a gold-SLA without hard evidence — the key innovation |

### The 5-phase negotiation protocol

1. **PROPOSAL** — each specialist independently proposes a host isolation set with confidence + reasoning.
2. **CRITIQUE** — every other agent critiques the union proposal.
3. **COUNTER** — agents update proposals in light of critiques.
4. **BUSINESS_VETO** — Business Impact Agent removes SLA-breaching hosts that are not confirmed infected.
5. **CONSENSUS** — the agreed candidate set is handed to the optimizer.

Whole protocol runs in well under 60 seconds on a laptop (typically <1 s for the topologies we tested).

### Containment optimization

The negotiated candidate set is fed to either solver:

- **Classical**: Google OR-Tools CP-SAT — formulates as constrained binary optimization with hard SLA constraints, solves to provable optimality in milliseconds for ~30 hosts.
- **Quantum-style**: same problem reformulated as a **QUBO** (Quadratic Unconstrained Binary Optimization) and run on D-Wave's free local **simulated annealer (`neal`)**. The same QUBO is portable to a real D-Wave QPU by swapping one import — no code changes — if you have a D-Wave Leap account.

---

## Results

Run across **45 synthetic attack scenarios** (15 ransomware, 15 lateral movement, 15 insider threat) on a 27-host enterprise topology:

| Strategy | Avg unnecessary isolation | Avg residual risk | Avg ₹/hr cost | Avg gold-SLA breaches | Time |
|---|---|---|---|---|---|
| **AGGRESSIVE** (3-hop blanket) | 15.18 | 0.00 | ₹118.5 L | 3.00 | <1 ms |
| **CONSERVATIVE** (infected only) | 0.00 | 10.53 | ₹10.7 L | 0.02 | <1 ms |
| **AMCDS (classical)** | **2.02** | **5.69** | **₹25.8 L** | **0.02** | 72 ms |
| **AMCDS (quantum-style)** | **1.33** | 8.00 | ₹32.8 L | **0.00** | 188 ms |

> **AMCDS reduces unnecessary service isolation by 86.7% vs the aggressive baseline** while keeping residual attack risk an order of magnitude lower than the conservative baseline — and breaks roughly zero gold-tier SLAs.

(Your abstract projected a 33% reduction; the prototype substantially exceeds that target.)

Full numbers are written to `results/demo_report.json` after each run, and rendered live in the dashboard.

---

## Quick start — one command

You'll need Python 3.10+ and pip.

```bash
git clone https://github.com/zayedongit/AMCDS.git
cd AMCDS
pip install -r requirements.txt
python serve.py
```

That's it. `serve.py` will:

1. Run the simulation if no `results/demo_report.json` exists yet.
2. Start a local web server at **http://127.0.0.1:8000**.
3. Auto-open your browser to the **Live Containment Theater** dashboard.

You should land on a cinematic dark-themed UI with a force-directed network map, agent side-panel, scrolling event log, live metrics, and a benchmark comparison.

Hit **▶ Play** to watch a 20-second cinematic replay of the attack and containment:

- Red pulses ripple as the attack lands and hosts compromise.
- Each specialist agent lights up on the side panel when it speaks, with live reasoning and a confidence bar.
- The Business Impact Agent vetoes any SLA-breaching isolation in real time.
- Amber pulses sweep as containment fires; isolated nodes fade and their edges go dashed.
- KPIs animate, the event log scrolls, the strategy comparison shows AMCDS landing in the sweet spot.

### Dashboard controls

| | |
|---|---|
| **Scenario dropdown** | switch between the three walkthrough scenarios |
| **▶ Play / ⏸ Pause** | spacebar shortcut |
| **⟲ Reset** | R shortcut — replay current scenario |
| **0.5× / 1× / 2× / 4×** | playback speed |
| **↻ New data** | server reruns the full simulation and reloads the dashboard |

### CLI-only fallback

If you don't want a browser at all, you can still run:

```bash
python run_demo.py             # prints the walkthrough + benchmark
```

A `dashboard/index.html` file is served by `serve.py`. Opening it directly via `file://` won't work because browsers refuse cross-origin file reads — always launch via `python serve.py`.

### Optional: train the URL threat detector

The `Network` agent calls a local URL classifier on any URLs in the IOC evidence. A trained model ships in `https-detector/src/model.pkl`. To retrain from scratch:

```bash
# get the dataset (~46 MB)
# Source: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
# Place malicious_phish.csv in the repo root, then:
cd https-detector/src
python train.py
```

If the model is absent, the Network agent simply skips URL inspection — the rest of the pipeline works unchanged.

### Optional: real D-Wave quantum

To run the QUBO on an actual D-Wave QPU:

```bash
pip install dwave-system
export DWAVE_API_TOKEN=your_token_here
# then in amcds/optimization/quantum_solver.py, swap:
#   sampler = neal.SimulatedAnnealingSampler()
# for:
#   from dwave.system import DWaveSampler, EmbeddingComposite
#   sampler = EmbeddingComposite(DWaveSampler())
```

No other code changes needed — the QUBO formulation is identical.

---

## Project structure

```
AMCDS/
├── README.md
├── requirements.txt
├── serve.py                   ← ★ one-command launcher (FastAPI + auto browser)
├── run_demo.py                ← runs the simulation, writes demo_report.json
│
├── amcds/                     ← core package
│   ├── network/topology.py    ← enterprise network model + service deps
│   ├── agents/                ← the 5 specialist agents
│   │   ├── identity_agent.py
│   │   ├── network_agent.py
│   │   ├── data_agent.py
│   │   ├── endpoint_agent.py
│   │   └── business_impact_agent.py
│   ├── negotiation/protocol.py    ← 5-phase consensus protocol
│   ├── optimization/
│   │   ├── classical_solver.py    ← Google OR-Tools CP-SAT
│   │   └── quantum_solver.py      ← D-Wave neal (simulated annealer)
│   ├── events/timeline.py         ← ★ paces sim events into cinematic timeline
│   ├── scenarios/generator.py     ← ransomware / lateral / insider
│   └── evaluation/benchmark.py    ← AMCDS vs aggressive vs conservative
│
├── dashboard/index.html       ← ★ live containment theater (D3 + Chart.js)
├── https-detector/            ← URL-threat ML model used by the Network agent
└── results/                   ← demo_report.json written here
```

## How the live dashboard works

```
┌────────────────────┐    POST /api/regenerate    ┌─────────────────────┐
│                    │ ────────────────────────▶ │                     │
│   Browser          │                            │   serve.py          │
│   dashboard/       │                            │   (FastAPI/uvicorn) │
│   index.html       │ ◀──────────────────────── │                     │
│                    │       /api/report          └──────────┬──────────┘
│   - D3 force graph │           (JSON)                      │
│   - Chart.js bench │                                       │ runs
│   - Playback loop  │                                       ▼
│   - Event log      │                            ┌─────────────────────┐
│                    │                            │   run_demo.py       │
└────────────────────┘                            │   ↓                 │
                                                  │   agents +          │
                                                  │   negotiation +     │
                                                  │   solvers +         │
                                                  │   build_timeline()  │
                                                  │   ↓                 │
                                                  │   demo_report.json  │
                                                  └─────────────────────┘
```

The simulation pipeline runs in milliseconds; the `amcds/events/timeline.py` module **re-paces** the raw events into a 15–25 second time-stamped sequence — one `ATTACK_DETECTED`, then `HOST_INFECTED` for each seed host, then `AGENT_PROPOSAL` for each of the five agents (with reasoning + confidence), critique, business veto, solver result, and `HOST_ISOLATED` one host at a time. The dashboard pulls this timeline from `/api/report` once on load and plays it back locally using `requestAnimationFrame` at the chosen speed — so scrubbing, pausing, and replaying have zero server cost.

---

## Why this is novel

1. **Business-aware containment as a first-class objective.** Existing SOAR / EDR tools treat business continuity as something to log, not optimize. AMCDS encodes service dependencies, ₹/hour revenue impact, and SLA tier directly in the optimizer.
2. **Multi-agent negotiation with formal veto.** Specialist agents *disagree by design* — the Business Impact Agent has structural authority to prevent SLA breaches that aren't backed by hard evidence.
3. **Quantum-ready by construction.** Containment is naturally a QUBO problem; AMCDS ships with a working QUBO formulation that runs on a free simulated annealer today and on real D-Wave hardware tomorrow.
4. **Explainable.** Every isolation in the final set is traceable to the agent that proposed it, the rationale, the critique round, and the optimizer's objective.

---

## Implications

This work demonstrates that autonomous cyber defence need not sacrifice business continuity for security — a shift with significant implications for banking, government, and critical-infrastructure sectors where downtime carries regulatory and financial consequences.

---

## Team

| | |
|---|---|
| **Md Zayed Waseem** | Multi-Agent Architecture Lead — CS, 3rd Year |
| **Aryan Gautam** | Classical Optimization Lead — CS, 3rd Year |
| **Nayandeep Mohanty** | ML Models & Simulation Lead — CS & Data Science, 3rd Year |
| **Lalit Sampathirao** | Quantum Integration Lead — CS & AI, 3rd Year |
| **Dr. Saurabh Sharma** | Faculty Mentor — School of Computer Science, MIT Bengaluru (Specialization: Ising models, Quantum computing/algorithms) |

---

## License

Prototype submitted to the Unisys Innovation Program 2026. All rights reserved by the team and Manipal Institute of Technology.
