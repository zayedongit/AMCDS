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

## Quick start

You'll need Python 3.10+ and pip.

```bash
git clone https://github.com/zayedongit/AMCDS.git
cd AMCDS
pip install -r requirements.txt
python run_demo.py
```

The demo:
1. Builds a 27-host enterprise topology with 8 business services and 3 gold-SLA services.
2. Walks through one ransomware, one lateral-movement, and one insider-threat scenario, showing every agent's reasoning and the final classical + quantum solver output.
3. Runs a 45-scenario benchmark against the two automated baselines.
4. Writes `results/demo_report.json`.

Then **open `dashboard/index.html` in your browser** to see:

- The enterprise network with infected (red) and isolated (amber) hosts.
- The full 5-phase agent negotiation log, with every agent's reasoning.
- Classical vs quantum-style solver runtime and isolation set side-by-side.
- A benchmark chart comparing AMCDS to the baselines.

You can also point the dashboard at any scenario in the dropdown.

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
├── run_demo.py                ← single-command demo entry point
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
│   ├── scenarios/generator.py     ← ransomware / lateral / insider
│   └── evaluation/benchmark.py    ← AMCDS vs aggressive vs conservative
│
├── dashboard/index.html       ← single-file HTML + D3 + Chart.js visualisation
├── https-detector/            ← URL-threat ML model used by the Network agent
└── results/                   ← demo_report.json written here
```

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
