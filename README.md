# AMCDS — Autonomous Multi-Agent Cyber Defense System

**Business-aware attack containment: five specialist agents negotiate a plan, and a CP-SAT optimizer proves it optimal.**

> Student research prototype · Unisys Innovation Program 2026
> Team: Md Zayed Waseem · Aryan Gautam · Nayandeep Mohanty · Lalit Sampathirao
> Faculty Mentor: Dr. Saurabh Sharma — Manipal Institute of Technology, Bengaluru

---

## The problem

When a breach is detected, a security team has to choose between two bad options.

| Option | What it costs |
|---|---|
| **Isolate aggressively** — cut everything near the infection | services go down, SLAs break, revenue stops |
| **Wait and investigate** — isolate only what is proven | the attacker keeps moving while you look |

On the reference network in this repository, a standard blanket playbook (isolate everything within three network hops of a confirmed compromise) takes **27 of 38 hosts offline and breaks 2.9 gold-tier SLAs per incident** — and 21 of those 27 machines were never compromised. Isolating only what is proven leaves **2.5 compromised hosts online per incident** and contains the attack in barely half of them.

AMCDS treats that as an optimization problem with constraints instead of a judgement call.

---

## How it works

```
  behavioural telemetry ──┐
                          ├──► ThreatAssessment ──► 5 specialist agents
  security sensor alerts ─┘         (evidence +          │
        │                            risk scores)        │  5-phase negotiation
        │                                                │  propose → critique → counter
   IsolationForest                                       │  → veto → consensus
   risk model                                            ▼
                                              candidate isolation set
                                                         │
                            NetworkX graph analysis ──────┤ attack paths, blast radius,
                            (reachability, service deps)  │ containment value
                                                         ▼
                                              OR-Tools CP-SAT optimizer
                                                         │
                                                         ▼
                                             final containment plan
                                             + full decision trace
```

Each layer answers exactly one question:

| Layer | Question |
|---|---|
| ML risk model | *How unusual is this host's behaviour?* |
| Evidence ledger | *What do we actually **know**, and how sure are we?* |
| Five agents + negotiation | *What should we do about it?* |
| NetworkX graph | *What breaks, and what gets protected, if we isolate it?* |
| CP-SAT | *Which subset of the candidates is optimal under the constraints?* |

---

## What it looks like

`make dashboard` opens this at **http://127.0.0.1:8000**. Everything below is a
real run — no mockups.

### 1. The network, and the agents arguing about it

![The enterprise network and the agent panel](docs/images/01-network-and-agents.png)

**On the left is the company's network**, drawn as a map. Every dot is a computer —
staff laptops (`ws-*`), file servers (`file-*`), the login servers every employee
authenticates against (`dc-*`), the application servers (`app-prod-*`) and the
customer databases (`db-prod-*`). Lines between dots mean one machine can reach
the other, which is exactly how an attacker travels.

The colours are the whole story at a glance: **green** = healthy, **red** =
compromised, **amber** = we've disconnected it, a **purple ring** = it holds
personal customer data, a **gold ring** = a business-critical service runs on it
and taking it offline breaks a contract.

**On the right, the five agents think out loud.** This is the moment the
*Endpoint Agent* — the one watching individual machines — reports what it found:

> *"ML risk model active. 0 host(s) carry hard endpoint evidence; 1 further
> host(s) are behaviourally anomalous above the 0.90 risk threshold.
> Proposing 1 host(s)."*

In plain English: *"Nobody has actually been caught red-handed. But one machine —
`jump-01` — is behaving oddly enough that only 10% of normal machines ever look
this strange. I think we should disconnect it."* The bar reads 40% because it is
not confident, and it says so.

Underneath, the **Business Impact Agent** — the one with veto power — gives its
verdict: nothing it needed to block, and the plan costs ₹0.2 lakh an hour with no
contract breaches. That agent is the reason this system won't panic and take the
payments database offline over a hunch.

### 2. The decision, step by step

![The containment timeline](docs/images/02-decision-timeline.png)

**This is the part that matters most, and it's worth reading line by line** —
it's the system explaining every step of its reasoning, timestamped.

The five agents have finished arguing. Then:

- **`12.5s — contested ws-sls-04`** — a genuine disagreement. The *Identity Agent*
  wants to disconnect a sales laptop; the *Network Agent* objects, because the
  attacker can't realistically reach it. Neither one wins by authority. Their
  votes are weighed — support versus objection — and the result is **0.54**, just
  over the halfway line, so it stays on the shortlist. **The system shows you the
  arithmetic instead of asking you to trust it.**

- **`13.3s — CP-SAT engaged`** — the shortlist goes to the optimizer, along with
  the rule it must respect: *don't let this plan cost more than ₹80 lakh an hour*.

- **`14.5s — OPTIMAL — 0 host(s)`** and **`dropped ws-sls-04 — cost exceeded the
  risk removed`** — and here is the interesting bit. **The optimizer decided the
  right answer was to disconnect nothing at all.** The disruption of taking that
  laptop offline was worth more than the risk it removed, so it didn't.

That is the entire point of the project. A blanket security playbook would have
disconnected 27 of 38 machines here. This one looked at a weak signal, did the
arithmetic, and correctly did nothing. It is also honest about that being a
*choice*: the panel shows the attack's real reach was 1 machine, so nothing was
missed.

### 3. Six strategies, side by side

![Strategy comparison](docs/images/03-strategy-comparison.png)

**This is the scoreboard**, and it's how you tell whether any of this actually
works. Six different ways of responding to the same 45 attacks:

| Strategy | In plain terms |
|---|---|
| **Aggressive 3-hop / 2-hop** | *"Something's wrong — unplug everything nearby."* The standard industry playbook. |
| **Conservative** | *"Only unplug what we can prove is infected."* Cautious. |
| **Risk threshold** | *"Unplug whatever the AI model finds suspicious."* The ML model on its own, with no agents. |
| **AMCDS no ML** | The five agents negotiating, but with the AI model switched off. |
| **AMCDS** | The full system. |

Read the top two rows of each card. **"Unnecessary shutdown"** = machines we took
offline that were never infected — the damage we caused. **"Missed threats"** =
infected machines we left running — the damage we allowed. You want both low, and
the two pull against each other.

The aggressive playbook causes **21.42** needless shutdowns per incident. The full
system causes **1.91** while missing fewer threats than the cautious approach
(0.78 vs 2.47). That's why AMCDS is marked **★ OPTIMAL** — it has the best
**F1 score** (0.805), the standard way of scoring something that has to be good at
two opposing things at once.

The last two cards are the honest self-check: *is the AI model actually earning
its place, or is it decoration?* Switching it off drops missed threats from 0.78
to 2.02 — so yes, it earns it, at the cost of slightly more unnecessary shutdowns.
Both numbers are on screen because hiding the trade-off would be dishonest.

### 4. The headline, in one chart

![Benchmark chart](docs/images/04-benchmark-chart.png)

**Yellow bars are damage we caused. Red bars are damage we allowed.** Six
strategies, left to right.

Look at the shape. The first two bars are enormous and yellow — the standard
playbook wrecks the business to be safe. **Conservative** flips it: almost no
yellow, but a tall red bar, because it lets infected machines keep running.
**AMCDS**, on the far right, is the only one where *both* bars are short.

That's the sentence above the chart:

> **AMCDS: 91.1% fewer unnecessary shutdowns than the 3-hop blanket baseline ·
> 48.5% fewer than the anomaly model acting alone**

The first number says the system beats the industry-standard approach. The second
says the negotiating agents and the optimizer are doing real work — you couldn't
get this by running the AI model alone.

---

## The five specialist agents

| Agent | Its domain | Its distinctive move |
|---|---|---|
| **Identity** | credential theft, privilege escalation | objects to isolating domain controllers and jump hosts on suspicion — recommends forced credential rotation instead |
| **Network** | lateral movement | measures how much attack surface each cut removes, and objects to isolating hosts the attacker cannot plausibly reach |
| **Data** | PII and exfiltration | objects when a plan would take *every* replica of a data service offline, turning a breach into an outage |
| **Endpoint** | per-host behaviour and the ML risk score | the evidence sceptic: objects to isolating a host with zero alerts and a low risk score |
| **Business Impact** | service continuity, SLA tiers, INR/hour | holds the **formal veto** |

They disagree by construction. On a typical incident they start with 8 hosts in the union of their proposals and 0 hosts they all agree on.

### The five-phase negotiation

1. **PROPOSE** — each agent produces an isolation set with a per-host justification and a confidence.
2. **CRITIQUE** — every agent reviews *every other agent's* proposal (20 reviews for 5 agents), recording per-host objections, endorsements and additions.
3. **COUNTER** — each agent revises its own proposal against the objections aimed at it. Hosts backed by hard evidence are never conceded.
4. **VETO** — the Business Impact agent applies its formal veto and its budget ceiling. A vetoed host is struck before the optimizer ever sees it.
5. **CONSENSUS** — remaining conflicts are settled by **weighted support**, not by taking a union:

   ```
   support(h)    = Σ confidence × weight  over agents proposing h
   opposition(h) = Σ confidence × weight  over agents objecting to h
   keep(h)       ⟺ support / (support + opposition) ≥ 0.50
   ```

   A host one agent wants and three object to loses. Hosts with hard evidence are pinned in regardless — leaving a proven compromise online is not something the vote gets to decide.

### The formal veto

```
VETO(h)  ⟺  isolating h breaks a gold-tier SLA
             AND  h has no hard evidence of infection
```

**Hard evidence** is a precise, testable predicate (`amcds/evidence.py`): either one high-fidelity detector fired (ransomware canary, EDR malicious process, credential dump, C2 beacon — fidelity ≥ 0.85), or several *independent* medium-fidelity signals combine by noisy-OR to ≥ 0.90 confidence. Repeating the same alert ten times does not corroborate anything, and the ML model is capped below the hard-evidence bar by construction — it can corroborate, never confirm alone.

Hard evidence is the **only** override, and when it fires the waiver is recorded in the trace, so you can always see the rule was evaluated rather than skipped. A second rule caps total hourly revenue impact; when hard-evidence hosts alone already exceed the ceiling, the rule reports that it is unattainable instead of dropping cheap hosts for show.

Real veto text from a benchmark run:

```
VETO db-prod-03: isolating it breaks gold-tier service(s) ['customer_data']
(INR 15.0L/hour) and the evidence is only 0.44 confidence (risk 0.04)
— below the hard-evidence bar
```

---

## The ML layer

Host compromise detection is framed the way a real SOC has to frame it: **you have no labelled attacks on your own network, but you have plenty of quiet days.**

- **Model** — `IsolationForest` (scikit-learn), fitted on 60 attack-free observation windows × 38 hosts = **2,280 rows of clean telemetry**. It never sees a labelled attack, so every benchmark scenario is genuinely held out.
- **Features** — 16 total: 13 behavioural counters (connection volume, distinct peers, new-peer ratio, failed authentications, port diversity, bytes out/in, off-hours ratio, admin process launches, file-operation rate, peer zone diversity, beacon regularity) plus 3 derived ratios (peer saturation, bytes-out-per-peer, connections-per-peer).
- **Peer-group baselining** — every counter is turned into a robust z-score *within its host type*: `z = (x − median_type) / (1.4826 × MAD_type)`. A web server making 1,500 connections is normal; a workstation making 1,500 is not. Medians come from the clean corpus only, so nothing about the incident leaks into the normalisation.
- **Calibration** — the raw IsolationForest score is converted to the empirical benign percentile, so **the score means something and the threshold *is* the nominal false-positive rate**. `risk = 0.90` reads as "only 10% of normal windows look at least this unusual"; a benign host's score is uniform on [0, 1].
- **Interpretability** — every score comes with the three features that drove it:
  `risk 0.99 driven by file_ops_per_min +12.0σ, new_peer_ratio +11.0σ, admin_process_launches +8.8σ vs peer-group baseline`

### ML results (45 scenarios, 1,710 host-windows, 16.7% base rate)

| Metric | Value |
|---|---|
| ROC-AUC | **0.943** |
| PR-AUC (average precision) | **0.758** (random baseline = base rate, 0.167) |
| Precision / Recall / F1 @ 0.90 | 0.595 / 0.856 / 0.702 |
| Recall @ FPR ≤ 1% / 5% / 10% | 0.316 / 0.751 / 0.842 |
| Accuracy | 0.879 — *reported but misleading at this base rate* |

Accuracy is deliberately not the headline: always predicting "clean" scores 83.3% here while catching nothing.

---

## Benchmark results

**45 scenarios** (15 ransomware, 15 lateral movement, 15 insider threat) on the 38-host segmented enterprise. Every strategy sees exactly the same observable inputs — hard evidence and ML risk scores. **None of them receives ground truth.**

```bash
python scripts/run_benchmark.py        # seeds: topology 7, scenarios 2024, ML 1234
```

| Strategy | Unnecessary shutdowns | Missed threats | Isolated | Precision | Recall | **F1** | INR L/hr | Gold SLA breaches | Contained | Decision time |
|---|---|---|---|---|---|---|---|---|---|---|
| AGGRESSIVE_3HOP | 21.42 | 0.44 | 27.31 | 0.216 | 0.930 | 0.350 | 113.1 | 2.93 | 89% | 0.1 ms |
| AGGRESSIVE_2HOP | 15.47 | 0.44 | 21.36 | 0.276 | 0.930 | 0.425 | 102.5 | 2.58 | 89% | 0.1 ms |
| CONSERVATIVE | **0.04** | 2.47 | 3.91 | **0.989** | 0.611 | 0.755 | 32.8 | 0.62 | 51% | 0.0 ms |
| RISK_THRESHOLD *(ML only)* | 3.71 | 0.60 | 9.44 | 0.607 | 0.905 | 0.727 | 66.6 | 1.42 | 80% | 0.0 ms |
| AMCDS_NO_ML *(agents only)* | 1.31 | 2.02 | 5.62 | 0.767 | 0.681 | 0.721 | **26.8** | **0.47** | 60% | 51 ms |
| **AMCDS** *(full pipeline)* | 1.91 | **0.78** | 7.47 | 0.744 | 0.877 | **0.805** | 34.5 | 0.62 | 80% | 88 ms |

**Headline: AMCDS cuts unnecessary shutdowns by 91.1% versus the 3-hop blanket baseline** (21.42 → 1.91 hosts per incident) while missing 68% fewer threats than the conservative approach, and it has the best F1 of any strategy tested.

### Reading the table honestly

Three results deserve to be stated plainly rather than buried:

1. **CONSERVATIVE wins on "unnecessary shutdowns" alone (0.04) — and that is exactly why that metric cannot stand by itself.** Isolating almost nothing trivially minimises it, at the cost of leaving 2.47 compromised hosts online per incident and containing the attack in only 51% of cases. F1 and containment rate are reported for this reason.

2. **The ML layer costs 46% *more* unnecessary shutdowns than the agents alone (1.91 vs 1.31) and is worth it.** It cuts missed threats by 61% (2.02 → 0.78), raises F1 from 0.721 to 0.805 and containment from 60% to 80%. That is a deliberate trade, not an improvement on every axis, and the ablation is in the benchmark so anyone can check.

3. **AMCDS beats the ML model acting alone by 48.5% on unnecessary shutdowns** (3.71 → 1.91) at similar recall. The negotiation and optimizer layers are doing real work, not decorating a classifier.

### Per attack type

| Attack type | AMCDS F1 | Unnecessary | Missed | Contained |
|---|---|---|---|---|
| ransomware | 0.862 | 2.93 | 0.27 | 100% |
| lateral movement | 0.818 | 2.00 | 0.73 | 73% |
| insider threat | **0.333** | 0.80 | 1.33 | 67% |

Insider threat is the honest weak spot: only ~1.9 of 38 hosts are compromised (a 5% base rate), and an insider using legitimate credentials trips almost no high-fidelity sensor. The system leans entirely on the ML layer there, and precision suffers.

### On the 86.7% figure

An earlier version of this project reported an 86.7% reduction. **That number was not reproducible** — the scenario generator iterated over Python `set` objects, and because Python randomises string hashing per process, three runs with the same seed produced 89.1%, 87.6% and 90.3%. It was also measured against a baseline that had been handed the ground-truth infected list, and on a flat topology of diameter 2 where a 3-hop blanket isolated every host by construction.

All three problems are fixed. The **91.1%** above is measured on a segmented network with a fairly-informed baseline, and it is byte-for-byte reproducible across processes and machines. Quote that number, and be ready to explain why it differs.

---

## Quick start

Python 3.10 or newer.

```bash
git clone https://github.com/zayedongit/AMCDS.git
cd AMCDS
python3 -m pip install -r requirements.txt -r requirements-dev.txt
python3 -m pip install -e .

make check         # verify this Python can run AMCDS  <- run this first
make test          # 280 tests, ~8 s
make benchmark     # the 45-scenario benchmark, ~10 s
make demo          # walkthrough + benchmark, writes results/demo_report.json
make dashboard     # http://127.0.0.1:8000
```

Or without `make`:

```bash
python3 scripts/check_env.py
python3 -m pytest tests/ -q
python3 scripts/run_benchmark.py
python3 run_demo.py
python3 serve.py
```

### If you have more than one Python

A machine with both a system Python and an Anaconda install will often have
`python` pointing at the older one. AMCDS needs **3.10+ with NetworkX 3.x**; an
older NetworkX fails deep inside `betweenness_centrality` with
`random_state_index is incorrect`, which does not hint at the real cause.

`make check` diagnoses this in one line. To point `make` at a specific
interpreter:

```bash
make test PYTHON=/usr/local/bin/python3
```

Every `make` target runs `check` first, so a wrong interpreter is caught before
anything else runs.

### Example: one incident, end to end

```
--- DEMO-LM (lateral_movement, 111 min dwell) ---
  seeded on            ['app-prod-05']
  ground truth spread  12 host(s) [evaluation only — the agents never see this]
  detection            12 confirmed (hard evidence), 4 suspected
  PROPOSE              union 14, unanimous 6 -> disagreement 8
  CRITIQUE             3 objection(s), 16 addition(s) across 20 peer reviews
  COUNTER              1 conceded, 7 adopted
  VETO                 1 vetoed, 6 waived on hard evidence
      x db-prod-03: isolating it breaks gold-tier service(s) ['customer_data']
        (INR 15.0L/hour) and the evidence is only 0.44 confidence (risk 0.04)
        — below the hard-evidence bar
  CONSENSUS            13 candidate(s); 1 contested; agreement 0.94
  CP-SAT               OPTIMAL in 1.0 ms -> 13 host(s), INR 151.7L/hour,
                       4 gold-SLA breach(es) [all evidence-backed]
  containment          attack surface 38 -> 0 (100% reduction)
```

### The decision trace

Every host in the final plan can be asked why:

```python
from amcds.network import build_segmented_enterprise
from amcds.ml import train_default_model
from amcds.pipeline import AMCDSPipeline
from amcds.scenarios import ScenarioGenerator

topology = build_segmented_enterprise()
model = train_default_model(topology)
decision = AMCDSPipeline(topology, model).run(
    ScenarioGenerator(topology, seed=2024).ransomware("DEMO"))

print(decision.trace_host("file-eng-01")["narrative"])
```

```
file-eng-01: no detector alerts; ML risk score 0.24. Proposed for isolation by
Network. Objected to by Endpoint. Contested: support 0.85 vs opposition 0.80
(ratio 0.52) -> kept. CP-SAT kept it: leaving it online carried 603
residual-risk units against its share of the business cost. Outcome: ISOLATED.
```

---

## The graph model

`amcds/network/topology.py` maintains three NetworkX structures, each answering a different question.

- **Reachability** (`nx.Graph`) — an edge means host A can open a connection to host B. Every edge carries a `trust` weight in (0, 1]: the modelled probability an attacker on A can pivot to B in one step. Workstation↔workstation SMB is 0.85; workstation→domain controller is a hardened auth channel at 0.10.

  Edges also store `weight = −log(trust)`, so **Dijkstra finds the maximum-probability attack path**: minimising a sum of `−log` maximises a product of trusts. `attack_path("ws-fin-01", "db-prod-01")` returns the route and its probability (0.047 — a production database is genuinely hard to reach from a finance workstation).

- **Service dependency** (`nx.DiGraph`, bipartite) — `service → host` edges, so `predecessors(host)` answers "what breaks if this machine goes offline". Revenue is counted **once per downed service**, not per host.

- **Blast radius** — `blast_radius(sources)` intersects a hop-bounded neighbourhood with the trust-weighted plausible attack surface, and reports hosts at risk, services at risk, gold services among them, INR/hour, and PII stores exposed. `containment_value(isolate, sources)` re-runs the reachability query on the graph with the isolation set deleted, giving a measured "this cut protects N downstream hosts".

Also used: `nx.betweenness_centrality` (how much lateral traffic a host carries), `nx.articulation_points` (choke points), `nx.node_connected_component` (post-isolation reachability), `nx.diameter`.

The reference network has **38 hosts, 104 edges, 13 services, 5 zones and diameter 5**. The earlier flat topology had diameter 2 — every workstation touched both domain controllers — which meant a 3-hop blanket baseline isolated literally every host and made the headline comparison meaningless. A test asserts diameter ≥ 4.

---

## The CP-SAT model

`amcds/optimization/cpsat_solver.py`.

**Variables**
- `x[h] ∈ {0,1}` — isolate host `h`, one per negotiated candidate
- `d[s] ∈ {0,1}` — service `s` is down, linked by `d[s] = max_h x[h]` over the hosts `s` depends on

**Objective**

```
minimise   α · residual_risk  +  β · business_cost

business_cost  = Σ_services  revenue_per_hour[s] · d[s]
residual_risk  = Σ_candidates  risk_weight[h] · (1 − x[h])
risk_weight[h] = criticality[h] · reach[h] · (1 + risk_score[h]) · 500
```

`reach[h]` is the most-probable-path trust from the confirmed foothold. Leaving a critical, easily-reached, behaviourally-anomalous host online is expensive; leaving an unreachable one online is free.

**Hard constraints**

| | Constraint |
|---|---|
| **C1** | every host with hard evidence is isolated |
| **C2** | every gold-tier service keeps at least one non-evidenced host online |
| **C3** | every multi-host service keeps a replica online |
| **C4** | total business cost stays under the hourly ceiling |

C4 is dropped — and the relaxation *reported* in the result — when C1 alone already exceeds the budget. A confirmed compromise of the payments database costs what it costs.

The service indicator variables are the important detail: they make the objective count business cost the same way the evaluation metric does. An earlier version summed per-host revenue, which double-counted every multi-host service and therefore optimised a different quantity from the one it was scored on.

---

## Reproducibility

Everything is seeded and every seed is printed and written into the report.

| Seed | Default | Controls |
|---|---|---|
| topology | 7 | which app servers each department and web server talks to |
| scenario | 2024 | seed hosts, dwell time, propagation, sensor alerts, telemetry |
| ML | 1234 | the attack-free training corpus and the forest |

Each scenario derives its own RNG from `sha256(master_seed : scenario_id)`, so scenario `RW-007` is identical whether you generate 10 scenarios or 1,000, and regenerating one does not shift any other. All iteration is over sorted sequences — never a raw `set`. CP-SAT runs single-threaded with a fixed seed.

Verified: two separate Python processes produce byte-identical isolation plans for all 45 scenarios × 6 strategies.

---

## Testing

```
280 passed, 3 skipped in 8.3 s
```

`tests/amcds/` covers behaviour, not just execution:

| File | What it asserts |
|---|---|
| `test_topology.py` | reachability, service dependencies, blast radius, that Dijkstra really finds the max-probability path, validation rejects malformed graphs |
| `test_evidence.py` | the hard-evidence predicate: one high-fidelity signal qualifies, two medium ones do not, three independent ones do, ten copies of one alert do not |
| `test_agents.py` | each agent's proposals and its domain-specific objections |
| `test_veto.py` | the veto predicate, its hard-evidence override, its absoluteness, and the budget rule |
| `test_negotiation.py` | all five phases, that the result is *not* the union, that a lone supporter loses, that hard evidence is never conceded |
| `test_optimizer.py` | every CP-SAT constraint individually, objective behaviour under varying α/β, determinism, infeasibility |
| `test_ml.py` | peer-group normalisation, calibration ("threshold = false-positive rate"), that ML can never reach the hard-evidence bar |
| `test_scenarios.py` | propagation determinism, that a scenario is independent of batch size, sensor error rates in both directions |
| `test_evaluation.py` | metric definitions, micro vs macro averaging, that no strategy receives ground truth |
| `test_robustness.py` | two-host and star topologies, disconnected graphs, zero-trust edges, tied candidates, empty evidence, malformed input |
| `test_integration.py` | the full path, plus the safety property: **every gold-SLA breach in the final plan is backed by hard evidence** |

Regression guards are marked as such for the specific defects the audit found.

---

## Repository layout

```
AMCDS/
├── amcds/                       ← the system
│   ├── config.py                  every tunable threshold, in one place
│   ├── evidence.py                evidence ledger + the hard-evidence predicate
│   ├── pipeline.py                end-to-end runner + decision traces
│   ├── network/                   NetworkX topology model and the reference builder
│   ├── attack/propagation.py      trust-weighted attack simulation (ground truth)
│   ├── telemetry/                 behavioural telemetry generator
│   ├── detection/                 simulated sensors + evidence/ML fusion
│   ├── ml/                        features, IsolationForest risk model, evaluation
│   ├── agents/                    the five specialist agents
│   ├── negotiation/protocol.py    the five phases
│   ├── optimization/              CP-SAT solver + QUBO annealing control
│   ├── scenarios/generator.py     reproducible scenario generation
│   ├── evaluation/                metric definitions + benchmark harness
│   └── events/timeline.py         paces a decision into a replayable timeline
├── tests/amcds/                 ← 267 tests for the above
├── scripts/run_benchmark.py     ← the seeded benchmark
├── run_demo.py                  ← walkthrough + benchmark → results/demo_report.json
├── serve.py                     ← local dashboard server
├── dashboard/index.html         ← live containment dashboard (D3 + Chart.js)
└── docs/AMCDS_PROJECT_GUIDE.md  ← full study guide
```

---

## What is built, and what is not

**Built and runnable** — everything under `amcds/`, the tests, the benchmark, the dashboard. It runs in-memory on local Python data structures: no Kafka, no Ray, no Docker, no databases.

**Specified but not built** — `docs/architecture.md`, `docker-compose.yml`, `messaging/`, `database/`, `simulation/`, `agents/`, `attack_engine/`, `dashboard/frontend/`. This is a distributed scaling design (Kafka telemetry streaming, Ray detection actors, Neo4j/PostgreSQL/Redis persistence) with topic definitions and init scripts. **The prototype does not use any of it.** It is kept because it documents the intended production path, but do not present it as working software.

**Not part of the pipeline** — `https-detector/` is an earlier standalone URL-reputation classifier (TF-IDF + Random Forest). The current Network agent does not call it. It is left in the repository as a separate artefact.

**Honest limitations** — see `docs/AMCDS_PROJECT_GUIDE.md`. The short version: telemetry and attack propagation are simulated, not real captured traffic; the ML result measures separability under this generative model, not on production data; the topology is one 38-host network; agent weights are uniform and hand-set; the system decides *what* to isolate, never actually isolates anything.

**On "quantum"** — an earlier version of this project described its second optimizer as quantum-accelerated. It is not. `amcds/optimization/annealing_solver.py` builds a QUBO and solves it with D-Wave's `neal`, a **classical** simulated annealer running on the CPU. The QUBO form is what an annealer expects, so the formulation is annealer-ready; the execution is entirely classical. It is kept as a control that shows what a metaheuristic costs you against CP-SAT's provable optimality.

---

## Documentation

- **[`docs/AMCDS_PROJECT_GUIDE.md`](docs/AMCDS_PROJECT_GUIDE.md)** — the study guide: every concept from first principles, the end-to-end execution flow, the real numbers, and nine stated limitations.
- **`docs/architecture.md`, `docs/agent_design.md`** — the distributed blueprint (specification, not implementation).

## License

Prototype submitted to the Unisys Innovation Program 2026. All rights reserved by the team and Manipal Institute of Technology.
