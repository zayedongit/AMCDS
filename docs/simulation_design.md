# Simulation Design

## Deterministic Replay

All simulation uses a seed-based RNG hierarchy:
- Global seed → sub-seeds for each module
- Tick-based simulation clock (discrete time steps)
- Events sorted deterministically within each tick
- `_sim` metadata on every event tracks seed, tick, and scenario

## Enterprise Topology

Generated using NetworkX graph:
- 5 subnets (DMZ, Engineering, Finance, HR, Executive)
- 100 hosts distributed by department ratios
- Server/workstation split with OS distribution
- Inter-host connectivity via service dependencies

## User Behavior Profiles

5 behavior profiles with time-weighted activity:
- **Normal**: Standard 9-5 activity
- **Early Bird**: Peak morning activity
- **Night Owl**: Peak evening/night activity
- **Heavy Email**: 45% email activity weight
- **Remote**: Distributed hours, VPN usage

## Telemetry Types

- Authentication (OCSF 3001)
- Network Flows (OCSF 4001)
- HTTP Activity (OCSF 4002)
- File Operations (OCSF 1001)
- Process Activity (OCSF 1007)
- Email Activity (OCSF 6001)
