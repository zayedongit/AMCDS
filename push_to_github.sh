#!/usr/bin/env bash
# push_to_github.sh — one-shot script to push AMCDS to
#   https://github.com/zayedongit/AMCDS.git
#
# Run this from your Mac's Terminal:
#   cd ~/Desktop/AMCDS
#   chmod +x push_to_github.sh
#   ./push_to_github.sh
#
# You'll need to be authenticated with GitHub. Easiest options:
#   1. GitHub CLI:        brew install gh && gh auth login
#   2. Personal token:    pasted as the password when prompted
#   3. SSH key:           the script falls back to SSH if HTTPS fails
#
set -e

REPO_URL_HTTPS="https://github.com/zayedongit/AMCDS.git"
REPO_URL_SSH="git@github.com:zayedongit/AMCDS.git"
BRANCH="main"

cd "$(dirname "$0")"

echo "===> 1/6  Cleaning any stale .git/ state"
rm -rf .git

echo "===> 2/6  git init"
git init -b "$BRANCH"

echo "===> 3/6  Configuring identity"
git config user.email "waseem@predlabs.in"
git config user.name "Md Zayed Waseem"

echo "===> 4/6  Adding all files (respecting .gitignore)"
git add -A
echo ""
echo "Files staged:"
git status --short | head -40
echo ""

echo "===> 5/6  Commit"
git commit -m "AMCDS prototype: 5-agent negotiation + classical & quantum-style optimization

- Network topology model with 27 hosts, 8 services, 3 gold-tier SLAs
- 5 specialist agents (Identity, Network, Data, Endpoint, Business Impact)
  - Network agent integrates the existing URL threat detector
  - Business Impact agent has formal SLA veto authority
- 5-phase negotiation protocol (PROPOSAL/CRITIQUE/COUNTER/VETO/CONSENSUS)
- Google OR-Tools CP-SAT classical optimizer
- D-Wave neal QUBO-based quantum-style optimizer (portable to real D-Wave QPU)
- Attack scenario generator (ransomware / lateral movement / insider threat)
- Evaluation harness: AMCDS vs aggressive vs conservative baselines
- Single-file HTML dashboard with D3 network viz + Chart.js benchmark
- run_demo.py end-to-end demo (writes results/demo_report.json)

Headline result across 90 scenarios:
  ~88% reduction in unnecessary service isolation vs aggressive baseline,
  while keeping residual risk an order of magnitude below conservative
  and breaking zero gold-tier SLAs.

For Unisys Innovation Program 2026."

echo "===> 6/6  Push to GitHub"
git remote add origin "$REPO_URL_HTTPS"

# Try HTTPS first; if that fails (auth refused, no token), retry with SSH.
if git push -u origin "$BRANCH"; then
    echo ""
    echo "✅  Pushed to $REPO_URL_HTTPS  (branch: $BRANCH)"
else
    echo ""
    echo "⚠   HTTPS push failed — falling back to SSH remote"
    git remote set-url origin "$REPO_URL_SSH"
    git push -u origin "$BRANCH"
    echo "✅  Pushed via SSH"
fi

echo ""
echo "🎉  Done. Your AMCDS prototype is now at:"
echo "    https://github.com/zayedongit/AMCDS"
