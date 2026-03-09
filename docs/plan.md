# Current Slice: Ledger-Driven Experiment Planner

## Goal

Extend the research ledger so Kryptos can:

- synthesize ranked next experiments from retained candidate evidence
- identify promising but underexplored transform families across GPU and CPU runs
- point recommendations at concrete toolkit strategies and seed hints
- expose the planner through the toolkit and dashboard without introducing a second state file

## Why This Slice

The ledger already preserves memory and steers adaptive ordering, but the operator still has to infer the best next run manually. Turning that shared evidence into an explicit planner makes the research loop more compounding: each sweep should not only retain candidates, but also tell us which strategy family deserves the next block of attention.

## Acceptance Criteria

- The ledger summary includes a ranked `experiment_plan` with concrete next experiments.
- Recommendations reflect both evidence strength and underexplored coverage gaps.
- Each recommendation maps to real toolkit strategies plus parameter hints from adaptive guidance.
- `kryptos_toolkit.py` can write a standalone next-experiments JSON artifact.
- The dashboard renders recommended next experiments from the shared ledger summary.
- Tests cover planner ranking and CLI plan export behavior.

## Deferred

- importing historical run directories in bulk
- automated execution of the planner's recommended runs
- exploration recommendations for low-evidence but high-diversity branches
