# Release Summary

## Adaptive Research Upgrade

- Added a persistent research ledger that merges retained candidates across CPU and GPU runs instead of leaving each sweep isolated.
- Added adaptive guidance so the toolkit and GPU runner reorder and rebudget search around the strongest transform families, widths, keywords, periods, primers, and corpus documents.
- Added an experiment planner that turns ledger evidence into ranked next runs, concrete strategy targets, and parameter hints.
- Updated the dashboard to show the consensus frontier and recommended next experiments from the shared ledger.

## Current Frontier

- The strongest retained lead is now a hybrid `running_key:official:offset=10 -> periodic_transposition:w17:row->column` candidate.
- Focused fan-out around that lead reinforced widths `17`, `19`, and `28`, with `KRYPTOS`, `BERLIN`, and `ABSCISSA` remaining the strongest seed family.
- The current ledger frontier is concentrated around periodic-transposition, bifid, and running-key interactions rather than a single isolated method.
