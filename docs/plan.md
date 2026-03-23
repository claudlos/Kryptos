# Kryptos current plan

Goal
- Integrate strategies 33-36 into the structured toolkit.
- Expand Strategy 32 beyond the initial local-note sweep.
- Add a combined transposition + unknown-source running-key lane.

Assumptions
- Keep standalone scripts 33-36 intact where practical; prefer thin wrappers into the toolkit over risky rewrites.
- "More source texts" means both additional repo-local text artifacts and already-packaged corpus documents, plus solved-panel plaintext references where useful.
- Combined-lane search should stay bounded and reviewable rather than attempting a huge exhaustive cross-product.

Acceptance criteria
- `kryptos_toolkit.py --list-strategies` includes 33-37.
- Strategies 33-37 are runnable through the toolkit without import-time crashes.
- Strategy 32 scans a broader source set than the initial seven local markdown files.
- Combined lane produces structured output and evidence for whether transposition + unknown-source running key is promising.
- Targeted tests pass.

Planned slices
1. Add shared helpers for loading running-key source material and bridging standalone scripts.
2. Register and expose 33-36 through toolkit-compatible wrapper modules.
3. Expand Strategy 32 to use broader source material.
4. Implement Strategy 37 for bounded transposition + unknown-source running-key search.
5. Validate with targeted tests and update handoff.
