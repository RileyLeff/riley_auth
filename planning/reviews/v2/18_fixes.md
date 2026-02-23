# Fixes — Review Round 3 (2026-02-23)

Commit: ba5e228

## Fix Applied

### M1. Config fallback on missing explicit path (codex-only)
`resolve_config` now returns an error immediately when an explicit `--config` path is provided but doesn't exist, instead of silently falling back to environment variables and directory searching.

## No Other Fixes Needed

All remaining findings are repeat observations from prior rounds (already documented in review_notes_README.md) or low-priority quality-of-life improvements for future iterations.
