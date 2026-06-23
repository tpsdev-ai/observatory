# Observatory deploy artifacts

## rockit-office aggregator

`../scripts/aggregate-rockit.mjs` derives **live** state for the rockit-resident
agents and POSTs it to the deployed Observatory (`/IngestEvents`) on a cadence,
replacing the one-shot `push-roster.mjs` seed (run once 2026-06-11, which left
the feed frozen).

### What it pushes (rockit office only)

- **Member presence** — newest session `*.jsonl` mtime per agent:
  - `flint` → `~/.claude/projects/-Users-squeued-agents-flint`
  - `kern`, `sherlock` → `~/.openclaw/agents/<name>/sessions`
  - `ember` → `~/.pi-agent/sessions` (and `~/agents/ember/.pi-agent/sessions`)
  - Thresholds: `<10m` → **active**, `<3h` → **idle**, else → **stale**.
- **currentTask** — `bd list --status in_progress` issue **titles** (non-secret).
- **Events** — recent PR state across `tpsdev-ai/{flair,cli}` mapped to
  `pr_opened` / `pr_merged` + CI rollup → `ci_passed` / `ci_failed`, deduped by
  stable event id (the server dedups by `{officeId}:{id}`).

Security: pushes status text only (names, presence states, bd titles, PR
numbers/titles). Never task bodies, mail bodies, secrets, or file contents.
`RosterView` excludes `Office.publicKey` from public reads.

### Install (rockit / launchd)

```sh
cp deploy/ai.tpsdev.observatory-aggregate.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/ai.tpsdev.observatory-aggregate.plist
```

Runs every 60s (comfortably above the endpoint's 10s rate limit).
Logs: `~/.tps/logs/observatory-aggregate-{stdout,stderr}.log`.

Signing key: `~/.tps/secrets/rockit-office.key` (the real rockit-office Ed25519
key, registered as `Office.rockit.publicKey`). Not in this repo.
