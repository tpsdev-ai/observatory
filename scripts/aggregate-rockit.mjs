// aggregate-rockit.mjs — live rockit-office aggregator for the TPS Observatory.
//
// Derives REAL state for the rockit-resident agents (flint, kern, sherlock,
// ember + the human Nathan) from local-only signals and POSTs it to the
// deployed Observatory via the Ed25519-signed /IngestEvents path. Run on a
// 30–60s cadence by launchd (ai.tpsdev.observatory-aggregate). This replaces
// the one-shot push-roster.mjs seed (run once 2026-06-11, hence the stale feed).
//
// SCOPE (v1): rockit office ONLY. Pulse is remote (its own host); other offices
// (tps-anvil, newton) keep their seeded snapshots until their host-side
// aggregators run. We never touch their records here.
//
// SECURITY: this feeds a partly-public dashboard (RosterView is public read).
// We push status text ONLY — agent names, presence states, bd issue TITLES,
// PR numbers/titles. NEVER task bodies, mail bodies, secrets, or file contents.
//
// Live signals (all local to rockit):
//   - presence  ← mtime of the newest session .jsonl per agent (Claude project
//                 dir for flint; OpenClaw sessions for kern/sherlock; pi-agent
//                 sessions for ember). <10m active, <3h idle, else stale.
//   - currentTask ← `bd list --status in_progress` issue TITLES (non-secret).
//   - events    ← recent PR state across tpsdev-ai/{flair,cli} mapped to
//                 pr_opened/pr_merged + CI rollup → ci_passed/ci_failed.
//                 Deduped by stable id so re-runs don't re-insert.
//
// No secret values are ever printed or pushed.

import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, statSync, readdirSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { resolve, join } from "node:path";

const BASE = process.env.OBS_BASE ?? "https://tps.dtrt.harperfabric.com";
const OFFICE_ID = "rockit";
const SEC = resolve(homedir(), ".tps/secrets");
const HOME = homedir();
const now = () => new Date().toISOString();
const nowMs = () => Date.now();

// ── presence thresholds (seconds) ──────────────────────────────────────────
// Mirrors the rhythm-agent DARK_MIN=180min convention: a 3h silence = stale.
const ACTIVE_MAX_S = 10 * 60; //   <10m  → active
const IDLE_MAX_S = 3 * 60 * 60; // <3h    → idle  (else → stale)

// ── signing (REUSED from push-roster.mjs — the real rockit-office key) ──────
const rockitPriv = crypto.createPrivateKey(readFileSync(resolve(SEC, "rockit-office.key")));

function signTPS(privKey, officeId, path) {
  const ts = Date.now();
  const nonce = crypto.randomBytes(8).toString("hex");
  const sig = crypto
    .sign(null, Buffer.from(`${officeId}:${ts}:${nonce}:POST:${path}`), privKey)
    .toString("base64");
  return `TPS-Ed25519 ${officeId}:${ts}:${nonce}:${sig}`;
}

// ── presence: newest session-file mtime per agent ──────────────────────────
// Each entry lists candidate dirs (newest matching .jsonl across all wins).
const PRESENCE_SOURCES = {
  flint: [join(HOME, ".claude/projects/-Users-squeued-agents-flint")],
  kern: [join(HOME, ".openclaw/agents/kern/sessions")],
  sherlock: [join(HOME, ".openclaw/agents/sherlock/sessions")],
  ember: [join(HOME, ".pi-agent/sessions"), join(HOME, "agents/ember/.pi-agent/sessions")],
};

// Walk a directory tree (shallow-ish) collecting the newest *.jsonl mtime in
// epoch ms. Skips memory/ and trajectory sidecars to avoid false liveness.
function newestJsonlMtimeMs(dir) {
  let newest = 0;
  let stack = [dir];
  const SEEN_CAP = 5000;
  let visited = 0;
  while (stack.length && visited < SEEN_CAP) {
    const d = stack.pop();
    visited++;
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const p = join(d, e.name);
      if (e.isDirectory()) {
        if (e.name === "memory" || e.name === "node_modules" || e.name === ".git") continue;
        stack.push(p);
      } else if (e.isFile() && e.name.endsWith(".jsonl") && !e.name.includes("trajectory")) {
        try {
          const m = statSync(p).mtimeMs;
          if (m > newest) newest = m;
        } catch {
          /* race: file vanished mid-scan */
        }
      }
    }
  }
  return newest;
}

function presenceFor(agentId) {
  let newest = 0;
  for (const dir of PRESENCE_SOURCES[agentId] ?? []) {
    if (!existsSync(dir)) continue;
    const m = newestJsonlMtimeMs(dir);
    if (m > newest) newest = m;
  }
  if (newest === 0) return { status: "offline", lastSeen: null, ageS: Infinity };
  const ageS = (nowMs() - newest) / 1000;
  let status;
  if (ageS < ACTIVE_MAX_S) status = "active";
  else if (ageS < IDLE_MAX_S) status = "idle";
  else status = "stale";
  return { status, lastSeen: new Date(newest).toISOString(), ageS };
}

// ── currentTask: bd in_progress TITLES (non-secret status text only) ────────
function inProgressTitles() {
  try {
    const out = execFileSync("bd", ["list", "--status", "in_progress", "--json"], {
      cwd: resolve(HOME, "ops"),
      encoding: "utf8",
      timeout: 20_000,
    });
    const arr = JSON.parse(out);
    return Array.isArray(arr) ? arr.map((x) => String(x.title ?? "")).filter(Boolean) : [];
  } catch {
    return [];
  }
}

// Static role/activity/model metadata — presence drives status; activity drives
// the renderer's room assignment (coding|reviewing|planning|idle).
const AGENT_META = {
  flint: { name: "Flint", role: "Strategy", activity: "planning", model: "claude-opus-4-8" },
  kern: { name: "Kern", role: "Architecture", activity: "reviewing", model: "glm-5.2:cloud" },
  sherlock: { name: "Sherlock", role: "Security", activity: "reviewing", model: "deepseek-v4-pro:cloud" },
  ember: { name: "Ember", role: "Implementer", activity: "coding", model: "qwen3-local" },
};

function buildMembers(titles) {
  // Round-robin the in-progress titles across the active agents so the floor
  // shows what's actually being worked, without leaking bodies.
  const members = [];
  const agents = ["flint", "kern", "sherlock", "ember"];
  agents.forEach((id, i) => {
    const p = presenceFor(id);
    const meta = AGENT_META[id];
    // idle/stale agents shouldn't claim a live task; only active agents get one.
    const task =
      p.status === "active" && titles.length ? titles[i % titles.length] : statusTask(p.status);
    members.push({
      agentId: id,
      name: meta.name,
      role: meta.role,
      type: "agent",
      status: p.status,
      activity: p.status === "active" ? meta.activity : "idle",
      model: meta.model,
      currentTask: task,
      lastSeen: p.lastSeen ?? now(),
    });
  });
  // Nathan — human, always rendered at reception. Presence from flint's own
  // session is a poor proxy; mark him idle (he watches, doesn't heartbeat).
  members.push({
    agentId: "nathan",
    name: "Nathan",
    role: "Founder",
    type: "human",
    status: "active",
    activity: "idle",
    currentTask: "Watching the office park",
    lastSeen: now(),
  });
  return members;
}

function statusTask(status) {
  switch (status) {
    case "idle":
      return "Idle — awaiting work";
    case "stale":
      return "(heartbeat lost)";
    case "offline":
      return "Offline";
    default:
      return "";
  }
}

// ── events: recent PR state across flair + cli → renderer event kinds ───────
const REPOS = ["tpsdev-ai/flair", "tpsdev-ai/cli"];

function ghPrs(repo) {
  try {
    const out = execFileSync(
      "gh-as",
      [
        "flint",
        "pr",
        "list",
        "--repo",
        repo,
        "--state",
        "all",
        "--limit",
        "10",
        "--json",
        "number,title,state,mergedAt,createdAt,author,statusCheckRollup",
      ],
      { encoding: "utf8", timeout: 30_000 },
    );
    const arr = JSON.parse(out);
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

// Map a tpsdev-ai login → a rockit agentId so the mail/PR sprite lands on the
// right desk. Unknown authors fall back to "flint" (the office owner).
function authorAgentId(login) {
  const l = String(login ?? "").toLowerCase();
  if (l.includes("kern")) return "kern";
  if (l.includes("sherlock")) return "sherlock";
  if (l.includes("ember")) return "ember";
  if (l.includes("anvil")) return "flint"; // anvil is a different office; attribute its PRs to flint here
  return "flint";
}

function ciRollup(pr) {
  const rollup = Array.isArray(pr.statusCheckRollup) ? pr.statusCheckRollup : [];
  if (!rollup.length) return null;
  const concl = rollup.map((c) => c.conclusion ?? c.state ?? null);
  if (concl.some((c) => c === "FAILURE" || c === "ERROR" || c === "TIMED_OUT")) return "ci_failed";
  if (concl.every((c) => c === "SUCCESS" || c === "SKIPPED" || c === "NEUTRAL" || c == null))
    return "ci_passed";
  return null; // pending — emit nothing
}

function buildEvents() {
  const events = [];
  for (const repo of REPOS) {
    const short = repo.split("/")[1]; // "flair" | "cli"
    for (const pr of ghPrs(repo)) {
      const author = authorAgentId(pr.author?.login);
      const ref = `${short}#${pr.number}`;
      const title = String(pr.title ?? "").slice(0, 120);
      if (pr.state === "MERGED" && pr.mergedAt) {
        // stable id keyed on the merge → only inserted once (server dedups by id)
        events.push({
          id: `pr-merged-${short}-${pr.number}`,
          kind: "pr_merged",
          authorId: author,
          summary: `${ref} merged — ${title}`,
          refId: ref,
          scope: short,
          createdAt: pr.mergedAt,
        });
      } else if (pr.state === "OPEN") {
        events.push({
          id: `pr-opened-${short}-${pr.number}`,
          kind: "pr_opened",
          authorId: author,
          summary: `${ref} opened — ${title}`,
          refId: ref,
          scope: short,
          createdAt: pr.createdAt ?? now(),
        });
        const ci = ciRollup(pr);
        if (ci) {
          // CI id includes the conclusion so a red→green flip emits a new event,
          // but the same state on the same PR won't re-insert (server dedup).
          events.push({
            id: `${ci}-${short}-${pr.number}`,
            kind: ci,
            authorId: author,
            summary: `${ref} CI ${ci === "ci_passed" ? "passed" : "failed"} — ${title}`,
            refId: ref,
            scope: short,
            createdAt: now(),
          });
        }
      }
    }
  }
  // Renderer reacts to the LAST events in feed order; cap to the freshest 20 so
  // a single tick doesn't drown the floor in confetti. Server keeps recent 50.
  events.sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
  return events.slice(-20);
}

// ── POST ───────────────────────────────────────────────────────────────────
async function api(path, opts) {
  const res = await fetch(BASE + path, opts);
  return { status: res.status, text: (await res.text()).slice(0, 200) };
}

async function main() {
  const titles = inProgressTitles();
  const members = buildMembers(titles);
  const events = buildEvents();

  const body = { officeId: OFFICE_ID, agents: members, events, syncedAt: now() };
  const r = await api("/IngestEvents", {
    method: "POST",
    headers: {
      "X-TPS-Ed25519": signTPS(rockitPriv, OFFICE_ID, "/IngestEvents"),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  // Single-line summary (no secrets): presence states + counts + server reply.
  const states = members.map((m) => `${m.agentId}:${m.status}`).join(" ");
  console.log(`[${now()}] ingest rockit → ${r.status} ${r.text} | ${states} | events=${events.length}`);

  // Non-zero exit on hard failure so launchd logs surface it.
  if (r.status !== 200) process.exitCode = 1;
}

main().catch((e) => {
  console.error(`[${now()}] aggregate-rockit failed: ${e.message}`);
  process.exitCode = 1;
});
