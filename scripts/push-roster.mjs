// push-roster.mjs — per-office aggregator (first cut, run from rockit).
// Registers each office (admin) then pushes its members + events via the
// REAL Ed25519-signed /IngestEvents path. rockit signs with its real key
// (~/.tps/secrets/rockit-office.key); the other hosts use generated keys here
// until their own host-side aggregators run. No secret values are printed.
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";

const BASE = "https://tps.dtrt.harperfabric.com";
const SEC = resolve(homedir(), ".tps/secrets");
const ADMIN_AUTH = "Basic " + Buffer.from("admin:" + readFileSync(resolve(SEC, "flair.dtrt.fabric"), "utf8").trim()).toString("base64");
const now = () => new Date().toISOString();

// raw 32-byte Ed25519 public key (hex) — Office.publicKey format IngestEvents expects
function rawPubHex(privKey) {
  const spki = crypto.createPublicKey(privKey).export({ type: "spki", format: "der" });
  return Buffer.from(spki.subarray(spki.length - 32)).toString("hex");
}
function signTPS(privKey, officeId, path) {
  const ts = Date.now();
  const nonce = crypto.randomBytes(8).toString("hex");
  const sig = crypto.sign(null, Buffer.from(`${officeId}:${ts}:${nonce}:POST:${path}`), privKey).toString("base64");
  return `TPS-Ed25519 ${officeId}:${ts}:${nonce}:${sig}`;
}
const rockitPriv = crypto.createPrivateKey(readFileSync(resolve(SEC, "rockit-office.key")));
const genKey = () => crypto.generateKeyPairSync("ed25519").privateKey;

const OFFICES = [
  { id: "rockit", name: "Rockit", status: "online", priv: rockitPriv,
    members: [
      { agentId: "flint",    name: "Flint",    role: "Strategy",     type: "agent", status: "active", activity: "planning",  model: "claude-opus-4-8", currentTask: "Wiring live roster data into the Office Space", lastSeen: now() },
      { agentId: "kern",     name: "Kern",     role: "Architecture", type: "agent", status: "active", activity: "reviewing", model: "qwen3-coder",     currentTask: "Reviewing the public read boundary",          lastSeen: now() },
      { agentId: "sherlock", name: "Sherlock", role: "Security",     type: "agent", status: "active", activity: "reviewing", model: "kimi-k2.6",       currentTask: "Auditing the RosterView field allowlist",     lastSeen: now() },
      { agentId: "ember",    name: "Ember",    role: "Implementer",  type: "agent", status: "idle",   activity: "coding",    model: "qwen3-local",     currentTask: "harper-lifecycle smoke",                      lastSeen: now() },
      { agentId: "nathan",   name: "Nathan",   role: "Founder",      type: "human", status: "active", activity: "idle",                                currentTask: "Watching the office park come alive",         lastSeen: now() },
    ],
    events: [
      { id: "e1", kind: "pr_merged",  authorId: "flint", summary: "Roster + Observatory live on tps.dtrt", refId: "obs", scope: "observatory", createdAt: now() },
      { id: "e2", kind: "mail",       authorId: "flint", summary: "spec handoff", targetIds: ["anvil"], createdAt: now() },
    ] },
  { id: "tps-anvil", name: "TPS-Anvil", status: "online", priv: genKey(),
    members: [{ agentId: "anvil", name: "Anvil", role: "Execution", type: "agent", status: "active", activity: "coding", model: "glm-5.1", currentTask: "Implementing the next spec", lastSeen: now() }],
    events: [{ id: "e1", kind: "pr_opened", authorId: "anvil", summary: "PR opened", createdAt: now() }] },
  { id: "pulse", name: "Pulse", status: "online", priv: genKey(),
    members: [{ agentId: "pulse", name: "Pulse", role: "EA", type: "agent", status: "active", activity: "idle", model: "claude", currentTask: "Triaging Nathan's inbox", lastSeen: now() }],
    events: [] },
  { id: "newton", name: "Newton", status: "degraded", priv: genKey(),
    members: [
      { agentId: "quill", name: "Quill", role: "Worker", type: "agent", status: "idle",  activity: "idle",   model: "qwen3", currentTask: "Awaiting dispatch", lastSeen: now() },
      { agentId: "reed",  name: "Reed",  role: "Worker", type: "agent", status: "stale", activity: "coding", model: "qwen3", currentTask: "(heartbeat lost)",   lastSeen: now() },
    ],
    events: [] },
];

async function api(path, opts) {
  const res = await fetch(BASE + path, opts);
  return { status: res.status, text: (await res.text()).slice(0, 140) };
}

// Phase 1: register every office (admin upsert)
for (const o of OFFICES) {
  const office = { id: o.id, name: o.name, publicKey: rawPubHex(o.priv), status: o.status, agentCount: o.members.length, staleThresholdSeconds: 600, createdAt: now(), updatedAt: now() };
  const r = await api(`/Office/${o.id}`, { method: "PUT", headers: { Authorization: ADMIN_AUTH, "Content-Type": "application/json" }, body: JSON.stringify(office) });
  console.log(`register ${o.id.padEnd(10)} → ${r.status} ${r.text}`);
}
// give replication a beat before ingest checks the office exists
await new Promise((r) => setTimeout(r, 3000));
// Phase 2: signed ingest of members + events per office
for (const o of OFFICES) {
  const body = { officeId: o.id, agents: o.members, events: o.events, syncedAt: now() };
  const r = await api("/IngestEvents", { method: "POST", headers: { "X-TPS-Ed25519": signTPS(o.priv, o.id, "/IngestEvents"), "Content-Type": "application/json" }, body: JSON.stringify(body) });
  console.log(`ingest   ${o.id.padEnd(10)} → ${r.status} ${r.text}`);
}
