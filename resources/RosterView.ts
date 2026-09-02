import { Resource, databases } from "harperdb";

/**
 * GET /RosterView — public-safe snapshot of the roster directory for the
 * Office Space (observatory) renderer.
 *
 * Auth: GATED (allowRead requires an authenticated user, 2026-09-02). Field-allowlisted read surface over roster.
 * Security boundary (Sherlock): every field returned here is public-safe.
 *   - Office.publicKey is the office Ed25519 key — EXCLUDED via OFFICE_PUBLIC.
 *   - Member/Event carry no secrets (currentTask/summary are agent-authored,
 *     untrusted free text → the renderer HTML-escapes them on display).
 * Returns: { offices: [...no publicKey], members: [...], events: [recent 50] }.
 */

const OFFICE_PUBLIC = [
	"id",
	"name",
	"status",
	"lastSeen",
	"agentCount",
	"staleThresholdSeconds",
	"createdAt",
	"updatedAt",
];

function pick(obj: any, keys: string[]): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const k of keys) if (obj?.[k] !== undefined) out[k] = obj[k];
	return out;
}

async function scan(table: any): Promise<any[]> {
	const out: any[] = [];
	try {
		for await (const row of table.search()) out.push(row);
	} catch {
		/* empty / not-yet-populated table */
	}
	return out;
}

export class RosterView extends Resource {
	// GATED 2026-09-02 (Nathan: "gate it now", ops-ku7f): authenticated Harper users
	// only. The roster directory exposes internal topology (host names, agent ids,
	// event titles); public read was the June demo posture. Anonymous -> 401.
	allowRead(user: unknown) {
		return Boolean(user);
	}

	async get() {
		const [officesRaw, members, eventsRaw] = await Promise.all([
			scan((databases as any).roster.Office),
			scan((databases as any).roster.Member),
			scan((databases as any).roster.Event),
		]);
		const offices = officesRaw.map((o) => pick(o, OFFICE_PUBLIC));
		const events = eventsRaw
			.sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)))
			.slice(-50);
		return { offices, members, events };
	}
}
