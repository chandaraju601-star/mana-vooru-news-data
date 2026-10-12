// Admin API (runs on Cloudflare, server side).
// Username/password are Cloudflare secrets; data + photos live in D1. Nothing secret reaches the browser.
import type { RequestEvent, RequestHandler } from "@builder.io/qwik-city";
import { deleteItem, getDb, getEnv, listItems, memo, TABLES, upsertItem, type D1, type Table } from "~/lib/db";
import { handleAdminLeads, handleTeam } from "~/lib/team";

const enc = new TextEncoder();
const COOKIE = "ug_session";
const MAX_AGE = 8 * 3600;
type R = { status: number; data?: unknown; res?: Response };

const hex = (b: ArrayBuffer | Uint8Array) =>
  Array.from(new Uint8Array(b as ArrayBuffer)).map((x) => x.toString(16).padStart(2, "0")).join("");
const sha256 = async (s: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));

async function same(a: string, b: string) {
  const x = await sha256(a), y = await sha256(b);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

// random signing key, created once and kept in D1 (not derived from the password)
const secret = (db: D1) => memo("secret", 1e12, () => readSecret(db)); // never changes -> read from D1 once per isolate
async function readSecret(db: D1) {
  let row = await db.prepare("SELECT v FROM settings WHERE k = 'session'").first<{ v: string }>();
  if (!row) {
    const v = hex(crypto.getRandomValues(new Uint8Array(32)));
    await db.prepare("INSERT OR IGNORE INTO settings (k, v) VALUES ('session', ?1)").bind(v).run();
    row = await db.prepare("SELECT v FROM settings WHERE k = 'session'").first<{ v: string }>();
  }
  return row!.v;
}

async function sign(db: D1, text: string) {
  const key = await crypto.subtle.importKey("raw", enc.encode(await secret(db)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(text)));
}

async function isAuthed(ev: RequestEvent, db: D1) {
  const v = ev.cookie.get(COOKIE)?.value;
  if (!v) return false;
  const [exp, sig] = v.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return same(sig, await sign(db, exp));
}

const MIME: Record<string, string> = { jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", webp: "image/webp" };

const validItem = (table: Table, x: any) =>
  x && typeof x === "object" && typeof x.id === "string" && /^[\w-]{1,80}$/.test(x.id) &&
  JSON.stringify(x).length < 100_000 &&
  (table !== "cars" ||
    (typeof x.brand === "string" && typeof x.model === "string" &&
      typeof x.year === "number" && typeof x.price === "number" && typeof x.km === "number"));

async function handle(ev: RequestEvent): Promise<R> {
  const { request, url, params, platform, cookie } = ev;
  const env = getEnv(platform);
  const db = getDb(platform);
  const route = String(params.route || "").replace(/\/$/, "");
  const method = request.method;

  if (!db) return { status: 500, data: { error: "D1 connect cheyyaledu (binding name: DB)" } };

  // ---- public: photos ----
  if (route.startsWith("img/") && method === "GET") {
    const id = route.slice(4);
    if (!/^[a-z0-9]+$/.test(id)) return { status: 404 };
    // photos never change (new upload = new id): serve from Cloudflare's cache and touch D1 only the first time
    const cache = (globalThis as any).caches?.default as Cache | undefined;
    const ckey = new Request(`${url.origin}/api/img/${id}`);
    try { const hit = await cache?.match(ckey); if (hit) return { status: 200, res: hit }; } catch { /* no cache available */ }
    const row = await db.prepare("SELECT mime, data FROM images WHERE id = ?1").bind(id).first<{ mime: string; data: string }>();
    if (!row) return { status: 404, data: { error: "Not found" } };
    const bytes = Uint8Array.from(atob(row.data), (c) => c.charCodeAt(0));
    const res = new Response(bytes, { headers: { "Content-Type": row.mime, "Cache-Control": "public, max-age=31536000, immutable" } });
    try { await cache?.put(ckey, res.clone()); } catch { /* ignore */ }
    return { status: 200, res };
  }

  if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD)
    return { status: 500, data: { error: "ADMIN_USERNAME / ADMIN_PASSWORD secrets add cheyyandi" } };

  // basic CSRF protection
  if (method !== "GET") {
    const origin = request.headers.get("Origin");
    if ((origin && origin !== url.origin) || request.headers.get("X-Requested-With") !== "ugcars")
      return { status: 403, data: { error: "Forbidden" } };
  }

  // employees (separate login, own cookie, time-locked) - see src/lib/team.ts
  if (route.startsWith("team/")) return handleTeam(ev, db, route.slice(5), method);

  if (route === "login" && method === "POST") {
    const b = (await request.json()) as { username?: string; password?: string };
    const u = await same(String(b.username ?? ""), String(env.ADMIN_USERNAME));
    const p = await same(String(b.password ?? ""), String(env.ADMIN_PASSWORD));
    if (u && p) {
      const exp = String(Date.now() + MAX_AGE * 1000);
      cookie.set(COOKIE, `${exp}.${await sign(db, exp)}`, {
        httpOnly: true, secure: true, sameSite: "strict", path: "/api", maxAge: MAX_AGE,
      });
      return { status: 200, data: { ok: true } };
    }
    await new Promise((r) => setTimeout(r, 1000)); // slow down guessing
    return { status: 401, data: { error: "Wrong username or password" } };
  }

  if (route === "logout" && method === "POST") {
    cookie.delete(COOKIE, { path: "/api" });
    return { status: 200, data: { ok: true } };
  }

  if (!(await isAuthed(ev, db))) return { status: 401, data: { error: "Login required" } };

  if (route === "session" && method === "GET") return { status: 200, data: { ok: true } };

  // admin: leads + employees
  if (route.startsWith("leads/") || route.startsWith("emps/")) {
    const r = await handleAdminLeads(ev, db, route, method);
    if (r) return r;
  }

  if (route === "items" && method === "GET") {
    const t = url.searchParams.get("table") as Table;
    if (!TABLES.includes(t)) return { status: 400, data: { error: "Bad table" } };
    return { status: 200, data: { items: await listItems(db, t, true) } };
  }

  if (route === "item" && method === "PUT") {
    const b = (await request.json()) as { table?: Table; item?: any };
    if (!b.table || !TABLES.includes(b.table) || !validItem(b.table, b.item)) return { status: 400, data: { error: "Invalid data" } };
    await upsertItem(db, b.table, b.item);
    return { status: 200, data: { ok: true } };
  }

  if (route === "item" && method === "DELETE") {
    const t = url.searchParams.get("table") as Table;
    const id = url.searchParams.get("id") || "";
    if (!TABLES.includes(t) || !id) return { status: 400, data: { error: "Bad request" } };
    await deleteItem(db, t, id);
    return { status: 200, data: { ok: true } };
  }

  // TEMPORARY: photos are stored in D1. When B2 is ready, only this block changes.
  if (route === "upload" && method === "POST") {
    const b = (await request.json()) as { file?: string; ext?: string };
    const mime = MIME[String(b.ext || "").toLowerCase()];
    if (!mime) return { status: 400, data: { error: "Only jpg / png / webp" } };
    if (!b.file || !/^[A-Za-z0-9+/=]+$/.test(b.file) || b.file.length > 1_500_000)
      return { status: 400, data: { error: "Photo too large (max ~1MB)" } };
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    await db.prepare("INSERT INTO images (id, mime, data, created) VALUES (?1, ?2, ?3, ?4)").bind(id, mime, b.file, Date.now()).run();
    return { status: 200, data: { url: `/api/img/${id}` } };
  }

  return { status: 404, data: { error: "Not found" } };
}

export const onRequest: RequestHandler = async (ev) => {
  let r: R;
  try {
    r = await handle(ev);
  } catch {
    r = { status: 500, data: { error: "Server error" } };
  }
  if (r.res) ev.send(r.res);
  else {
    ev.headers.set("Cache-Control", "no-store");
    ev.json(r.status, r.data ?? {});
  }
};
      
