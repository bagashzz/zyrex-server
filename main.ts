// ZyrexAi License Server — Deno Deploy + Deno KV
const kv = await Deno.openKv();
const E = new TextEncoder();
const u8 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64 = (a: Uint8Array) => { let s = ""; for (const x of a) s += String.fromCharCode(x); return btoa(s); };
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Authorization,Content-Type", "Access-Control-Allow-Methods": "GET,POST,OPTIONS" };
const J = (c: number, o: unknown) => new Response(c === 204 ? null : JSON.stringify(o), { status: c, headers: { "Content-Type": "application/json", ...CORS } });
const now = () => Math.floor(Date.now() / 1000);
const norm = (s: unknown) => String(s || "").trim().toUpperCase();
const env = (k: string) => Deno.env.get(k) || "";
type Lic = { created?: number; name?: string; exp?: number; revoked?: boolean; last?: number; ip?: string };

// WebCrypto menghasilkan r||s; Java butuh DER
function der(sig: Uint8Array) {
  const i = (a: Uint8Array) => { const x = [...a]; while (x.length > 1 && x[0] === 0) x.shift(); if (x[0] & 128) x.unshift(0); return [2, x.length, ...x]; };
  const r = i(sig.slice(0, 32)), s = i(sig.slice(32));
  return new Uint8Array([48, r.length + s.length, ...r, ...s]);
}
let KEY: CryptoKey | undefined;
async function sign(str: string) {
  KEY = KEY || await crypto.subtle.importKey("pkcs8", u8(env("PRIVATE_KEY").trim()), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  return b64(der(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, KEY, E.encode(str)))));
}
async function same(a: string, b: string) {
  const h = async (x: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", E.encode(x)));
  const x = await h(a), y = await h(b); let d = 0; for (let i = 0; i < 32; i++) d |= x[i] ^ y[i]; return d === 0;
}
const get = async (s: string) => (await kv.get<Lic>(["lic", s])).value;
const put = (s: string, o: Lic) => kv.set(["lic", s], o);
async function all() {
  const out: Record<string, unknown>[] = [];
  for await (const e of kv.list<Lic>({ prefix: ["lic"] })) out.push({ serial: e.key[1], ...e.value });
  return out.sort((a, b) => ((b.created as number) || 0) - ((a.created as number) || 0));
}

Deno.serve(async (q: Request) => {
  const u = new URL(q.url).pathname;
  if (q.method === "OPTIONS") return J(204, null);
  if (u === "/health") return J(200, { ok: true });
  if (!env("PRIVATE_KEY") || !env("ADMIN_TOKEN")) return J(500, { ok: false, reason: "server_not_configured" });
  let j: Record<string, unknown> = {};
  if (q.method === "POST") { try { const t = await q.text(); j = t ? JSON.parse(t) : {}; } catch (_e) { return J(400, { error: "json" }); } }
  const ip = (q.headers.get("x-forwarded-for") || "").split(",")[0].trim(), GRACE = (+env("GRACE_HOURS") || 72) * 3600, s = norm(j.serial);
  if (u === "/api/check" && q.method === "POST") {
    const n = String(j.nonce || "").slice(0, 64);
    if (!s || !n) return J(400, { ok: false, reason: "bad_request" });
    const l = await get(s);
    if (!l) return J(200, { ok: false, reason: "not_licensed" });
    if (l.revoked) return J(200, { ok: false, reason: "revoked" });
    if (l.exp && l.exp < now()) return J(200, { ok: false, reason: "expired" });
    if (!l.last || now() - l.last > 21600) { l.last = now(); l.ip = ip; await put(s, l); }
    const iat = now(), exp = l.exp || iat + 315360000;
    return J(200, { ok: true, serial: s, nonce: n, iat, exp, grace: GRACE, sig: await sign([s, n, iat, exp, GRACE].join("|")) });
  }
  if (u.startsWith("/admin/")) {
    const a = (q.headers.get("authorization") || "").replace(/^Bearer /, "");
    if (!await same(a, env("ADMIN_TOKEN"))) return J(401, { error: "auth" });
    if (u === "/admin/licenses" && q.method === "GET") return J(200, await all());
    if (u === "/admin/licenses" && q.method === "POST") {
      if (!/^[A-Z0-9._\-]{4,64}$/.test(s)) return J(400, { error: "serial tidak valid" });
      const days = Math.max(0, Math.floor(+(j.days as number) || 0)), o: Lic = await get(s) || { created: now(), name: "" };
      if (days === 0) o.exp = 0; else { const base = o.exp && o.exp > now() ? o.exp : now(); o.exp = base + days * 86400; }
      if (j.name !== undefined) o.name = String(j.name).slice(0, 60);
      o.revoked = false; await put(s, o); return J(200, { ok: true });
    }
    const m = u.match(/^\/admin\/licenses\/(revoke|unrevoke|delete)$/);
    if (m && q.method === "POST") {
      const o = await get(s); if (!o) return J(404, { error: "tidak ada" });
      if (m[1] === "delete") await kv.delete(["lic", s]); else { o.revoked = m[1] === "revoke"; await put(s, o); }
      return J(200, { ok: true });
    }
  }
  return J(404, { error: "not found" });
});
