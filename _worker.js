// Qvmpxt edge backend: Cloudflare Pages (_worker.js) with Cloudflare D1 + two KV namespaces.
//
// Bindings (Pages -> Settings -> Bindings):
//   DB        D1 database (required)
//   QV_KV     KV namespace "qvmpxt-kv"    (email/reset tokens, WebAuthn challenges, login lockout, translation cache)
//   QV_VAULT  KV namespace "qvmpxt-vault" (E2EE vault: ciphertext only, the server never sees keys)
//   ASSETS    added automatically by Pages (serves qvmpxt.html or index.html)
// Secrets / vars:
//   JWT_SECRET (required, 16+ chars), OWNER_EMAIL, PUBLIC_URL, WEBAUTHN_RP_ID, MAIL_WEBHOOK_URL, MAIL_WEBHOOK_SECRET,
//   ANTHROPIC_API_KEY (+ optional MODEL), STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_<PLAN>[_YEARLY],
//   GOOGLE_CLIENT_ID, GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET, BKASH_NUMBER, NAGAD_NUMBER, ROCKET_NUMBER,
//   BTC_LIGHTNING_ADDRESS, TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID, SENTRY_DSN, ALLOWED_ORIGIN, BRAND, GLOSSARY_EXTRA, I18N_DAILY_MAX
//
// Team workspace: an accepted team member works inside the owner's workspace. Agents, quotes, runs, OCR logs and history are
// stored under the owner's id (table ws_docs for synced client data), so every member sees the same data pool.
// Roles are enforced here on every request: Admin = everything; Editor = create/edit/run/publish; Viewer = read only.
// Audit: table audit_log is append-only (SQLite triggers block UPDATE/DELETE) and hash-chained per workspace.
// Tables are created and migrated automatically on first request.

const DEFAULT_BRAND = 'Qvmpxt';
const DEFAULT_MAIL_URL = 'https://script.google.com/macros/s/AKfycbzxOGdviKa2lx37zMt05wcdpbdQDOF8nABuwhotl9hjO1ehUyitlPZpdBw_uVeYrkOS/exec';
const PLANS = {
  starter: { price: 9, yearly: 89, runs: 300, keys: 3, seats: 5, bdt: [990, 9900], btc: [0.00009, 0.0009] },
  growth: { price: 29, yearly: 289, runs: 2000, keys: 10, seats: 15, bdt: [2990, 28900], btc: [0.0003, 0.0028] },
  enterprise: { price: 99, yearly: 989, runs: 20000, keys: 9999, seats: 9999, bdt: [9900, 98900], btc: [0.001, 0.01] },
};
const FREE = { runs: 50, keys: 1, seats: 2 };
const RATE_LIMITS = { free: 30, starter: 60, growth: 300, enterprise: 1200 };
const COMMISSION_PCT = 15, MOBILE = ['bkash', 'nagad', 'rocket'], CURRENCIES = ['USD', 'BDT'], ROLES = ['Admin', 'Editor', 'Viewer'];
const TOKEN_TTL = 864e5, PBKDF2_ITER = 100000, RATE_PER_1K = 0.002, HISTORY_PER_USER = 300;
const HISTORY_TYPES = ['run', 'quote', 'invoice', 'audit', 'ocr', 'voice', 'note'], CLIENT_TYPES = ['voice', 'note'];
const DOC_KINDS = ['agent', 'share', 'hist'];
const TOOL_NAMES = ['create_quotation', 'generate_invoice', 'audit_dataset', 'save_memory', 'recall_memory', 'send_webhook'];
const RTL_LANGS = new Set(['ar', 'he', 'fa', 'ur', 'ps', 'sd', 'ug', 'yi', 'dv', 'ckb', 'syr', 'arc', 'ks', 'azb', 'nqo', 'rhg']);
const GLOSSARY = ['Google Authenticator', 'Zero-Knowledge', 'AES-256-GCM', 'AI Agent', 'API Key', 'Passkey', 'WebAuthn', 'Webhook', 'Bitcoin', 'Lightning', 'OpenAI', 'DeepSeek', 'Anthropic', 'Claude', 'Stripe', 'bKash', 'Nagad', 'Rocket', 'Telegram', 'GitHub', 'Google', 'QVMPXT', 'Qvmpxt', 'SOC 2', 'PBKDF2', 'E2EE', 'TOTP', 'JWT', 'OCR', 'PDF', 'USD', 'BDT', 'BTC', 'sats'];
const enc = new TextEncoder(), dec = new TextDecoder();

// ---------- helpers ----------
const b64u = (buf) => { let s = ''; for (const b of new Uint8Array(buf)) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const rid = (n = 6) => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const fail = (status, error, extra) => json({ error, ...extra }, status);
const httpErr = (status, message, extra) => Object.assign(new Error(message), { status, extra });
const safeEq = (a, b) => { a = String(a); b = String(b); if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const emailOk = (e) => /^\S+@\S+\.\S+$/.test(e || '') && e.length <= 120;
const phoneOk = (s) => /^[+\d][\d\s()-]{6,19}$/.test(s || '');
const lnAddrOk = (s) => /^[\w.+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(s || '');
const langOk = (s) => /^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8}){0,2}$/.test(s || '');
const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
const brandOf = (env) => env.BRAND || DEFAULT_BRAND;
const baseOf = (env, url) => (env.PUBLIC_URL || url.origin).replace(/\/+$/, '');
const intParam = (v, def, min, max) => { const n = parseInt(v, 10); return Number.isFinite(n) ? clamp(n, min, max) : def; };
const parse = (s, d) => { try { return JSON.parse(s) ?? d; } catch { return d; } };
const ub = (s, max = 20000) => { s = String(s || ''); if (!s || s.length > max || !/^[A-Za-z0-9_-]+={0,2}$/.test(s)) throw httpErr(400, 'Invalid encoding'); try { return unb64u(s); } catch { throw httpErr(400, 'Invalid encoding'); } };
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
const PRIVATE_HOST = /^(localhost|.*\.localhost|.*\.local|.*\.internal|127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|\[|\d+$|0x)/i;
const validHookUrl = (s) => { try { const u = new URL(s); return /^https?:$/.test(u.protocol) && !u.username && !u.password && !PRIVATE_HOST.test(u.hostname); } catch { return false; } };
const money = (n, cur) => (cur === 'BDT' ? '৳' : '$') + Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

// ---------- D1 access ----------
const one = (env, sql, ...a) => env.DB.prepare(sql).bind(...a).first();
const all = async (env, sql, ...a) => (await env.DB.prepare(sql).bind(...a).all()).results || [];
const run = (env, sql, ...a) => env.DB.prepare(sql).bind(...a).run();

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY,name TEXT,phone TEXT DEFAULT '',cur TEXT DEFAULT 'USD',salt TEXT DEFAULT '',hash TEXT DEFAULT '',social TEXT DEFAULT '',plan TEXT DEFAULT 'free',plan_until INTEGER DEFAULT 0,used INTEGER DEFAULT 0,tokens INTEGER DEFAULT 0,cost REAL DEFAULT 0,period TEXT DEFAULT '',company TEXT DEFAULT '',addr TEXT DEFAULT '',pay_json TEXT DEFAULT '{}',totp_secret TEXT DEFAULT '',totp_on INTEGER DEFAULT 0,stripe_customer TEXT DEFAULT '',created INTEGER)`,
  `CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY,owner TEXT,name TEXT,prompt TEXT,tools TEXT DEFAULT '[]',rent_until INTEGER DEFAULT 0,created INTEGER)`,
  `CREATE INDEX IF NOT EXISTS ix_agents_owner ON agents(owner)`,
  `CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,owner TEXT,agent TEXT,input TEXT,output TEXT,steps TEXT,tokens INTEGER,cost REAL,gateway TEXT,ms INTEGER,at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS ix_runs_owner ON runs(owner,at)`,
  `CREATE TABLE IF NOT EXISTS history(id TEXT PRIMARY KEY,owner TEXT,type TEXT,title TEXT,summary TEXT,detail TEXT,at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS ix_history_owner ON history(owner,at)`,
  `CREATE TABLE IF NOT EXISTS quotes(id TEXT PRIMARY KEY,owner TEXT,kind TEXT DEFAULT 'quote',title TEXT,client TEXT,client_email TEXT DEFAULT '',currency TEXT DEFAULT 'USD',items TEXT,tax REAL DEFAULT 0,total REAL,sats INTEGER DEFAULT 0,notes TEXT DEFAULT '',status TEXT DEFAULT 'sent',views INTEGER DEFAULT 0,signups INTEGER DEFAULT 0,accepted_by TEXT DEFAULT '',accepted_at INTEGER DEFAULT 0,paid_at INTEGER DEFAULT 0,created INTEGER)`,
  `CREATE INDEX IF NOT EXISTS ix_quotes_owner ON quotes(owner,created)`,
  `CREATE TABLE IF NOT EXISTS keys(hash TEXT PRIMARY KEY,id TEXT,owner TEXT,hint TEXT,created INTEGER)`,
  `CREATE TABLE IF NOT EXISTS hooks(owner TEXT PRIMARY KEY,url TEXT,secret TEXT)`,
  `CREATE TABLE IF NOT EXISTS teams(email TEXT PRIMARY KEY,owner TEXT,role TEXT,accepted INTEGER DEFAULT 0,invited INTEGER)`,
  `CREATE INDEX IF NOT EXISTS ix_teams_owner ON teams(owner)`,
  `CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY,ukey TEXT UNIQUE,kind TEXT,txid TEXT,provider TEXT,plan TEXT DEFAULT '',cycle TEXT DEFAULT '',quote_id TEXT DEFAULT '',amount REAL,currency TEXT,email TEXT,payer TEXT DEFAULT '',status TEXT DEFAULT 'pending',reviewed_by TEXT DEFAULT '',at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS feedback(id TEXT PRIMARY KEY,type TEXT,name TEXT,email TEXT,message TEXT,at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS market(id TEXT PRIMARY KEY,by TEXT,email TEXT,name TEXT,task TEXT,tools TEXT DEFAULT '[]',buy REAL,rent REAL,sales INTEGER DEFAULT 0,created INTEGER)`,
  `CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,item TEXT,mode TEXT,buyer TEXT,seller TEXT,gross REAL,fee REAL,net REAL,settled INTEGER DEFAULT 0,at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS agent_memory(id TEXT PRIMARY KEY,owner TEXT,agent_id TEXT,note TEXT,at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS ix_mem ON agent_memory(owner,agent_id,at)`,
  `CREATE TABLE IF NOT EXISTS passkeys(id TEXT PRIMARY KEY,owner TEXT,jwk TEXT,counter INTEGER DEFAULT 0,name TEXT DEFAULT '',created INTEGER)`,
  `CREATE INDEX IF NOT EXISTS ix_passkeys_owner ON passkeys(owner)`,
  // shared team data pool (soft deletes so every member learns about removals)
  `CREATE TABLE IF NOT EXISTS ws_docs(owner TEXT,kind TEXT,id TEXT,data TEXT,by TEXT,at INTEGER,del INTEGER DEFAULT 0,PRIMARY KEY(owner,kind,id))`,
  `CREATE INDEX IF NOT EXISTS ix_ws_docs_at ON ws_docs(owner,at)`,
  // immutable audit trail: append-only, hash-chained per workspace
  `CREATE TABLE IF NOT EXISTS audit_log(seq INTEGER PRIMARY KEY AUTOINCREMENT,owner TEXT,at INTEGER,actor TEXT,action TEXT,target TEXT,prev TEXT,hash TEXT)`,
  `CREATE INDEX IF NOT EXISTS ix_audit_owner ON audit_log(owner,seq)`,
  `CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT,'audit_log is append-only'); END`,
  `CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT,'audit_log is append-only'); END`,
];
const MIGRATIONS = [
  ['email_verified', `ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0`],
  ['tv', `ALTER TABLE users ADD COLUMN tv INTEGER DEFAULT 0`],
  ['recovery', `ALTER TABLE users ADD COLUMN recovery TEXT DEFAULT '[]'`],
];
const SYSTEM_AGENTS = [
  ['sys-quote', 'Quotation Drafter', 'You turn a plain-language job description into a professional itemized quotation. Always call create_quotation with sensible line items and prices, then reply with the link and a one-line summary. If prices are missing, ask for them instead of inventing numbers.', ['create_quotation', 'save_memory', 'recall_memory']],
  ['sys-invoice', 'Invoice Generator', 'You create invoices from the details the user gives. Call generate_invoice with the exact items and amounts provided. Never invent amounts.', ['generate_invoice', 'recall_memory']],
  ['sys-audit', 'Compliance Auditor', 'You audit datasets. When the user pastes records (JSON array with id, amount, date, approvedBy), call audit_dataset and explain the findings in plain language, highest risk first.', ['audit_dataset']],
  ['sys-triage', 'Support Triage', 'Classify the message by urgency (high, medium, low) and draft a short, polite reply.', []],
  ['sys-notify', 'Webhook Notifier', 'You send the user a short notification to their saved webhook endpoint. Call send_webhook with a clear one or two sentence message, then confirm whether delivery succeeded. If it failed, say why.', ['send_webhook']],
];
let READY = null;
function ensureSchema(env) {
  if (!READY) READY = (async () => {
    await env.DB.batch(SCHEMA.map((s) => env.DB.prepare(s)));
    const cols = ((await env.DB.prepare("SELECT name FROM pragma_table_info('users')").all()).results || []).map((r) => r.name);
    for (const [col, ddl] of MIGRATIONS) if (!cols.includes(col)) await env.DB.prepare(ddl).run();
    await env.DB.prepare("UPDATE users SET email_verified=1 WHERE social!='' AND email_verified=0").run();
    await env.DB.batch(SYSTEM_AGENTS.map(([id, name, prompt, tools]) => env.DB.prepare(`INSERT OR IGNORE INTO agents(id,owner,name,prompt,tools,created) VALUES(?,?,?,?,?,?)`).bind(id, 'system', name, prompt, JSON.stringify(tools), Date.now())));
  })().catch((e) => { READY = null; throw e; });
  return READY;
}

// ---------- KV helpers ----------
const kv = (env) => { if (!env.QV_KV) throw httpErr(503, 'KV namespace QV_KV is not bound to this project'); return env.QV_KV; };
const vaultKv = (env) => { if (!env.QV_VAULT) throw httpErr(503, 'KV namespace QV_VAULT is not bound to this project'); return env.QV_VAULT; };
async function mintToken(env, prefix, value, ttl) { const t = rid(24); await kv(env).put(`${prefix}:${await sha(t)}`, JSON.stringify(value), { expirationTtl: Math.max(60, ttl) }); return t; }
async function peekToken(env, prefix, t) { t = String(t || ''); if (!/^[a-f0-9]{48}$/.test(t)) return null; return parse(await kv(env).get(`${prefix}:${await sha(t)}`), null); }
async function dropToken(env, prefix, t) { await kv(env).delete(`${prefix}:${await sha(String(t))}`); }
async function takeKv(env, key) { const v = await kv(env).get(key); if (v) await kv(env).delete(key); return parse(v, null); }
async function cooldown(env, key, sec) { if (await kv(env).get(key)) return true; await kv(env).put(key, '1', { expirationTtl: Math.max(60, sec) }); return false; }

// ---------- crypto: PBKDF2, JWT (HS256), TOTP ----------
const secretOf = (env) => { if (!env.JWT_SECRET || env.JWT_SECRET.length < 16) throw httpErr(500, 'Server is missing JWT_SECRET (16+ characters)'); return env.JWT_SECRET; };
async function hmacRaw(secret, data, hash = 'SHA-256') {
  const k = await crypto.subtle.importKey('raw', typeof secret === 'string' ? enc.encode(secret) : secret, { name: 'HMAC', hash }, false, ['sign']);
  return crypto.subtle.sign('HMAC', k, typeof data === 'string' ? enc.encode(data) : data);
}
const hmac = async (secret, data) => b64u(await hmacRaw(secret, data));
async function hashPw(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: PBKDF2_ITER, hash: 'SHA-256' }, k, 256));
}
// "v" is a per-user token version: bumping it signs the user out everywhere. Every request re-checks signature, expiry and version.
async function signToken(env, email, tv = 0) {
  const h = b64u(enc.encode('{"alg":"HS256","typ":"JWT"}')), now = Date.now();
  const body = b64u(enc.encode(JSON.stringify({ sub: email, v: tv | 0, iat: now, exp: now + TOKEN_TTL })));
  return `${h}.${body}.${await hmac(secretOf(env), h + '.' + body)}`;
}
async function verifyToken(env, tok) {
  const [h, b, s] = String(tok).split('.');
  if (!h || !b || !s || !safeEq(s, await hmac(secretOf(env), h + '.' + b))) return null;
  const hd = parse(dec.decode(unb64u(h)), null); if (!hd || hd.alg !== 'HS256') return null;
  const p = parse(dec.decode(unb64u(b)), null);
  return p && p.exp > Date.now() && p.iat <= Date.now() + 60000 ? { sub: p.sub, v: p.v | 0 } : null;
}
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(bytes) { let bits = '', out = ''; for (const b of bytes) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; }
function b32dec(s) { let bits = ''; for (const c of s.replace(/=+$/, '').toUpperCase()) { const i = B32.indexOf(c); if (i < 0) throw new Error('bad base32'); bits += i.toString(2).padStart(5, '0'); } const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return new Uint8Array(out); }
async function totpAt(secret, step) {
  const msg = new DataView(new ArrayBuffer(8)); msg.setUint32(0, Math.floor(step / 4294967296)); msg.setUint32(4, step >>> 0);
  const h = new Uint8Array(await hmacRaw(b32dec(secret), msg.buffer, 'SHA-1')), o = h[19] & 15;
  return String(((h[o] & 127) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).padStart(6, '0');
}
async function totpOk(secret, code) {
  code = String(code || '').replace(/\s/g, ''); if (!/^\d{6}$/.test(code) || !secret) return false;
  const st = Math.floor(Date.now() / 30000); let ok = false;
  for (const d of [-1, 0, 1]) if (safeEq(await totpAt(secret, st + d), code)) ok = true;
  return ok;
}
async function secondFactor(env, u, code) {
  if (await totpOk(u.totp_secret, code)) return true;
  const c = String(code || '').toUpperCase().replace(/[\s-]/g, ''); if (c.length < 8) return false;
  const list = parse(u.recovery, []), i = list.indexOf(await sha('rc:' + c));
  if (i < 0) return false;
  list.splice(i, 1); await run(env, 'UPDATE users SET recovery=? WHERE email=?', JSON.stringify(list), u.email); return true;
}
async function newRecoveryCodes() {
  const codes = Array.from({ length: 8 }, () => [...crypto.getRandomValues(new Uint8Array(10))].map((x) => B32[x % 32]).join(''));
  return { codes: codes.map((c) => c.slice(0, 5) + '-' + c.slice(5)), hashes: await Promise.all(codes.map((c) => sha('rc:' + c))) };
}

// ---------- rate limiting (per isolate; add Cloudflare rate-limit rules for a global limit) ----------
const HITS = new Map();
function limited(req, bucket, max, windowMs) {
  const ip = req.headers.get('cf-connecting-ip') || 'local', k = bucket + ':' + ip, now = Date.now(), h = HITS.get(k);
  if (HITS.size > 5000) HITS.clear();
  if (!h || now - h.t > windowMs) { HITS.set(k, { t: now, n: 1 }); return false; }
  return ++h.n > max;
}

// ---------- notifications, mail, error reporting ----------
const background = (ctx, job) => { const p = Promise.resolve(job).catch(() => {}); if (ctx && ctx.waitUntil) ctx.waitUntil(p); };
async function tg(env, text) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return false;
  try { const r = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text: String(text).slice(0, 4000), disable_web_page_preview: true }), signal: AbortSignal.timeout(8000) }); return r.ok; } catch { return false; }
}
async function sentry(env, err, extra) {
  if (!env.SENTRY_DSN) return;
  try {
    const d = new URL(env.SENTRY_DSN), proj = d.pathname.replace(/^\/+/, '');
    await fetch(`${d.protocol}//${d.host}/api/${proj}/store/`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-sentry-auth': `Sentry sentry_version=7, sentry_key=${d.username}, sentry_client=qvmpxt/3` }, body: JSON.stringify({ event_id: rid(16), timestamp: Date.now() / 1000, platform: 'javascript', level: 'error', message: String((err && err.message) || err).slice(0, 500), extra }), signal: AbortSignal.timeout(5000) });
  } catch { /* ignore */ }
}
async function sendMail(env, to, subject, html) {
  const url = env.MAIL_WEBHOOK_URL || DEFAULT_MAIL_URL, secret = env.MAIL_WEBHOOK_SECRET;
  if (!url || !secret || !emailOk(to)) return false;
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'text/plain;charset=utf-8' }, body: JSON.stringify({ secret, to, subject, html }), redirect: 'follow', signal: AbortSignal.timeout(15000) });
    return r.ok && (await r.text()).trim() === 'ok';
  } catch { return false; }
}
const mailHtml = (brand, heading, text, btnUrl, btnText) => `<div style="font-family:system-ui,-apple-system,sans-serif;max-width:520px;margin:auto;padding:24px;background:#0a1022;color:#f1f5f9;border-radius:16px"><h2 style="margin:0 0 12px;color:#00f0ff">${esc(brand)}</h2><h3 style="margin:0 0 10px">${esc(heading)}</h3><p style="color:#cbd5e1;line-height:1.5">${esc(text)}</p>${btnUrl ? `<p><a href="${esc(btnUrl)}" style="display:inline-block;background:#6366f1;color:#fff;padding:12px 20px;border-radius:10px;text-decoration:none;font-weight:700">${esc(btnText)}</a></p><p style="color:#94a3b8;font-size:12px;word-break:break-all">${esc(btnUrl)}</p>` : ''}<p style="color:#64748b;font-size:12px">If you did not expect this email you can safely ignore it.</p></div>`;
async function sendVerify(env, u, base) {
  const t = await mintToken(env, 'ev', { email: u.email }, 86400), b = brandOf(env);
  return sendMail(env, u.email, `Verify your ${b} email`, mailHtml(b, 'Confirm your email address', `Hi ${u.name || ''}, tap the button to confirm this email for your ${b} account. The link works for 24 hours.`, `${base}/api/auth/verify?token=${t}`, 'Verify email'));
}
const securityMail = (env, u, what) => sendMail(env, u.email, `${brandOf(env)} security notice`, mailHtml(brandOf(env), 'Security notice', `${what} If this was not you, reset your password right away and contact the founder from the app menu.`, '', ''));
async function fireHook(h, event, payload) {
  const body = JSON.stringify({ event, id: rid(), at: Date.now(), ...payload });
  try {
    const sig = await hmac(h.secret, body);
    const r = await fetch(h.url, { method: 'POST', headers: { 'content-type': 'application/json', 'x-qvmpxt-signature': 'sha256=' + sig }, body, redirect: 'manual', signal: AbortSignal.timeout(5000) });
    return { status: r.status };
  } catch { return { status: 0, error: 'Delivery failed' }; }
}
async function notifyOwnerHook(env, ctx, email, event, payload) {
  const h = await one(env, 'SELECT url,secret FROM hooks WHERE owner=?', email);
  if (h) background(ctx, fireHook(h, event, payload));
}

// ---------- workspace, RBAC, audit ----------
// Resolve which workspace a user works in and with which role. Done on every authenticated request (least privilege, no cached roles).
async function wsInfo(env, u) {
  const t = await one(env, 'SELECT owner,role,accepted FROM teams WHERE email=?', u.email);
  if (t && t.accepted && ROLES.includes(t.role)) {
    const o = await one(env, 'SELECT * FROM users WHERE email=?', t.owner);
    if (o) { u.ws = t.owner; u.role = t.role; u.eff = o; return u; }
  }
  u.ws = u.email; u.role = 'Admin'; u.eff = u; return u;
}
const chainHash = (prev, r) => sha([prev, r.at, r.actor, r.action, r.target, r.owner].join('|'));
// every sensitive action is appended here; rows are never updated or deleted (triggers enforce it) and each row hashes the previous one
async function audit(env, owner, actor, action, target = '') {
  try {
    const last = await one(env, 'SELECT hash FROM audit_log WHERE owner=? ORDER BY seq DESC LIMIT 1', owner), prev = last ? last.hash : '';
    const r = { owner, at: Date.now(), actor: String(actor).slice(0, 120), action: String(action).slice(0, 60), target: String(target || '').slice(0, 200) };
    await run(env, 'INSERT INTO audit_log(owner,at,actor,action,target,prev,hash) VALUES(?,?,?,?,?,?,?)', owner, r.at, r.actor, r.action, r.target, prev, await chainHash(prev, r));
  } catch (e) { await sentry(env, e, { where: 'audit' }); }
}
async function chainCheck(rows) { let prev = ''; for (const r of rows) { if (r.prev !== prev || r.hash !== await chainHash(prev, r)) return r.seq; prev = r.hash; } return 0; }

// ---------- domain logic ----------
const planOf = (u) => { const x = u.eff || u; return x.plan !== 'free' && x.plan_until && x.plan_until < Date.now() ? 'free' : x.plan; };
const capOf = (u) => PLANS[planOf(u)] || FREE;
async function roll(env, u) { const p = new Date().toISOString().slice(0, 7); if (u.period !== p) { u.period = p; u.used = 0; await run(env, 'UPDATE users SET period=?,used=0 WHERE email=?', p, u.email); } return u; }
const payInfo = (u) => parse(u.pay_json, {});
const profileOf = (u) => ({ email: u.email, name: u.name, phone: u.phone || '', company: u.company || '', addr: u.addr || '', cur: u.cur || 'USD', pay: payInfo(u), mfa: !!u.totp_on, social: u.social || '', verified: !!u.email_verified });
const cleanItems = (a) => (Array.isArray(a) ? a : []).slice(0, 50).map((i) => ({ name: String((i && i.name) || 'Item').slice(0, 100), qty: clamp(+(i && i.qty) || 1, 0.01, 1e6), price: clamp(+(i && i.price) || 0, 0, 1e9) })).filter((i) => i.name.trim());
const subOf = (items) => +items.reduce((a, i) => a + i.qty * i.price, 0).toFixed(2);
const splitCommission = (gross) => { const c = Math.round(gross * 100), f = Math.round(c * COMMISSION_PCT / 100); return { gross: c / 100, fee: f / 100, net: (c - f) / 100 }; };
const quoteView = (q) => ({ id: q.id, kind: q.kind, title: q.title, client: q.client, clientEmail: q.client_email, currency: q.currency, items: parse(q.items, []), tax: q.tax, total: q.total, sats: q.sats, notes: q.notes, status: q.status, views: q.views, signups: q.signups, acceptedBy: q.accepted_by, acceptedAt: q.accepted_at, paidAt: q.paid_at, created: q.created, url: `/s/${q.id}`, pdf: `/s/${q.id}/pdf` });

async function logHistory(env, e) {
  const id = e.id || rid(), at = e.at || Date.now();
  await run(env, 'INSERT INTO history(id,owner,type,title,summary,detail,at) VALUES(?,?,?,?,?,?,?)', id, e.owner, e.type, String(e.title).slice(0, 80), String(e.summary || '').slice(0, 300), JSON.stringify(e.detail || {}).slice(0, 8000), at);
  await run(env, 'DELETE FROM history WHERE owner=? AND id NOT IN (SELECT id FROM history WHERE owner=? ORDER BY at DESC LIMIT ?)', e.owner, e.owner, HISTORY_PER_USER);
  return { id, at };
}
// documents belong to the workspace (u.ws), so every member sees the same quotes
async function createQuote(env, u, b, kind = 'quote') {
  const items = cleanItems(b.items); if (!items.length) throw httpErr(400, 'Add at least one line item');
  const cur = CURRENCIES.includes(b.currency) ? b.currency : 'USD', tax = clamp(+b.tax || 0, 0, 40), sub = subOf(items), total = +(sub * (1 + tax / 100)).toFixed(2);
  if (!(total > 0)) throw httpErr(400, 'Total must be above zero');
  const sats = clamp(Math.round(+b.sats || 0), 0, 1e9), id = rid(6), now = Date.now(), title = String(b.title || (kind === 'invoice' ? 'Invoice' : 'Quotation')).slice(0, 80);
  const client = String(b.client || '').slice(0, 80), ce = emailOk(String(b.clientEmail || '').trim()) ? String(b.clientEmail).trim() : '';
  await run(env, 'INSERT INTO quotes(id,owner,kind,title,client,client_email,currency,items,tax,total,sats,notes,status,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', id, u.ws, kind, title, client, ce, cur, JSON.stringify(items), tax, total, sats, String(b.notes || '').slice(0, 1000), 'sent', now);
  await logHistory(env, { owner: u.ws, type: kind, title, summary: `${items.length} item(s), total ${money(total, cur)}${client ? ' for ' + client : ''} by ${u.email}`, detail: { quoteId: id, url: `/s/${id}`, pdf: `/s/${id}/pdf`, client, total, currency: cur, by: u.email }, at: now });
  await audit(env, u.ws, u.email, kind + '.create', id);
  return { id, url: `/s/${id}`, pdf: `/s/${id}/pdf`, total, currency: cur, kind };
}
function auditRows(rows) {
  const am = rows.map((x) => +x.amount || 0), mean = am.reduce((a, b) => a + b, 0) / am.length;
  const sd = Math.sqrt(am.reduce((a, b) => a + (b - mean) ** 2, 0) / am.length) || 1, seen = new Set(), out = [];
  rows.forEach((x, i) => {
    const f = (rule, severity, detail) => out.push({ row: i + 1, id: x.id, rule, severity, detail }), a = +x.amount || 0;
    if (seen.has(x.id)) f('duplicate-id', 'high', 'Same id appears twice'); seen.add(x.id);
    if (a > 10000 && !x.approvedBy) f('approval-required', 'high', 'Over 10,000 without approver');
    else if (a > 1000 && !x.approvedBy) f('missing-approver', 'medium', 'No approver on file');
    const d = new Date(x.date); if (!isNaN(d) && [0, 6].includes(d.getUTCDay())) f('weekend-entry', 'low', 'Posted on a weekend');
    const z = (a - mean) / sd; if (Math.abs(z) > 1.9) f('statistical-outlier', 'high', `Amount is ${z.toFixed(1)} standard deviations from the average`);
  });
  const w = { high: 25, medium: 12, low: 4 };
  return { checked: rows.length, flagged: out.length, mean: +mean.toFixed(2), sd: +sd.toFixed(2), score: Math.min(100, out.reduce((s, f) => s + w[f.severity], 0)), findings: out };
}

// ---------- AI: Claude with tool use, vision, BYOK ----------
const ITEMS_SCHEMA = { type: 'array', description: 'Line items', items: { type: 'object', properties: { name: { type: 'string' }, qty: { type: 'number' }, price: { type: 'number', description: 'Unit price' } }, required: ['name', 'qty', 'price'] } };
const DOC_PROPS = { title: { type: 'string' }, client: { type: 'string' }, clientEmail: { type: 'string' }, currency: { type: 'string', enum: CURRENCIES }, items: ITEMS_SCHEMA, tax: { type: 'number', description: 'Tax percent 0-40' }, notes: { type: 'string' } };
const TOOLDEFS = {
  create_quotation: { name: 'create_quotation', description: 'Create a shareable quotation link and a downloadable PDF for a client. Returns the link, the PDF path and the total.', input_schema: { type: 'object', properties: DOC_PROPS, required: ['title', 'items'] } },
  generate_invoice: { name: 'generate_invoice', description: 'Create a shareable invoice link and a downloadable PDF. Use only amounts the user stated.', input_schema: { type: 'object', properties: DOC_PROPS, required: ['title', 'items'] } },
  audit_dataset: { name: 'audit_dataset', description: 'Audit records for duplicate ids, missing approvals, weekend postings and statistical outliers.', input_schema: { type: 'object', properties: { rows: { type: 'array', items: { type: 'object' } } }, required: ['rows'] } },
  save_memory: { name: 'save_memory', description: 'Remember a short fact for future runs of this agent (client preferences, rates, terms).', input_schema: { type: 'object', properties: { note: { type: 'string' } }, required: ['note'] } },
  recall_memory: { name: 'recall_memory', description: 'List saved memory notes for this agent.', input_schema: { type: 'object', properties: {} } },
  send_webhook: { name: 'send_webhook', description: "Send a signed event to the workspace's saved webhook endpoint. Use for notifications the user asked for.", input_schema: { type: 'object', properties: { message: { type: 'string' }, data: { type: 'object' } }, required: ['message'] } },
};
async function execTool(env, u, agent, name, a) {
  a = a && typeof a === 'object' ? a : {};
  if (name === 'create_quotation' || name === 'generate_invoice') {
    if (u.role === 'Viewer') return { error: 'Viewer role cannot create documents' };
    try { const r = await createQuote(env, u, a, name === 'generate_invoice' ? 'invoice' : 'quote'); return { ...r, note: 'Share this link with the client. The PDF path can be opened or downloaded.' }; } catch (e) { return { error: e.message }; }
  }
  if (name === 'audit_dataset') { const rows = (Array.isArray(a.rows) ? a.rows : []).slice(0, 2000).map((x) => (x && typeof x === 'object' ? x : {})); if (!rows.length) return { error: 'No rows' }; const r = auditRows(rows); r.findings = r.findings.slice(0, 30); return r; }
  if (name === 'save_memory') { if (u.role === 'Viewer') return { error: 'Viewer role cannot save memory' }; const note = String(a.note || '').trim().slice(0, 400); if (!note) return { error: 'Empty note' }; await run(env, 'INSERT INTO agent_memory(id,owner,agent_id,note,at) VALUES(?,?,?,?,?)', rid(), u.ws, agent.id, note, Date.now()); await run(env, 'DELETE FROM agent_memory WHERE owner=? AND agent_id=? AND id NOT IN (SELECT id FROM agent_memory WHERE owner=? AND agent_id=? ORDER BY at DESC LIMIT 50)', u.ws, agent.id, u.ws, agent.id); return { saved: true }; }
  if (name === 'recall_memory') return { notes: (await all(env, 'SELECT note,at FROM agent_memory WHERE owner=? AND agent_id=? ORDER BY at DESC LIMIT 20', u.ws, agent.id)).map((r) => r.note) };
  if (name === 'send_webhook') {
    if (u.role === 'Viewer') return { error: 'Viewer role cannot send webhooks' };
    const h = await one(env, 'SELECT url,secret FROM hooks WHERE owner=?', u.ws); if (!h) return { error: 'No webhook endpoint is saved. Add one under Developer > Webhook first.' };
    const message = String(a.message || '').trim().slice(0, 2000); if (!message) return { error: 'Empty message' };
    const data = a.data && typeof a.data === 'object' && JSON.stringify(a.data).length <= 6000 ? a.data : undefined;
    const r = await fireHook(h, 'agent.message', { agent: agent.name, message, data });
    return r.status >= 200 && r.status < 300 ? { delivered: true, status: r.status } : { delivered: false, status: r.status, error: r.error || 'The endpoint did not accept the event' };
  }
  return { error: 'Unknown tool' };
}
async function anthropic(env, key, body) {
  let res, j;
  try { res = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' }, body: JSON.stringify({ model: env.MODEL || 'claude-sonnet-5-5', ...body }), signal: AbortSignal.timeout(45000) }); j = await res.json(); } catch { throw httpErr(502, 'The model did not respond in time'); }
  if (!res.ok) throw httpErr(502, String((j.error && j.error.message) || 'Model request failed').split(key).join('***').slice(0, 200));
  return j;
}
const BYOK = { openai: ['https://api.openai.com/v1/chat/completions', 'gpt-4o-mini'], deepseek: ['https://api.deepseek.com/chat/completions', 'deepseek-chat'], claude: ['https://api.anthropic.com/v1/messages', null] };
function byokOf(b) {
  if (!b) return null;
  const provider = String(b.provider || '').toLowerCase(), key = String(b.key || '').trim();
  if (!BYOK[provider]) throw httpErr(400, 'Provider must be openai, claude or deepseek');
  if (!/^[\w.-]{8,200}$/.test(key)) throw httpErr(400, 'That API key does not look valid');
  return { provider, key };
}
async function openaiCompat(byok, system, input) {
  const [endpoint, model] = BYOK[byok.provider]; let res, j;
  try { res = await fetch(endpoint, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + byok.key }, body: JSON.stringify({ model, max_tokens: 900, messages: [{ role: 'system', content: system }, { role: 'user', content: input }] }), signal: AbortSignal.timeout(30000) }); j = await res.json(); } catch { throw httpErr(502, 'Your provider did not respond in time'); }
  if (!res.ok) throw httpErr(502, String((j.error && (j.error.message || j.error)) || 'Provider rejected the request').split(byok.key).join('***').slice(0, 200));
  return { text: String((((j.choices || [])[0] || {}).message || {}).content || ''), tokens: (j.usage && j.usage.total_tokens) || 0 };
}
async function runAgent(env, u, agent, input, byok) {
  const t0 = Date.now(), steps = [{ step: 'plan', at: 0, note: 'Read task, memory and recent runs' }];
  const mem = await all(env, 'SELECT note FROM agent_memory WHERE owner=? AND agent_id=? ORDER BY at DESC LIMIT 10', u.ws, agent.id);
  const past = await all(env, 'SELECT input,output FROM runs WHERE owner=? AND agent=? ORDER BY at DESC LIMIT 3', u.ws, agent.name);
  let system = agent.prompt + `\n\nToday is ${new Date().toISOString().slice(0, 10)}. The user's default currency is ${u.cur === 'BDT' ? 'BDT' : 'USD'}. Never invent facts or prices.`;
  if (mem.length) system += '\n\nSaved memory:\n- ' + mem.map((m) => m.note).join('\n- ');
  if (past.length) system += '\n\nRecent runs (newest first):\n' + past.map((r) => `Input: ${String(r.input).slice(0, 200)}\nOutput: ${String(r.output).slice(0, 300)}`).join('\n---\n');
  let text = '', tokens = 0;
  if (byok && byok.provider !== 'claude') {
    const r = await openaiCompat(byok, system, input); text = r.text; tokens = r.tokens;
    steps.push({ step: 'model', at: Date.now() - t0, note: `Dedicated Gateway (${byok.provider}); tools are available with Claude keys` });
  } else {
    const key = byok ? byok.key : env.ANTHROPIC_API_KEY;
    if (!key) throw httpErr(503, 'AI model is not configured. Add ANTHROPIC_API_KEY on the server, or connect your own API key.');
    const tools = agent.tools.filter((t) => TOOLDEFS[t]).map((t) => TOOLDEFS[t]), messages = [{ role: 'user', content: input }];
    for (let i = 0; i < 5; i++) {
      const j = await anthropic(env, key, { max_tokens: 1200, system, messages, ...(tools.length ? { tools } : {}) });
      tokens += ((j.usage && j.usage.input_tokens) || 0) + ((j.usage && j.usage.output_tokens) || 0);
      steps.push({ step: 'model', at: Date.now() - t0, note: byok ? 'Dedicated Gateway (claude)' : 'Model call' });
      const uses = (j.content || []).filter((c) => c.type === 'tool_use');
      if (j.stop_reason !== 'tool_use' || !uses.length) { text = (j.content || []).map((c) => c.text || '').join(''); break; }
      messages.push({ role: 'assistant', content: j.content });
      const results = [];
      for (const t of uses) { const out = await execTool(env, u, agent, t.name, t.input); steps.push({ step: 'tool', at: Date.now() - t0, note: `${t.name}${out.error ? ' failed: ' + out.error : ' ok'}` }); results.push({ type: 'tool_result', tool_use_id: t.id, content: JSON.stringify(out).slice(0, 6000) }); }
      messages.push({ role: 'user', content: results });
      if (i === 4) text = 'Stopped after 5 tool rounds. Check My history for what was created.';
    }
  }
  steps.push({ step: 'done', at: Date.now() - t0, note: 'Result ready' });
  return { text, steps, tokens: tokens || Math.ceil((system.length + input.length + text.length) / 4), ms: Date.now() - t0 };
}
async function lnInvoice(addr, sats) {
  const [name, host] = addr.split('@'), ms = sats * 1000, sig = () => AbortSignal.timeout(6000);
  try {
    const a = await (await fetch(`https://${host}/.well-known/lnurlp/${encodeURIComponent(name)}`, { signal: sig(), redirect: 'error' })).json();
    if (!a || a.tag !== 'payRequest' || !a.callback || ms < a.minSendable || ms > a.maxSendable) return null;
    const cb = new URL(a.callback); if (cb.protocol !== 'https:') return null;
    cb.searchParams.set('amount', String(ms));
    const b = await (await fetch(cb, { signal: sig(), redirect: 'error' })).json();
    return b && typeof b.pr === 'string' && /^ln(bc|tb)/i.test(b.pr) ? b.pr : null;
  } catch { return null; }
}

// ---------- WebAuthn (passkeys): attestation "none", ES256 + RS256 ----------
function cborDecode(buf, off = 0) {
  if (buf.length > 16000) throw new Error('cbor too large');
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const rd = (o, depth) => {
    if (depth > 8) throw new Error('cbor too deep');
    const ib = buf[o++], mt = ib >> 5, ai = ib & 31; let n;
    if (ai < 24) n = ai;
    else if (ai === 24) { n = buf[o]; o += 1; }
    else if (ai === 25) { n = dv.getUint16(o); o += 2; }
    else if (ai === 26) { n = dv.getUint32(o); o += 4; }
    else if (ai === 27) { n = Number(dv.getBigUint64(o)); o += 8; }
    else throw new Error('cbor unsupported');
    switch (mt) {
      case 0: return [n, o];
      case 1: return [-1 - n, o];
      case 2: if (o + n > buf.length) throw new Error('cbor range'); return [buf.slice(o, o + n), o + n];
      case 3: if (o + n > buf.length) throw new Error('cbor range'); return [dec.decode(buf.slice(o, o + n)), o + n];
      case 4: { const a = []; for (let i = 0; i < n; i++) { const [v, no] = rd(o, depth + 1); a.push(v); o = no; } return [a, o]; }
      case 5: { const m = new Map(); for (let i = 0; i < n; i++) { const [k, o2] = rd(o, depth + 1), [v, o3] = rd(o2, depth + 1); m.set(k, v); o = o3; } return [m, o]; }
      case 7: return [n === 21 ? true : n === 20 ? false : null, o];
      default: throw new Error('cbor unsupported type');
    }
  };
  return rd(off, 0);
}
function coseToJwk(m) {
  const kty = m.get(1), alg = m.get(3);
  if (kty === 2 && alg === -7 && m.get(-1) === 1 && m.get(-2) && m.get(-3)) return { kty: 'EC', crv: 'P-256', x: b64u(m.get(-2)), y: b64u(m.get(-3)) };
  if (kty === 3 && alg === -257 && m.get(-1) && m.get(-2)) return { kty: 'RSA', n: b64u(m.get(-1)), e: b64u(m.get(-2)) };
  throw httpErr(400, 'This passkey uses an unsupported algorithm');
}
function derToRaw(sig) {
  let o = 2; if (sig[1] & 0x80) o = 2 + (sig[1] & 0x7f);
  const rd = () => { if (sig[o] !== 2) throw new Error('bad signature'); const l = sig[o + 1], s = o + 2; o = s + l; let v = sig.slice(s, s + l); while (v.length > 32 && v[0] === 0) v = v.slice(1); const out = new Uint8Array(32); out.set(v, 32 - v.length); return out; };
  const r = rd(), s = rd(); return concat(r, s);
}
const rpOf = (env, url) => { const base = baseOf(env, url), u = new URL(base); return { origin: u.origin, id: env.WEBAUTHN_RP_ID || u.hostname }; };
const rpHash = async (id) => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(id)));
function waClient(cdB64, type, challenge, rp) {
  const raw = ub(cdB64), cd = parse(dec.decode(raw), null);
  if (!cd || cd.type !== type || !safeEq(cd.challenge || '', challenge) || cd.origin !== rp.origin) throw httpErr(400, 'Passkey check failed (challenge or origin did not match)');
  return raw;
}
async function parseAttestation(att, rpId) {
  let obj; try { obj = cborDecode(att)[0]; } catch { throw httpErr(400, 'Invalid passkey data'); }
  const ad = obj instanceof Map ? obj.get('authData') : null;
  if (!(ad instanceof Uint8Array) || ad.length < 55) throw httpErr(400, 'Invalid passkey data');
  if (!safeEq(hex(ad.slice(0, 32)), hex(await rpHash(rpId)))) throw httpErr(400, 'Passkey was made for a different site');
  const flags = ad[32];
  if (!(flags & 1) || !(flags & 4) || !(flags & 64)) throw httpErr(400, 'Passkey needs user presence and verification');
  const counter = new DataView(ad.buffer, ad.byteOffset + 33, 4).getUint32(0), o = 37 + 16, len = new DataView(ad.buffer, ad.byteOffset + o, 2).getUint16(0);
  if (!len || len > 1023 || o + 2 + len >= ad.length) throw httpErr(400, 'Invalid passkey data');
  const credId = ad.slice(o + 2, o + 2 + len); let cose; try { cose = cborDecode(ad, o + 2 + len)[0]; } catch { throw httpErr(400, 'Invalid passkey key'); }
  if (!(cose instanceof Map)) throw httpErr(400, 'Invalid passkey key');
  return { id: b64u(credId), jwk: coseToJwk(cose), counter };
}
async function verifyAssertion(jwk, rpId, authData, clientRaw, sig) {
  if (authData.length < 37 || !safeEq(hex(authData.slice(0, 32)), hex(await rpHash(rpId)))) return null;
  const flags = authData[32]; if (!(flags & 1) || !(flags & 4)) return null;
  const data = concat(authData, new Uint8Array(await crypto.subtle.digest('SHA-256', clientRaw)));
  let ok;
  if (jwk.kty === 'EC') ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']), derToRaw(sig), data);
  else ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']), sig, data);
  return ok ? { counter: new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0) } : null;
}

// ---------- real PDF (text only, Helvetica; non-Latin characters print as ?) ----------
const pdfText = (s) => String(s ?? '').replace(/৳/g, 'BDT ').replace(/[^\x20-\x7e]/g, '?').replace(/[\\()]/g, '\\$&');
function buildPdf(pages) {
  const objs = [], n = pages.length;
  objs[1] = '<< /Type /Catalog /Pages 2 0 R >>';
  objs[2] = `<< /Type /Pages /Kids [${pages.map((_, i) => `${5 + 2 * i} 0 R`).join(' ')}] /Count ${n} >>`;
  objs[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>';
  objs[4] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>';
  pages.forEach((c, i) => { objs[5 + 2 * i] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${6 + 2 * i} 0 R >>`; objs[6 + 2 * i] = `<< /Length ${c.length} >>\nstream\n${c}\nendstream`; });
  let out = '%PDF-1.4\n'; const off = [];
  for (let i = 1; i < objs.length; i++) { off[i] = out.length; out += `${i} 0 obj\n${objs[i]}\nendobj\n`; }
  const x = out.length;
  out += `xref\n0 ${objs.length}\n0000000000 65535 f \n` + off.slice(1).map((o) => String(o).padStart(10, '0') + ' 00000 n \n').join('') + `trailer\n<< /Size ${objs.length} /Root 1 0 R >>\nstartxref\n${x}\n%%EOF`;
  return enc.encode(out);
}
function quotePdf(brand, qt, owner) {
  const items = parse(qt.items, []), sub = subOf(items), taxAmt = +(qt.total - sub).toFixed(2), doc = qt.kind === 'invoice' ? 'INVOICE' : 'QUOTATION';
  const pages = []; let cur = '', y = 790;
  const txt = (s, x, size = 11, bold = false) => { cur += `BT /${bold ? 'F2' : 'F1'} ${size} Tf ${x} ${y} Td (${pdfText(s)}) Tj ET\n`; };
  const right = (s, xr, size = 11, bold = false) => txt(s, Math.max(40, Math.round(xr - pdfText(s).length * size * 0.54)), size, bold);
  const line = () => { cur += `0.8 g 50 ${y - 4} 495 0.6 re f 0 g\n`; };
  const page = () => { pages.push(cur); cur = ''; y = 790; };
  const cm = (n) => (qt.currency === 'BDT' ? 'BDT ' : 'USD ') + Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  txt(doc, 50, 22, true); y -= 26;
  txt(String(qt.title).slice(0, 70), 50, 14, true); y -= 20;
  txt('From: ' + String(owner.company || owner.name).slice(0, 60), 50); y -= 15;
  if (qt.client) { txt('For: ' + String(qt.client).slice(0, 60), 50); y -= 15; }
  txt('Date: ' + new Date(qt.created).toISOString().slice(0, 10) + '    Ref: ' + qt.id, 50); y -= 15;
  txt('Status: ' + qt.status.toUpperCase(), 50); y -= 28;
  txt('Item', 50, 10, true); right('Qty', 360, 10, true); right('Price', 450, 10, true); right('Amount', 545, 10, true); y -= 4; line(); y -= 16;
  for (const i of items) {
    if (y < 110) page();
    txt(String(i.name).slice(0, 52), 50); right(String(+i.qty), 360); right(cm(i.price), 450); right(cm(i.qty * i.price), 545); y -= 17;
  }
  if (y < 150) page();
  line(); y -= 18;
  if (qt.tax) { right('Subtotal  ' + cm(sub), 545); y -= 15; right(`Tax ${+qt.tax}%  ` + cm(taxAmt), 545); y -= 18; }
  right('TOTAL  ' + cm(qt.total), 545, 14, true); y -= 30;
  if (qt.notes) for (const l of String(qt.notes).split('\n').slice(0, 12)) { if (y < 80) page(); txt(l.slice(0, 95), 50, 10); y -= 13; }
  y = 40; txt('Powered by ' + brand, 50, 9);
  pages.push(cur);
  return buildPdf(pages);
}

// ---------- translations: Claude translates, protected terms are never touched ----------
function protectTerms(text, terms) {
  const map = [], re = new RegExp('(?<![\\w])(' + terms.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')(?![\\w])', 'g');
  return { out: text.replace(re, (t) => { map.push(t); return `⟦${map.length - 1}⟧`; }), map };
}
function restoreTerms(text, map) {
  let bad = false, seen = 0;
  const out = text.replace(/⟦\s*(\d+)\s*⟧/g, (_, i) => { if (map[i] === undefined) { bad = true; return ''; } seen++; return map[i]; });
  return bad || /[⟦⟧]/.test(out) || seen !== map.length ? null : out;
}
const langName = (l) => { try { return new Intl.DisplayNames(['en'], { type: 'language' }).of(l) || l; } catch { return l; } };
async function translateStrings(env, lang, items) {
  const terms = GLOSSARY.concat(String(env.GLOSSARY_EXTRA || '').split(',').map((s) => s.trim()).filter(Boolean)).sort((a, b) => b.length - a.length);
  const prot = {}; for (const { key, text } of items) prot[key] = protectTerms(text, terms);
  const payload = Object.fromEntries(Object.entries(prot).map(([k, v]) => [k, v.out]));
  const j = await anthropic(env, env.ANTHROPIC_API_KEY, { max_tokens: 6000, system: `You translate app user-interface strings into ${langName(lang)} (language code ${lang}). Reply with ONLY one JSON object that has exactly the same keys as the input. Keep tokens such as ⟦0⟧, {0}, %s, numbers and emoji exactly as they are and never translate text inside ⟦ ⟧. Keep each translation short, natural and suitable for a button or label.`, messages: [{ role: 'user', content: JSON.stringify(payload) }] });
  const txt = (j.content || []).map((c) => c.text || '').join(''), mt = txt.match(/\{[\s\S]*\}/), obj = parse(mt ? mt[0] : '', {}), out = {};
  for (const [k, v] of Object.entries(obj)) { if (!prot[k] || typeof v !== 'string') continue; const r = restoreTerms(v, prot[k].map); if (r !== null && r.length <= 200) out[k] = r; }
  return out;
}

// ---------- PWA assets ----------
const SW_SOURCE = (brand) => `// ${brand} service worker
const CACHE='qvmpxt-v5';
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(['/','/manifest.webmanifest','/icon.svg'])).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==CACHE).map(x=>caches.delete(x)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{
 const r=e.request,u=new URL(r.url);
 if(r.method!=='GET'||u.origin!==location.origin||u.pathname.startsWith('/api/')||u.pathname.startsWith('/s/')||u.pathname==='/sw.js')return;
 const key=r.mode==='navigate'?'/':r;
 const net=fetch(r).then(x=>{if(x.ok){const c=x.clone();caches.open(CACHE).then(h=>h.put(key,c))}return x});
 e.respondWith(caches.match(key).then(hit=>{if(hit){e.waitUntil(net.catch(()=>{}));return hit}return net}));
});`;
const ICON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" fill="none"><rect width="48" height="48" rx="10" fill="#03050C"/><polygon points="24,5 40.45,14.5 40.45,33.5 24,43 7.55,33.5 7.55,14.5" stroke="#00f0ff" stroke-width="3.2" stroke-linejoin="round"/><polygon points="43,24 33.5,40.45 14.5,40.45 5,24 14.5,7.55 33.5,7.55" stroke="#6366f1" stroke-width="3.2" stroke-linejoin="round"/><polygon points="24,16 30.9,20 30.9,28 24,32 17.1,28 17.1,20" fill="#00f0ff"/></svg>';
const MANIFEST = (brand) => JSON.stringify({ name: brand, short_name: brand, start_url: '/', scope: '/', display: 'standalone', background_color: '#03050C', theme_color: '#03050C', icons: [{ src: '/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' }] });

// ---------- API ----------
async function api(req, env, ctx, url) {
  const p = url.pathname, m = req.method, brand = brandOf(env), q = url.searchParams;
  const readBody = async (limit = 400000) => {
    if (m === 'GET' || m === 'DELETE') return {};
    const t = await req.text(); if (t.length > limit) throw httpErr(413, 'Payload too large');
    try { return t ? JSON.parse(t) : {}; } catch { throw httpErr(400, 'Invalid JSON body'); }
  };
  // every authenticated request: verify signature + expiry + token version, then resolve workspace and role from the database
  const maybeUser = async () => {
    const tok = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, ''); if (!tok) return null;
    let u = null;
    if (tok.startsWith('qvm_live_')) { const k = await one(env, 'SELECT owner FROM keys WHERE hash=?', await sha(tok)); u = k ? await one(env, 'SELECT * FROM users WHERE email=?', k.owner) : null; }
    else { const t = await verifyToken(env, tok); if (!t) return null; u = await one(env, 'SELECT * FROM users WHERE email=?', t.sub); if (!u || (u.tv | 0) !== t.v) return null; }
    return u ? wsInfo(env, u) : null;
  };
  const needUser = async () => { const u = await maybeUser(); if (!u) throw httpErr(401, 'Sign in required'); return u; };
  const write = async (u) => { if (u.role === 'Viewer') throw httpErr(403, 'Role Viewer cannot change data'); };
  const admin = async (u) => { if (u.role !== 'Admin') throw httpErr(403, 'Admin role required'); };
  const needVerified = (u) => { if (!u.email_verified) throw httpErr(403, 'Verify your email first. Open the link we sent you, or request a new one from Personal info.', { verify: true }); };
  const isOwner = (u) => !!env.OWNER_EMAIL && u.email === String(env.OWNER_EMAIL).trim().toLowerCase();
  const needOwner = (u) => { if (!env.OWNER_EMAIL) throw httpErr(403, 'Set OWNER_EMAIL to review payments'); if (!isOwner(u)) throw httpErr(403, 'Owner only'); };
  const keysUsed = async (e) => (await one(env, 'SELECT COUNT(*) n FROM keys WHERE owner=?', e)).n;
  const seatsUsed = async (e) => 1 + (await one(env, 'SELECT COUNT(*) n FROM teams WHERE owner=?', e)).n;
  const limitsOf = async (u) => { const c = capOf(u); return { runs: c.runs, keys: { used: await keysUsed(u.ws), limit: c.keys }, seats: { used: await seatsUsed(u.ws), limit: c.seats } }; };
  const newUser = async (f) => { await run(env, 'INSERT INTO users(email,name,phone,salt,hash,social,email_verified,created) VALUES(?,?,?,?,?,?,?,?)', f.email, f.name, f.phone || '', f.salt || '', f.hash || '', f.social || '', f.verified ? 1 : 0, Date.now()); background(ctx, tg(env, `New ${brand} sign-up (${f.how})\nName: ${f.name}\nEmail: ${f.email}\nPhone: ${f.phone || 'not given'}`)); };
  const mailReady = () => !!((env.MAIL_WEBHOOK_URL || DEFAULT_MAIL_URL) && env.MAIL_WEBHOOK_SECRET);
  let mm;

  if (p === '/api/health') {
    return json({ ok: true, brand, time: Date.now(), db: true, storage: 'D1', kv: !!env.QV_KV, vault: !!env.QV_VAULT, mail: mailReady(), passkeys: true, ai: !!env.ANTHROPIC_API_KEY, stripe: !!(env.STRIPE_SECRET_KEY && env.STRIPE_WEBHOOK_SECRET), google: !!env.GOOGLE_CLIENT_ID, github: !!(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET), sentry: !!env.SENTRY_DSN, telegram: !!(env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID), audit: true });
  }
  if (p === '/api/config' && m === 'GET') {
    return json({ brand, googleClientId: env.GOOGLE_CLIENT_ID || '', github: !!(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET), ai: !!env.ANTHROPIC_API_KEY, stripe: !!(env.STRIPE_SECRET_KEY && env.STRIPE_WEBHOOK_SECRET), plans: PLANS, free: FREE, commissionPct: COMMISSION_PCT, mail: mailReady(), passkeys: true, vault: !!env.QV_VAULT, glossary: GLOSSARY,
      platformPay: { bkash: env.BKASH_NUMBER || '', nagad: env.NAGAD_NUMBER || '', rocket: env.ROCKET_NUMBER || '', lightning: !!lnAddrOk(env.BTC_LIGHTNING_ADDRESS) } });
  }
  if (p === '/api/log' && m === 'POST') {
    if (limited(req, 'log', 20, 60000)) return json({ ok: false });
    const b = await readBody(20000); const u = await maybeUser();
    background(ctx, sentry(env, String(b.message || 'client error'), { stack: String(b.stack || '').slice(0, 2000), page: String(b.page || '').slice(0, 200), ua: req.headers.get('user-agent'), user: u ? u.email : null }));
    return json({ ok: true });
  }
  if (p === '/api/notify/signup' && m === 'POST') { limited(req, 'notify', 10, 60000); await readBody(5000); return json({ ok: true }); }
  // Message to Founder: stored in D1 and relayed to Telegram
  if ((p === '/api/feedback' || p === '/api/founder') && m === 'POST') {
    if (limited(req, 'fb', 5, 60000)) return fail(429, 'Too many messages. Try again in a minute.');
    const b = await readBody(20000), msg = String(b.message || '').trim().slice(0, 3000), u = await maybeUser();
    if (msg.length < 3) return fail(400, 'Write a message first');
    const type = ['feedback', 'bug', 'idea', 'question', 'message'].includes(b.type) ? b.type : 'message', name = String(b.name || (u && u.name) || 'Guest').slice(0, 80), email = String(b.email || (u && u.email) || '').trim().slice(0, 120);
    await run(env, 'INSERT INTO feedback(id,type,name,email,message,at) VALUES(?,?,?,?,?,?)', rid(), type, name, email, msg, Date.now());
    const sent = await tg(env, `${brand} ${type} from ${name}${email ? ' <' + email + '>' : ''}\n\n${msg}`);
    return json({ ok: true, relayed: sent });
  }

  // ----- auth -----
  if (p === '/api/auth/register' && m === 'POST') {
    if (limited(req, 'auth', 20, 60000)) return fail(429, 'Too many attempts. Try again in a minute.');
    const b = await readBody(), email = String(b.email || '').trim().toLowerCase(), phone = String(b.phone || '').trim(), pw = String(b.password || '');
    if (!emailOk(email)) return fail(400, 'A valid email is required');
    if (pw.length < 8) return fail(400, 'Password must be at least 8 characters');
    if (!phoneOk(phone)) return fail(400, 'A valid phone number is required');
    if (await one(env, 'SELECT 1 x FROM users WHERE email=?', email)) return fail(409, 'Account already exists');
    const salt = rid(8), name = String(b.name || email.split('@')[0]).trim().slice(0, 60) || email.split('@')[0];
    await newUser({ email, name, phone, salt, hash: await hashPw(pw, salt), how: 'email' });
    if (/^[\w-]{6,20}$/.test(String(b.ref || ''))) await run(env, 'UPDATE quotes SET signups=signups+1 WHERE id=?', b.ref);
    await audit(env, email, email, 'account.create', 'email');
    background(ctx, sendVerify(env, { email, name }, baseOf(env, url)));
    return json({ token: await signToken(env, email, 0), name, verified: false });
  }
  if (p === '/api/auth/login' && m === 'POST') {
    if (limited(req, 'auth', 20, 60000)) return fail(429, 'Too many attempts. Try again in a minute.');
    const b = await readBody(), email = String(b.email || '').trim().toLowerCase(), u = await one(env, 'SELECT * FROM users WHERE email=?', email), pw = String(b.password || '');
    const lk = 'lf:' + await sha(email), fails = env.QV_KV ? +(await env.QV_KV.get(lk)) || 0 : 0;
    if (fails >= 8) return fail(429, 'Too many failed sign-ins for this account. Wait 15 minutes or reset your password.');
    const bump = () => env.QV_KV ? env.QV_KV.put(lk, String(fails + 1), { expirationTtl: 900 }) : null;
    const ok = u && u.hash ? safeEq(await hashPw(pw, u.salt), u.hash) : (await hashPw(pw, 'x'), false);
    if (!ok) { await bump(); if (u) await audit(env, u.email, u.email, 'auth.login.failed', 'password'); return fail(401, 'Wrong email or password'); }
    if (u.totp_on) {
      if (!b.code) return fail(401, 'Enter your 6-digit authenticator code', { mfa: true });
      if (!(await secondFactor(env, u, b.code))) { await bump(); await audit(env, u.email, u.email, 'auth.login.failed', 'mfa'); return fail(401, 'Wrong authenticator code', { mfa: true }); }
    }
    if (fails && env.QV_KV) await env.QV_KV.delete(lk);
    await audit(env, u.email, u.email, 'auth.login', u.totp_on ? 'password+mfa' : 'password');
    return json({ token: await signToken(env, u.email, u.tv), name: u.name, verified: !!u.email_verified });
  }
  if (p === '/api/auth/verify/send' && m === 'POST') {
    const u = await needUser(); if (u.email_verified) return json({ already: true });
    if (limited(req, 'mail', 6, 60000)) return fail(429, 'Too many requests. Try again in a minute.');
    if (await cooldown(env, 'cd:ev:' + await sha(u.email), 60)) return fail(429, 'A link was sent a moment ago. Check your inbox and spam folder.');
    const sent = await sendVerify(env, u, baseOf(env, url));
    return sent ? json({ sent: true }) : fail(502, 'The email could not be sent right now. Please try again later.');
  }
  if (p === '/api/auth/verify' && m === 'GET') {
    const to = (frag) => new Response(null, { status: 302, headers: { location: baseOf(env, url) + '/#' + frag, 'cache-control': 'no-store' } });
    try {
      const t = q.get('token'), rec = await peekToken(env, 'ev', t);
      if (!rec || !rec.email) return to('qv_err=' + encodeURIComponent('That verification link has expired. Request a new one from Personal info.'));
      await run(env, 'UPDATE users SET email_verified=1 WHERE email=?', rec.email); await dropToken(env, 'ev', t);
      return to('qv_msg=verified');
    } catch { return to('qv_err=' + encodeURIComponent('Verification is temporarily unavailable.')); }
  }
  if (p === '/api/auth/forgot' && m === 'POST') {
    if (limited(req, 'mail', 6, 60000)) return fail(429, 'Too many requests. Try again in a minute.');
    const email = String((await readBody(5000)).email || '').trim().toLowerCase(), u = emailOk(email) ? await one(env, 'SELECT * FROM users WHERE email=?', email) : null;
    if (u && u.hash && !(await cooldown(env, 'cd:pr:' + await sha(email), 60))) {
      background(ctx, (async () => {
        const t = await mintToken(env, 'pr', { email: u.email, tv: u.tv | 0 }, 3600);
        await sendMail(env, u.email, `Reset your ${brand} password`, mailHtml(brand, 'Reset your password', 'We received a request to reset your password. The link works once and expires in 1 hour.', `${baseOf(env, url)}/#qv_reset=${t}`, 'Choose a new password'));
      })());
    }
    return json({ ok: true, message: 'If an account exists for that email, a reset link is on its way.' });
  }
  if (p === '/api/auth/reset' && m === 'POST') {
    if (limited(req, 'auth', 20, 60000)) return fail(429, 'Too many attempts. Try again in a minute.');
    const b = await readBody(5000), pw = String(b.password || '');
    if (pw.length < 8) return fail(400, 'Password must be at least 8 characters');
    const rec = await peekToken(env, 'pr', b.token); if (!rec) return fail(400, 'This reset link is invalid or has expired. Request a new one.');
    const u = await one(env, 'SELECT * FROM users WHERE email=?', rec.email); if (!u || (u.tv | 0) !== rec.tv) return fail(400, 'This reset link is invalid or has expired. Request a new one.');
    if (u.totp_on && !(await secondFactor(env, u, b.code))) return fail(401, 'Enter your authenticator or recovery code to reset the password', { mfa: true });
    const salt = rid(8);
    await run(env, 'UPDATE users SET salt=?,hash=?,tv=tv+1,email_verified=1 WHERE email=?', salt, await hashPw(pw, salt), u.email); await dropToken(env, 'pr', b.token);
    await audit(env, u.email, u.email, 'auth.password.reset', 'all sessions revoked');
    background(ctx, securityMail(env, u, 'Your password was just reset and all devices were signed out.'));
    return json({ ok: true });
  }
  if (p === '/api/auth/password' && m === 'POST') {
    const u = await needUser(), b = await readBody(5000), pw = String(b.password || '');
    if (limited(req, 'auth', 20, 60000)) return fail(429, 'Too many attempts. Try again in a minute.');
    if (!u.hash) return fail(400, 'This account signs in with Google or GitHub, so it has no password to change');
    if (pw.length < 8) return fail(400, 'Password must be at least 8 characters');
    if (!safeEq(await hashPw(String(b.current || ''), u.salt), u.hash)) return fail(401, 'Your current password is wrong');
    if (u.totp_on && !(await secondFactor(env, u, b.code))) return fail(401, 'Enter your authenticator or recovery code', { mfa: true });
    const salt = rid(8);
    await run(env, 'UPDATE users SET salt=?,hash=?,tv=tv+1 WHERE email=?', salt, await hashPw(pw, salt), u.email);
    await audit(env, u.ws, u.email, 'auth.password.change', 'other sessions revoked');
    background(ctx, securityMail(env, u, 'Your password was changed and all other devices were signed out.'));
    return json({ token: await signToken(env, u.email, (u.tv | 0) + 1) });
  }
  if (p === '/api/auth/logout-all' && m === 'POST') {
    const u = await needUser(); await run(env, 'UPDATE users SET tv=tv+1 WHERE email=?', u.email);
    await audit(env, u.ws, u.email, 'auth.logout.all', 'session version bumped');
    return json({ ok: true, token: await signToken(env, u.email, (u.tv | 0) + 1) });
  }
  if (p === '/api/auth/google' && m === 'POST') {
    if (!env.GOOGLE_CLIENT_ID) return fail(503, 'Google sign-in is not configured');
    if (limited(req, 'auth', 20, 60000)) return fail(429, 'Too many attempts. Try again in a minute.');
    const tok = String((await readBody()).access_token || ''); let ti, g;
    try {
      ti = await (await fetch('https://oauth2.googleapis.com/tokeninfo?access_token=' + encodeURIComponent(tok), { signal: AbortSignal.timeout(8000) })).json();
      g = await (await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { authorization: 'Bearer ' + tok }, signal: AbortSignal.timeout(8000) })).json();
    } catch { return fail(502, 'Google could not be reached'); }
    const email = String(g.email || '').toLowerCase();
    if ((ti.aud !== env.GOOGLE_CLIENT_ID && ti.azp !== env.GOOGLE_CLIENT_ID) || g.email_verified !== true || !emailOk(email)) return fail(401, 'Google sign-in could not be verified');
    const u = await one(env, 'SELECT hash,name,tv FROM users WHERE email=?', email);
    if (u && u.hash) return fail(409, 'This email already has a password account. Sign in with your password.');
    const name = u ? u.name : String(g.name || email.split('@')[0]).slice(0, 60);
    if (!u) await newUser({ email, name, social: 'google', how: 'Google', verified: true });
    await audit(env, email, email, 'auth.login', 'google');
    return json({ token: await signToken(env, email, u ? u.tv : 0), name });
  }
  const ghBase = baseOf(env, url), ghCb = ghBase + '/api/auth/github/callback';
  const ghCookie = (v, age) => `qv_gh=${v}; Path=/api/auth/github; HttpOnly; SameSite=Lax; Max-Age=${age}` + (ghBase.startsWith('https') ? '; Secure' : '');
  if (p === '/api/auth/github' && m === 'GET') {
    if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) return fail(503, 'GitHub sign-in is not configured');
    const st = rid(16);
    return new Response(null, { status: 302, headers: { location: 'https://github.com/login/oauth/authorize?' + new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID, redirect_uri: ghCb, scope: 'read:user user:email', state: st }), 'set-cookie': ghCookie(st, 600) } });
  }
  if (p === '/api/auth/github/callback' && m === 'GET') {
    const back = (msg, tok) => new Response(null, { status: 302, headers: { location: ghBase + '/#' + (tok ? 'qv_gh=' + tok : 'qv_err=' + encodeURIComponent(msg)), 'set-cookie': ghCookie('', 0) } });
    const ck = /(?:^|;\s*)qv_gh=(\w+)/.exec(req.headers.get('cookie') || ''), code = q.get('code') || '', state = q.get('state') || '';
    if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) return back('GitHub sign-in is not configured');
    if (!ck || !code || !safeEq(ck[1], state)) return back('GitHub sign-in expired. Please try again.');
    let me, ems;
    try {
      const tr = await (await fetch('https://github.com/login/oauth/access_token', { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json' }, body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code, redirect_uri: ghCb }), signal: AbortSignal.timeout(8000) })).json();
      if (!tr.access_token) return back('GitHub did not approve the sign-in');
      const gh = { authorization: 'Bearer ' + tr.access_token, accept: 'application/vnd.github+json', 'user-agent': brand };
      me = await (await fetch('https://api.github.com/user', { headers: gh, signal: AbortSignal.timeout(8000) })).json();
      ems = await (await fetch('https://api.github.com/user/emails', { headers: gh, signal: AbortSignal.timeout(8000) })).json();
    } catch { return back('GitHub could not be reached'); }
    const pe = Array.isArray(ems) ? ems.find((x) => x.primary && x.verified) : null, email = String((pe && pe.email) || '').toLowerCase();
    if (!emailOk(email)) return back('Your GitHub account needs a verified primary email');
    const u = await one(env, 'SELECT hash,tv FROM users WHERE email=?', email);
    if (u && u.hash) return back('This email already has a password account. Sign in with your password.');
    if (!u) await newUser({ email, name: String(me.name || me.login || email.split('@')[0]).slice(0, 60), social: 'github', how: 'GitHub', verified: true });
    await audit(env, email, email, 'auth.login', 'github');
    return back('', await signToken(env, email, u ? u.tv : 0));
  }

  // ----- passkeys (WebAuthn) -----
  if (p === '/api/webauthn/register/options' && m === 'POST') {
    const u = await needUser(); if (limited(req, 'wa', 20, 60000)) return fail(429, 'Too many attempts. Try again in a minute.');
    const have = await all(env, 'SELECT id FROM passkeys WHERE owner=?', u.email); if (have.length >= 10) return fail(409, 'Passkey limit reached (10). Remove one first.');
    const rp = rpOf(env, url), challenge = b64u(crypto.getRandomValues(new Uint8Array(32))), cid = rid(12);
    await kv(env).put('wa:' + cid, JSON.stringify({ t: 'reg', email: u.email, challenge }), { expirationTtl: 300 });
    return json({ cid, publicKey: { rp: { name: brand, id: rp.id }, user: { id: b64u(enc.encode(await sha(u.email)).slice(0, 32)), name: u.email, displayName: u.name || u.email }, challenge, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], timeout: 60000, attestation: 'none', authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' }, excludeCredentials: have.map((x) => ({ type: 'public-key', id: x.id })) } });
  }
  if (p === '/api/webauthn/register/verify' && m === 'POST') {
    const u = await needUser(); if (limited(req, 'wa', 20, 60000)) return fail(429, 'Too many attempts. Try again in a minute.');
    const b = await readBody(30000), rec = await takeKv(env, 'wa:' + String(b.cid || ''));
    if (!rec || rec.t !== 'reg' || rec.email !== u.email) return fail(400, 'Passkey request expired. Start again.');
    const rp = rpOf(env, url); waClient(b.clientDataJSON, 'webauthn.create', rec.challenge, rp);
    const att = await parseAttestation(ub(b.attestationObject), rp.id);
    if (b.id && b.id !== att.id) return fail(400, 'Passkey id mismatch');
    if (await one(env, 'SELECT 1 x FROM passkeys WHERE id=?', att.id)) return fail(409, 'This passkey is already registered');
    await run(env, 'INSERT INTO passkeys(id,owner,jwk,counter,name,created) VALUES(?,?,?,?,?,?)', att.id, u.email, JSON.stringify(att.jwk), att.counter, String(b.name || 'Passkey').trim().slice(0, 40) || 'Passkey', Date.now());
    await audit(env, u.ws, u.email, 'passkey.add', String(b.name || 'Passkey').slice(0, 40));
    background(ctx, securityMail(env, u, 'A new passkey was added to your account.'));
    return json({ registered: true, id: att.id });
  }
  if (p === '/api/webauthn/login/options' && m === 'POST') {
    if (limited(req, 'wa', 30, 60000)) return fail(429, 'Too many attempts. Try again in a minute.');
    const email = String((await readBody(5000)).email || '').trim().toLowerCase(), rp = rpOf(env, url), challenge = b64u(crypto.getRandomValues(new Uint8Array(32))), cid = rid(12);
    const have = emailOk(email) ? await all(env, 'SELECT id FROM passkeys WHERE owner=?', email) : [];
    await kv(env).put('wa:' + cid, JSON.stringify({ t: 'auth', challenge }), { expirationTtl: 300 });
    return json({ cid, publicKey: { challenge, rpId: rp.id, timeout: 60000, userVerification: 'required', allowCredentials: have.map((x) => ({ type: 'public-key', id: x.id })) } });
  }
  if (p === '/api/webauthn/login/verify' && m === 'POST') {
    if (limited(req, 'wa', 20, 60000)) return fail(429, 'Too many attempts. Try again in a minute.');
    const b = await readBody(30000), bad = () => fail(401, 'Passkey sign-in failed');
    try {
      const rec = await takeKv(env, 'wa:' + String(b.cid || '')); if (!rec || rec.t !== 'auth') return bad();
      const pk = await one(env, 'SELECT * FROM passkeys WHERE id=?', String(b.id || '').slice(0, 1400)); if (!pk) return bad();
      const rp = rpOf(env, url), clientRaw = waClient(b.clientDataJSON, 'webauthn.get', rec.challenge, rp);
      const r = await verifyAssertion(parse(pk.jwk, {}), rp.id, ub(b.authenticatorData), clientRaw, ub(b.signature));
      if (!r || ((pk.counter > 0 || r.counter > 0) && r.counter <= pk.counter)) return bad();
      const u = await one(env, 'SELECT * FROM users WHERE email=?', pk.owner); if (!u) return bad();
      await run(env, 'UPDATE passkeys SET counter=? WHERE id=?', r.counter, pk.id);
      await audit(env, u.email, u.email, 'auth.login', 'passkey');
      return json({ token: await signToken(env, u.email, u.tv), name: u.name });
    } catch (e) { if (e && e.status === 503) throw e; return bad(); }
  }
  if (p === '/api/passkeys' && m === 'GET') { const u = await needUser(); return json(await all(env, 'SELECT id,name,created FROM passkeys WHERE owner=? ORDER BY created DESC', u.email)); }
  if ((mm = p.match(/^\/api\/passkeys\/([\w-]{8,1400})$/)) && m === 'DELETE') {
    const u = await needUser(), r = await run(env, 'DELETE FROM passkeys WHERE id=? AND owner=?', mm[1], u.email);
    if (!r.meta || !r.meta.changes) return fail(404, 'Passkey not found');
    await audit(env, u.ws, u.email, 'passkey.remove', mm[1].slice(0, 20)); background(ctx, securityMail(env, u, 'A passkey was removed from your account.')); return json({ removed: true });
  }

  // ----- profile, MFA -----
  if (p === '/api/me' && m === 'GET') {
    const u = await roll(env, await needUser());
    return json({ ...profileOf(u), plan: planOf(u), planUntil: (u.eff || u).plan_until || 0, role: u.role, workspace: u.ws, used: u.used, limit: capOf(u).runs, tokens: u.tokens, created: u.created, limits: await limitsOf(u), isOwner: isOwner(u), passkeys: (await one(env, 'SELECT COUNT(*) n FROM passkeys WHERE owner=?', u.email)).n, recoveryLeft: parse(u.recovery, []).length });
  }
  if (p === '/api/me' && m === 'PUT') {
    const u = await needUser(), b = await readBody();
    if (b.name !== undefined) { const n = String(b.name).trim().slice(0, 60); if (!n) return fail(400, 'Name cannot be empty'); u.name = n; }
    if (b.phone !== undefined) { const ph = String(b.phone).trim(); if (!phoneOk(ph)) return fail(400, 'A valid phone number is required'); u.phone = ph; }
    if (b.company !== undefined) u.company = String(b.company).trim().slice(0, 80);
    if (b.addr !== undefined) u.addr = String(b.addr).trim().slice(0, 200);
    if (b.cur !== undefined) { if (!['USD', 'BDT', 'BTC'].includes(b.cur)) return fail(400, 'Currency must be USD, BDT or BTC'); u.cur = b.cur; }
    if (b.pay !== undefined) {
      const x = b.pay || {}, o = {};
      if (x.stripe) { if (!/^https:\/\/(buy|checkout)\.stripe\.com\/[\w\-/?=&%.]+$/.test(String(x.stripe).trim())) return fail(400, 'Stripe link must be a https://buy.stripe.com/... Payment Link'); o.stripe = String(x.stripe).trim(); }
      for (const k of MOBILE) if (x[k]) { if (!phoneOk(String(x[k]).trim())) return fail(400, `Enter a valid ${k} number`); o[k] = String(x[k]).trim(); }
      if (x.lightning) { if (!lnAddrOk(String(x.lightning).trim())) return fail(400, 'Lightning address must look like you@wallet.com'); o.lightning = String(x.lightning).trim(); }
      u.pay_json = JSON.stringify(o);
      await audit(env, u.ws, u.email, 'settings.payment.update', 'payout details');
    }
    await run(env, 'UPDATE users SET name=?,phone=?,company=?,addr=?,cur=?,pay_json=? WHERE email=?', u.name, u.phone, u.company, u.addr, u.cur, u.pay_json, u.email);
    return json(profileOf(u));
  }
  if (p === '/api/mfa/setup' && m === 'POST') {
    const u = await needUser(); if (u.totp_on) return fail(409, 'MFA is already enabled');
    const secret = b32enc(crypto.getRandomValues(new Uint8Array(20)));
    await run(env, 'UPDATE users SET totp_secret=? WHERE email=?', secret, u.email);
    return json({ secret, uri: `otpauth://totp/${encodeURIComponent(brand)}:${encodeURIComponent(u.email)}?secret=${secret}&issuer=${encodeURIComponent(brand)}&digits=6&period=30` });
  }
  if (p === '/api/mfa/enable' && m === 'POST') {
    const u = await needUser(), b = await readBody();
    if (limited(req, 'mfa', 10, 60000)) return fail(429, 'Too many attempts');
    if (!u.totp_secret || !(await totpOk(u.totp_secret, b.code))) return fail(400, 'That code is not valid. Check the time on your phone and try again.');
    const rc = await newRecoveryCodes();
    await run(env, 'UPDATE users SET totp_on=1,recovery=? WHERE email=?', JSON.stringify(rc.hashes), u.email);
    await audit(env, u.ws, u.email, 'mfa.enable', 'totp');
    background(ctx, securityMail(env, u, 'Two-factor authentication was turned on.'));
    return json({ mfa: true, recovery: rc.codes, note: 'Save these recovery codes now. Each works once and they are not shown again.' });
  }
  if (p === '/api/mfa/disable' && m === 'POST') {
    const u = await needUser(), b = await readBody();
    if (limited(req, 'mfa', 10, 60000)) return fail(429, 'Too many attempts');
    if (!u.totp_on) return json({ mfa: false });
    if (!(await secondFactor(env, u, b.code))) return fail(400, 'That code is not valid');
    await run(env, "UPDATE users SET totp_on=0,totp_secret='',recovery='[]' WHERE email=?", u.email);
    await audit(env, u.ws, u.email, 'mfa.disable', 'totp');
    background(ctx, securityMail(env, u, 'Two-factor authentication was turned off.'));
    return json({ mfa: false });
  }
  if (p === '/api/summary' && m === 'GET') {
    const u = await roll(env, await needUser()), e = u.ws;
    const qs = await one(env, "SELECT COUNT(*) n,COALESCE(SUM(views),0) v,COALESCE(SUM(signups),0) s,SUM(CASE WHEN status='accepted' OR status='paid' THEN 1 ELSE 0 END) a,SUM(CASE WHEN status='paid' THEN 1 ELSE 0 END) p,COALESCE(SUM(CASE WHEN status='paid' THEN total ELSE 0 END),0) rev FROM quotes WHERE owner=?", e);
    const rn = await one(env, 'SELECT COUNT(*) n FROM runs WHERE owner=?', e), au = await one(env, "SELECT COUNT(*) n FROM history WHERE owner=? AND type='audit'", e);
    return json({ quotes: qs.n, views: qs.v, signups: qs.s, accepted: qs.a || 0, paid: qs.p || 0, revenue: qs.rev, runs: rn.n, audits: au.n, used: u.used, limit: capOf(u).runs, plan: planOf(u) });
  }

  // ----- E2EE vault: the browser encrypts with AES-256-GCM; the server stores ciphertext only (private to each user) -----
  if (p === '/api/vault/meta' && (m === 'GET' || m === 'PUT')) {
    const u = await needUser(), mk = 'vm:' + (await sha(u.email)).slice(0, 32);
    if (m === 'GET') { const v = await vaultKv(env).get(mk); return json(v ? parse(v, { exists: false }) : { exists: false }); }
    await write(u); const b = await readBody(20000), salt = String(b.salt || ''), chk = b.check || {};
    if (!/^[A-Za-z0-9_-]{16,64}$/.test(salt) || !/^[A-Za-z0-9_-]{16}$/.test(String(chk.iv || '')) || !/^[A-Za-z0-9_-]{16,200}$/.test(String(chk.ct || ''))) return fail(400, 'Invalid vault parameters');
    if (await vaultKv(env).get(mk) && b.rotate !== true) return fail(409, 'A vault already exists. Unlock it, or send rotate:true after re-encrypting your items.');
    const meta = { exists: true, kdf: 'PBKDF2-SHA256', iter: intParam(b.iter, 600000, 100000, 2000000), salt, check: { iv: chk.iv, ct: chk.ct }, v: 1, at: Date.now() };
    await vaultKv(env).put(mk, JSON.stringify(meta)); await audit(env, u.ws, u.email, b.rotate === true ? 'vault.rotate' : 'vault.create', 'AES-256-GCM, key stays in browser'); return json(meta);
  }
  if (p === '/api/vault' && m === 'GET') {
    const u = await needUser(), pre = `v:${(await sha(u.email)).slice(0, 32)}:`, l = await vaultKv(env).list({ prefix: pre, limit: 200 });
    return json({ items: l.keys.map((k) => ({ id: k.name.slice(pre.length), ...(k.metadata || {}) })).sort((a, b) => (b.at || 0) - (a.at || 0)) });
  }
  if ((mm = p.match(/^\/api\/vault\/([\w-]{6,40})$/))) {
    const u = await needUser(), pre = `v:${(await sha(u.email)).slice(0, 32)}:`, key = pre + mm[1];
    if (m === 'GET') { const v = await vaultKv(env).get(key); return v ? json(parse(v, {})) : fail(404, 'Vault item not found'); }
    if (m === 'PUT') {
      await write(u); const b = await readBody(300000), iv = String(b.iv || ''), ct = String(b.ct || ''), label = String(b.label || '').slice(0, 80);
      if (!/^[A-Za-z0-9_-]{16}$/.test(iv) || !/^[A-Za-z0-9_-]{22,262144}$/.test(ct)) return fail(400, 'Invalid ciphertext. Send base64url iv (12 bytes) and ct.');
      if (!(await vaultKv(env).get(key)) && (await vaultKv(env).list({ prefix: pre, limit: 200 })).keys.length >= 200) return fail(402, 'Vault is full (200 items). Delete an item first.');
      const at = Date.now(); await vaultKv(env).put(key, JSON.stringify({ iv, ct, label, at, v: 1 }), { metadata: { label, at, size: ct.length } });
      await audit(env, u.ws, u.email, 'vault.item.write', mm[1]);
      return json({ id: mm[1], at });
    }
    if (m === 'DELETE') { await write(u); await vaultKv(env).delete(key); await audit(env, u.ws, u.email, 'vault.item.delete', mm[1]); return json({ deleted: true }); }
  }

  // ----- translations (cached per language in KV) -----
  if ((mm = p.match(/^\/api\/i18n\/([\w-]{2,12})$/))) {
    const lang = mm[1]; if (!langOk(lang)) return fail(400, 'Unknown language code');
    const low = lang.toLowerCase(), base = low.split('-')[0], dir = RTL_LANGS.has(low) || RTL_LANGS.has(base) ? 'rtl' : 'ltr', ck = 'i18n:' + low;
    if (m === 'GET') {
      if (!env.QV_KV) return json({ lang, dir, strings: null });
      const pack = parse(await env.QV_KV.get(ck), null);
      return json({ lang, dir, strings: pack ? Object.fromEntries(Object.entries(pack).map(([k, v]) => [k, v.v])) : null });
    }
    if (m === 'POST') {
      if (limited(req, 'i18n', 4, 60000)) return fail(429, 'Too many translation requests. Try again in a minute.');
      const b = await readBody(60000), src = b.strings && typeof b.strings === 'object' ? b.strings : {};
      const entries = Object.entries(src).filter(([k, v]) => /^[\w.-]{1,60}$/.test(k) && typeof v === 'string' && v.trim() && v.length <= 200).slice(0, 80);
      if (!entries.length) return fail(400, 'No strings to translate');
      if (base === 'en') return json({ lang, dir, strings: Object.fromEntries(entries), missing: [] });
      if (!env.ANTHROPIC_API_KEY) return fail(503, 'AI model is not configured on the server');
      const pack = parse(await kv(env).get(ck), {}) || {}, todo = [];
      for (const [k, v] of entries) { const h = (await sha(v)).slice(0, 10); if (!pack[k] || pack[k].h !== h) todo.push({ key: k, text: v, h }); }
      if (todo.length) {
        const day = 'i18n:day:' + new Date().toISOString().slice(0, 10), n = +(await kv(env).get(day)) || 0;
        if (n >= intParam(env.I18N_DAILY_MAX, 300, 1, 100000)) return fail(429, 'Today\'s translation budget is used up. Try again tomorrow.');
        if (Object.keys(pack).length + todo.length > 900) return fail(413, 'Translation pack is full');
        await kv(env).put(day, String(n + 1), { expirationTtl: 172800 });
        const got = await translateStrings(env, lang, todo);
        for (const t of todo) if (got[t.key]) pack[t.key] = { h: t.h, v: got[t.key] };
        await kv(env).put(ck, JSON.stringify(pack));
      }
      return json({ lang, dir, strings: Object.fromEntries(entries.filter(([k]) => pack[k]).map(([k]) => [k, pack[k].v])), missing: entries.filter(([k]) => !pack[k]).map(([k]) => k) });
    }
  }

  // ----- team workspace: shared data pool, invites, roles, audit trail -----
  if (p === '/api/ws/state' && m === 'GET') {
    const u = await needUser();
    const mem = await all(env, 'SELECT t.email,t.role,t.accepted,x.name FROM teams t LEFT JOIN users x ON x.email=t.email WHERE t.owner=? ORDER BY t.invited', u.ws);
    const ow = u.eff || u;
    return json({ owner: u.ws, role: u.role, members: [{ email: u.ws, name: ow.name, role: 'Admin', accepted: 1 }, ...mem.map((x) => ({ email: x.email, name: x.name || '', role: x.role, accepted: !!x.accepted }))], invites: await all(env, 'SELECT owner,role FROM teams WHERE email=? AND accepted=0', u.email) });
  }
  if (p === '/api/ws/docs' && m === 'GET') {
    const u = await needUser(), since = Math.max(0, +q.get('since') || 0);
    const rows = await all(env, 'SELECT kind,id,data,del,by,at FROM ws_docs WHERE owner=? AND at>? ORDER BY at LIMIT 500', u.ws, since);
    return json({ docs: rows.map((r) => ({ kind: r.kind, id: r.id, data: r.del ? null : parse(r.data, {}), del: !!r.del, by: r.by, at: r.at })), now: rows.length ? rows[rows.length - 1].at : since });
  }
  if ((mm = p.match(/^\/api\/ws\/docs\/(agent|share|hist)\/([\w-]{1,40})$/))) {
    const u = await needUser(), kind = mm[1], id = mm[2]; await write(u);
    const cur = await one(env, 'SELECT data,del FROM ws_docs WHERE owner=? AND kind=? AND id=?', u.ws, kind, id);
    if (m === 'PUT') {
      const b = await readBody(40000); let d = b.data && typeof b.data === 'object' && !Array.isArray(b.data) ? b.data : null; if (!d) return fail(400, 'data must be an object');
      if (kind === 'agent') { const name = String(d.name || '').trim().slice(0, 60), task = String(d.task || '').trim().slice(0, 2000); if (!name || !task) return fail(400, 'Name and task are required'); d = { name, task, rentUntil: clamp(+d.rentUntil || 0, 0, 9e15) }; }
      const s = JSON.stringify(d); if (s.length > 30000) return fail(413, 'Document too large');
      if (cur && !cur.del && kind === 'hist') return json({ id, kept: true }); // history is append-only
      if (cur && !cur.del && cur.data === s) return json({ id, unchanged: true });
      await run(env, 'INSERT INTO ws_docs(owner,kind,id,data,by,at,del) VALUES(?,?,?,?,?,?,0) ON CONFLICT(owner,kind,id) DO UPDATE SET data=excluded.data,by=excluded.by,at=excluded.at,del=0', u.ws, kind, id, s, u.email, Math.max(Date.now(), 1));
      if (kind === 'agent') await audit(env, u.ws, u.email, cur && !cur.del ? 'agent.update' : 'agent.create', d.name);
      else if (kind === 'share') await audit(env, u.ws, u.email, cur && !cur.del ? 'quote.update' : 'quote.create', id);
      return json({ id, saved: true });
    }
    if (m === 'DELETE') {
      if (kind === 'hist') return fail(403, 'History is append-only');
      if (!cur || cur.del) return json({ deleted: true });
      await run(env, 'UPDATE ws_docs SET del=1,data=?,by=?,at=? WHERE owner=? AND kind=? AND id=?', '{}', u.email, Date.now(), u.ws, kind, id);
      if (kind === 'agent') await run(env, 'DELETE FROM agent_memory WHERE owner=? AND agent_id=?', u.ws, id);
      await audit(env, u.ws, u.email, kind === 'agent' ? 'agent.delete' : 'quote.delete', id);
      return json({ deleted: true });
    }
  }
  if (p === '/api/ws/invite' && m === 'POST') {
    const u = await needUser(); await admin(u); if (limited(req, 'invite', 20, 60000)) return fail(429, 'Too many invitations. Try again in a minute.');
    const b = await readBody(5000), email = String(b.email || '').trim().toLowerCase(), role = String(b.role || '');
    if (!emailOk(email)) return fail(400, 'Enter a valid email'); if (!ROLES.includes(role)) return fail(400, 'Role must be Admin, Editor or Viewer');
    if (email === u.ws) return fail(400, 'That is the workspace owner');
    if (await seatsUsed(u.ws) >= capOf(u).seats && !(await one(env, 'SELECT 1 x FROM teams WHERE email=? AND owner=?', email, u.ws))) return fail(402, `Your plan includes ${capOf(u).seats} team seats. Upgrade to invite more people.`);
    const ex = await one(env, 'SELECT owner,accepted FROM teams WHERE email=?', email);
    if (ex && ex.owner !== u.ws && ex.accepted) return fail(409, 'That person already belongs to another workspace');
    if (await one(env, 'SELECT 1 x FROM teams WHERE owner=?', email)) return fail(409, 'That person owns a workspace with members of their own');
    await run(env, 'INSERT INTO teams(email,owner,role,accepted,invited) VALUES(?,?,?,0,?) ON CONFLICT(email) DO UPDATE SET owner=excluded.owner,role=excluded.role,accepted=0,invited=excluded.invited', email, u.ws, role, Date.now());
    await audit(env, u.ws, u.email, 'team.invite', `${email} as ${role}`);
    const mailed = await sendMail(env, email, `${u.name} invited you to ${brand}`, mailHtml(brand, 'Workspace invitation', `${u.name} (${u.email}) invited you to a shared workspace as ${role}. Sign in with this email and accept the invitation inside the app.`, baseOf(env, url), 'Open ' + brand));
    return json({ invited: true, mailed });
  }
  if (p === '/api/ws/role' && m === 'PUT') {
    const u = await needUser(); await admin(u); const b = await readBody(5000), email = String(b.email || '').trim().toLowerCase(), role = String(b.role || '');
    if (!ROLES.includes(role)) return fail(400, 'Role must be Admin, Editor or Viewer');
    const t = await one(env, 'SELECT role FROM teams WHERE email=? AND owner=?', email, u.ws); if (!t) return fail(404, 'Member not found');
    await run(env, 'UPDATE teams SET role=? WHERE email=? AND owner=?', role, email, u.ws);
    await audit(env, u.ws, u.email, 'team.role.change', `${email}: ${t.role} -> ${role}`);
    return json({ email, role });
  }
  if ((mm = p.match(/^\/api\/ws\/member\/([^/]{3,120})$/)) && m === 'DELETE') {
    const u = await needUser(); await admin(u); const email = decodeURIComponent(mm[1]).toLowerCase();
    const r = await run(env, 'DELETE FROM teams WHERE email=? AND owner=?', email, u.ws); if (!r.meta || !r.meta.changes) return fail(404, 'Member not found');
    await audit(env, u.ws, u.email, 'team.member.remove', email); return json({ removed: true });
  }
  if (p === '/api/ws/accept' && m === 'POST') {
    const u = await needUser(), b = await readBody(5000), owner = String(b.owner || '').trim().toLowerCase();
    const t = await one(env, 'SELECT role FROM teams WHERE email=? AND owner=? AND accepted=0', u.email, owner); if (!t) return fail(404, 'No pending invitation from that workspace');
    if (await one(env, 'SELECT 1 x FROM teams WHERE owner=?', u.email)) return fail(409, 'Remove the members of your own workspace before joining another one');
    await run(env, 'UPDATE teams SET accepted=1 WHERE email=? AND owner=?', u.email, owner);
    await audit(env, owner, u.email, 'team.invite.accept', t.role); return json({ joined: true, role: t.role });
  }
  if (p === '/api/ws/decline' && m === 'POST') {
    const u = await needUser(), b = await readBody(5000), owner = String(b.owner || '').trim().toLowerCase();
    const r = await run(env, 'DELETE FROM teams WHERE email=? AND owner=? AND accepted=0', u.email, owner);
    if (r.meta && r.meta.changes) await audit(env, owner, u.email, 'team.invite.decline', ''); return json({ declined: true });
  }
  if (p === '/api/ws/audit-log' && m === 'GET') {
    const u = await needUser(); await admin(u);
    const rows = await all(env, 'SELECT * FROM audit_log WHERE owner=? ORDER BY seq LIMIT 5000', u.ws), bad = await chainCheck(rows);
    return json({ chain: bad ? 'broken' : 'intact', brokenAt: bad || null, total: rows.length, items: rows.slice(-intParam(q.get('limit'), 100, 1, 500)).reverse().map((r) => ({ seq: r.seq, at: r.at, actor: r.actor, action: r.action, target: r.target, hash: r.hash.slice(0, 16) })) });
  }
  if (p === '/api/ws/export' && m === 'GET') {
    const u = await needUser(); await admin(u); if (limited(req, 'export', 5, 60000)) return fail(429, 'Too many exports. Try again in a minute.');
    await audit(env, u.ws, u.email, 'data.export', 'workspace export');
    return json({ exportedAt: Date.now(), workspace: u.ws, by: u.email, note: 'Vault items are end-to-end encrypted and are not part of this export.',
      members: await all(env, 'SELECT email,role,accepted,invited FROM teams WHERE owner=?', u.ws),
      docs: (await all(env, 'SELECT kind,id,data,by,at FROM ws_docs WHERE owner=? AND del=0', u.ws)).map((r) => ({ ...r, data: parse(r.data, {}) })),
      quotes: (await all(env, 'SELECT * FROM quotes WHERE owner=?', u.ws)).map(quoteView),
      history: (await all(env, 'SELECT id,type,title,summary,detail,at FROM history WHERE owner=? ORDER BY at DESC', u.ws)).map((r) => ({ ...r, detail: parse(r.detail, {}) })),
      runs: (await all(env, 'SELECT id,agent,input,output,tokens,at FROM runs WHERE owner=? ORDER BY at DESC LIMIT 1000', u.ws)) });
  }
  if (p === '/api/team' && m === 'GET') { // legacy list
    const u = await needUser(); return json(await all(env, 'SELECT email,role,accepted,invited FROM teams WHERE owner=?', u.ws));
  }

  // ----- quotes and invoices -----
  if (p === '/api/quotes' && m === 'POST') {
    const u = await needUser(); await write(u); const b = await readBody();
    return json(await createQuote(env, u, b, b.kind === 'invoice' ? 'invoice' : 'quote'));
  }
  if (p === '/api/quotes' && m === 'GET') {
    const u = await needUser(); return json((await all(env, 'SELECT * FROM quotes WHERE owner=? ORDER BY created DESC LIMIT 200', u.ws)).map(quoteView));
  }
  if ((mm = p.match(/^\/api\/quotes\/([\w-]+)$/)) && m === 'DELETE') {
    const u = await needUser(); await write(u); const r = await run(env, 'DELETE FROM quotes WHERE id=? AND owner=?', mm[1], u.ws);
    if (!r.meta || !r.meta.changes) return fail(404, 'Quote not found'); await audit(env, u.ws, u.email, 'quote.delete', mm[1]); return json({ deleted: true });
  }

  // ----- public quote actions (no sign-in; the link is the credential) -----
  if ((mm = p.match(/^\/api\/public\/quotes\/([\w-]+)\/(methods|accept|lightning|proof)$/))) {
    if (limited(req, 'pub', 40, 60000)) return fail(429, 'Too many requests. Try again in a minute.');
    const qt = await one(env, 'SELECT * FROM quotes WHERE id=?', mm[1]); if (!qt) return fail(404, 'Link not found');
    const owner = await one(env, 'SELECT * FROM users WHERE email=?', qt.owner), pay = payInfo(owner);
    if (mm[2] === 'methods' && m === 'GET') return json({ status: qt.status, total: qt.total, currency: qt.currency, sats: qt.sats, stripe: pay.stripe || '', mobile: Object.fromEntries(MOBILE.filter((k) => pay[k]).map((k) => [k, pay[k]])), lightning: !!(pay.lightning && qt.sats > 0), seller: owner.company || owner.name });
    if (mm[2] === 'accept' && m === 'POST') {
      const b = await readBody(); if (qt.status === 'paid') return json({ status: 'paid' });
      const name = String(b.name || '').trim().slice(0, 80); if (name.length < 2) return fail(400, 'Enter your name to accept');
      if (qt.status !== 'accepted') { await run(env, "UPDATE quotes SET status='accepted',accepted_by=?,accepted_at=? WHERE id=?", name, Date.now(), qt.id); background(ctx, tg(env, `${brand}: "${qt.title}" was accepted by ${name}`)); await notifyOwnerHook(env, ctx, qt.owner, 'quote.accepted', { quote: qt.id, by: name }); }
      return json({ status: 'accepted' });
    }
    if (mm[2] === 'lightning' && m === 'GET') {
      if (!(pay.lightning && qt.sats > 0)) return fail(404, 'Lightning is not offered for this link');
      const invoice = await lnInvoice(pay.lightning, qt.sats);
      return json({ sats: qt.sats, address: pay.lightning, invoice, qr: invoice ? 'lightning:' + invoice : 'lightning:' + pay.lightning });
    }
    if (mm[2] === 'proof' && m === 'POST') {
      const b = await readBody(), prov = String(b.provider || ''), tx = String(b.txid || '').trim().toUpperCase().replace(/\s/g, '');
      if (!['stripe', 'lightning', ...MOBILE].includes(prov)) return fail(400, 'Unknown payment method');
      if (prov === 'lightning' ? !/^[A-Z0-9]{16,128}$/.test(tx) : !/^[A-Z0-9]{6,40}$/.test(tx)) return fail(400, prov === 'lightning' ? 'Enter the payment hash or preimage (16-128 letters or digits)' : 'Enter the transaction ID or receipt number');
      if (qt.status === 'paid') return fail(409, 'This link is already paid');
      const ukey = `${prov}:${tx}`; if (await one(env, 'SELECT 1 x FROM payments WHERE ukey=?', ukey)) return fail(409, 'This transaction ID was already submitted');
      const rec = { id: rid(), at: Date.now() };
      await run(env, "INSERT INTO payments(id,ukey,kind,txid,provider,quote_id,amount,currency,email,payer,status,at) VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?)", rec.id, ukey, 'quote', tx, prov, qt.id, prov === 'lightning' ? qt.sats : qt.total, prov === 'lightning' ? 'SATS' : qt.currency, qt.owner, String(b.name || '').slice(0, 80), rec.at);
      background(ctx, tg(env, `${brand}: payment proof (${prov}) for "${qt.title}" ${money(qt.total, qt.currency)}. Review it in Quotes.`));
      return json({ received: true, message: 'Payment details received. The seller confirms them before the link shows as paid.' });
    }
    return fail(405, 'Method not allowed');
  }

  // ----- payment review (quote payments: workspace Admin; plan payments: the platform owner) -----
  if (p === '/api/payments/review' && m === 'GET') {
    const u = await needUser();
    const mine = u.role === 'Viewer' ? [] : await all(env, "SELECT p.*,q.title FROM payments p LEFT JOIN quotes q ON q.id=p.quote_id WHERE p.kind='quote' AND p.email=? AND p.status='pending' ORDER BY p.at DESC LIMIT 100", u.ws);
    const plans = isOwner(u) ? await all(env, "SELECT * FROM payments WHERE kind='plan' AND status='pending' ORDER BY at DESC LIMIT 100") : [];
    return json({ quotePayments: mine, planPayments: plans });
  }
  if ((mm = p.match(/^\/api\/payments\/(approve|reject)\/(\w+)$/)) && m === 'POST') {
    const u = await needUser(), rec = await one(env, 'SELECT * FROM payments WHERE id=?', mm[2]);
    if (!rec) return fail(404, 'Payment not found'); if (rec.status !== 'pending') return fail(409, 'Already ' + rec.status);
    if (rec.kind === 'plan') needOwner(u); else { await admin(u); if (rec.email !== u.ws) return fail(403, 'Not your payment to review'); }
    if (mm[1] === 'approve') {
      if (rec.kind === 'plan') await run(env, 'UPDATE users SET plan=?,plan_until=? WHERE email=?', rec.plan, Date.now() + (rec.cycle === 'yearly' ? 366 : 31) * 864e5, rec.payer);
      else { await run(env, "UPDATE quotes SET status='paid',paid_at=? WHERE id=?", Date.now(), rec.quote_id); await notifyOwnerHook(env, ctx, rec.email, 'quote.paid', { quote: rec.quote_id, provider: rec.provider }); }
    }
    await run(env, 'UPDATE payments SET status=?,reviewed_by=? WHERE id=?', mm[1] === 'approve' ? 'approved' : 'rejected', u.email, rec.id);
    await audit(env, u.ws, u.email, 'payment.' + mm[1], `${rec.kind}:${rec.provider}:${rec.txid}`);
    return json({ id: rec.id, status: mm[1] === 'approve' ? 'approved' : 'rejected' });
  }
  if (p === '/api/payments/mine' && m === 'GET') {
    const u = await needUser(); return json(await all(env, "SELECT id,kind,provider,plan,cycle,amount,currency,status,at FROM payments WHERE kind='plan' AND payer=? ORDER BY at DESC LIMIT 50", u.email));
  }

  // ----- agents and runs -----
  if (p === '/api/agents' && m === 'GET') {
    const u = await maybeUser(), ws = u ? u.ws : '';
    const rows = (await all(env, 'SELECT id,owner,name,prompt,tools,rent_until,created FROM agents WHERE owner=? OR owner=? ORDER BY created DESC', 'system', ws)).map((a) => ({ ...a, tools: parse(a.tools, []), system: a.owner === 'system' }));
    const docs = u ? (await all(env, "SELECT id,data,at FROM ws_docs WHERE owner=? AND kind='agent' AND del=0 ORDER BY at DESC", ws)).map((r) => { const d = parse(r.data, {}); return { id: r.id, owner: ws, name: d.name, prompt: d.task, tools: [], rent_until: d.rentUntil || 0, created: r.at, system: false }; }) : [];
    return json([...rows, ...docs]);
  }
  if (p === '/api/agents' && m === 'POST') {
    const u = await needUser(); await write(u); const b = await readBody();
    if (!b.name || !b.prompt) return fail(400, 'Name and task are required');
    const tools = (Array.isArray(b.tools) ? b.tools : []).filter((t) => TOOL_NAMES.includes(t)), id = rid();
    await run(env, 'INSERT INTO agents(id,owner,name,prompt,tools,created) VALUES(?,?,?,?,?,?)', id, u.ws, String(b.name).slice(0, 60), String(b.prompt).slice(0, 2000), JSON.stringify(tools), Date.now());
    await audit(env, u.ws, u.email, 'agent.create', String(b.name).slice(0, 60));
    return json({ id });
  }
  if ((mm = p.match(/^\/api\/agents\/([\w-]+)$/)) && m === 'DELETE') {
    const u = await needUser(); await write(u); const r = await run(env, 'DELETE FROM agents WHERE id=? AND owner=?', mm[1], u.ws);
    if (!r.meta || !r.meta.changes) return fail(404, 'Agent not found'); await run(env, 'DELETE FROM agent_memory WHERE owner=? AND agent_id=?', u.ws, mm[1]); await audit(env, u.ws, u.email, 'agent.delete', mm[1]); return json({ deleted: true });
  }
  if ((mm = p.match(/^\/api\/agents\/([\w-]+)\/memory$/))) {
    const u = await needUser();
    if (m === 'GET') return json(await all(env, 'SELECT id,note,at FROM agent_memory WHERE owner=? AND agent_id=? ORDER BY at DESC LIMI
