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
//   BTC_LIGHTNING_ADDRESS, TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID, SENTRY_DSN, ALLOWED_ORIGIN, BRAND, GLOSSARY_EXTRA, I18N_DAILY_MAX,
//   TURNSTILE_SITE_KEY + TURNSTILE_SECRET_KEY (bot protection for AI runs), DAILY_AI_BUDGET_USD (platform-wide daily AI spend cap, default 50),
//   LEMON_API_KEY + LEMON_STORE_ID + LEMON_WEBHOOK_SECRET + LEMON_VARIANT_<PLAN>[_YEARLY] (Lemon Squeezy checkout, optional)
//
// Team workspace: an accepted team member works inside the owner's workspace. Agents, quotes, runs, OCR logs and history are
// stored under the owner's id (table ws_docs for synced client data), so every member sees the same data pool.
// Roles are enforced here on every request: Admin = everything; Editor = create/edit/run/publish; Viewer = read only.
// Audit: table audit_log is append-only (SQLite triggers block UPDATE/DELETE) and hash-chained per workspace.
// Tables are created and migrated automatically on first request.

const DEFAULT_BRAND = 'QVMPXT';
const DEFAULT_MAIL_URL = 'https://script.google.com/macros/s/AKfycbzxOGdviKa2lx37zMt05wcdpbdQDOF8nABuwhotl9hjO1ehUyitlPZpdBw_uVeYrkOS/exec';
const PLANS = {
  starter: { price: 9, yearly: 89, runs: 300, keys: 3, seats: 5, bdt: [990, 9900], btc: [0.00009, 0.0009] },
  growth: { price: 29, yearly: 289, runs: 2000, keys: 10, seats: 15, bdt: [2990, 28900], btc: [0.0003, 0.0028] },
  enterprise: { price: 99, yearly: 989, runs: 20000, keys: 9999, seats: 9999, bdt: [9900, 98900], btc: [0.001, 0.01] },
};
const FREE = { runs: 50, keys: 1, seats: 2 };
const RATE_LIMITS = { free: 30, starter: 60, growth: 300, enterprise: 1200 };
// managed AI runs per UTC day and per workspace (runs and estimated USD cost), on top of the monthly quota and the per-minute rate limit
const DAILY = { free: { runs: 15, usd: 0.1 }, starter: { runs: 80, usd: 1 }, growth: { runs: 400, usd: 6 }, enterprise: { runs: 2500, usd: 40 } };
const REF_BONUS = 25, REF_NEW = 10, BONUS_CAP = 500; // bonus managed runs: referrer, new user, lifetime cap
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
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-robots-tag': 'noindex' } });
const fail = (status, error, extra) => json({ error, ...extra }, status);
const httpErr = (status, message, extra) => Object.assign(new Error(message), { status, extra });
const safeEq = (a, b) => { a = String(a); b = String(b); if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const emailOk = (e) => /^\S+@\S+\.\S+$/.test(e || '') && e.length <= 120;
const phoneOk = (s) => /^[+\d][\d\s()-]{6,19}$/.test(s || '');
const lnAddrOk = (s) => /^[\w.+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(s || '');
const langOk = (s) => /^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8}){0,2}$/.test(s || '');
const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
const brandOf = (env) => String(env.BRAND || DEFAULT_BRAND).toUpperCase();
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
  ['bonus_runs', `ALTER TABLE users ADD COLUMN bonus_runs INTEGER DEFAULT 0`],
  ['ref_by', `ALTER TABLE users ADD COLUMN ref_by TEXT DEFAULT ''`],
  ['ref_paid', `ALTER TABLE users ADD COLUMN ref_paid INTEGER DEFAULT 0`],
  ['ref_code', `ALTER TABLE users ADD COLUMN ref_code TEXT DEFAULT ''`],
  ['logo', `ALTER TABLE users ADD COLUMN logo TEXT DEFAULT ''`],
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
function limited(req, bucket, max, windowMs, who) {
  const ip = req.headers.get('cf-connecting-ip') || 'local', k = bucket + ':' + (who || ip), now = Date.now(), h = HITS.get(k);
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
// Founder alerts. Every line starts with an icon. Sign-up / sign-in alerts carry contact details and request telemetry
// (device, approximate location, IP) and never the password, token or any secret.
const clip = (v, n) => String(v || '').replace(/[\r\n]+/g, ' ').trim().slice(0, n) || '-';
const SEP = '➖➖➖➖➖➖➖➖➖➖';
const flagOf = (cc) => (/^[A-Za-z]{2}$/.test(cc || '') && !/^(XX|T1)$/i.test(cc) ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)) : '🌍');
const countryName = (cc) => { try { return new Intl.DisplayNames(['en'], { type: 'region' }).of(String(cc).toUpperCase()) || cc; } catch { return cc; } };
function deviceOf(ua) {
  ua = String(ua || '');
  let m;
  const os = /Windows NT 10/.test(ua) ? 'Windows 10/11' : /Windows/.test(ua) ? 'Windows' : (m = /Android ([\d.]+)/.exec(ua)) ? 'Android ' + m[1] : (m = /(?:iPhone|iPad|iPod).*? OS ([\d_]+)/.exec(ua)) ? 'iOS ' + m[1].replace(/_/g, '.') : /Mac OS X/.test(ua) ? 'macOS' : /CrOS/.test(ua) ? 'ChromeOS' : /Linux/.test(ua) ? 'Linux' : 'Unknown OS';
  const ver = (re) => { const x = re.exec(ua); return x ? ' ' + x[1].split('.')[0] : ''; };
  const browser = /Edg(?:e|A|iOS)?\//.test(ua) ? 'Edge' + ver(/Edg(?:e|A|iOS)?\/([\d.]+)/) : /OPR\/|Opera/.test(ua) ? 'Opera' + ver(/OPR\/([\d.]+)/) : /SamsungBrowser/.test(ua) ? 'Samsung Internet' + ver(/SamsungBrowser\/([\d.]+)/) : /Firefox\/|FxiOS/.test(ua) ? 'Firefox' + ver(/(?:Firefox|FxiOS)\/([\d.]+)/) : /CriOS|Chrome\//.test(ua) ? 'Chrome' + ver(/(?:Chrome|CriOS)\/([\d.]+)/) : /Safari\//.test(ua) ? 'Safari' + ver(/Version\/([\d.]+)/) : ua ? 'Other browser' : 'Unknown';
  const type = /iPad|Tablet|SM-T/.test(ua) ? 'Tablet' : /Mobi|iPhone|iPod|Android/.test(ua) ? 'Mobile' : ua ? 'Desktop' : 'Unknown';
  const model = (m = /Android [\d.]+; ([^;)]+?)(?: Build|\))/.exec(ua)) ? m[1].trim() : /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : '';
  return { os, browser, type, model };
}
function geoOf(req) {
  const cf = req.cf || {}, h = (k) => req.headers.get(k) || '', cc = String(cf.country || h('cf-ipcountry') || '').toUpperCase();
  return { ip: h('cf-connecting-ip') || h('x-forwarded-for').split(',')[0].trim(), cc, country: cc && !/^(XX|T1)$/.test(cc) ? countryName(cc) : '', city: cf.city || h('cf-ipcity'), region: cf.region || h('cf-region'), tz: cf.timezone, net: [cf.asn ? 'AS' + cf.asn : '', cf.asOrganization || ''].filter(Boolean).join(' '), lat: cf.latitude || h('cf-iplatitude'), lon: cf.longitude || h('cf-iplongitude') };
}
// rows: [icon, label, value]. Builds a card in which every line begins with an icon.
const card = (brand, head, rows) => [head, SEP, ...rows.filter(Boolean).map(([i, l, v]) => `${i} ${l}: ${clip(v, 300)}`), SEP, `🛡️ Powered by ${brand}`].join('\n');
const telemetryRows = (req) => {
  const g = geoOf(req), d = deviceOf(req.headers.get('user-agent')), where = [g.city, g.region].filter(Boolean).join(', ');
  return [
    ['🌍', 'Country', g.country ? `${flagOf(g.cc)} ${g.country} (${g.cc})` : '-'],
    ['🏙️', 'City', where || '-'],
    ['🕒', 'Timezone', g.tz || '-'],
    g.lat && g.lon ? ['🧭', 'Coordinates', `${g.lat}, ${g.lon}`] : null,
    g.lat && g.lon ? ['🗺️', 'Map', `https://www.google.com/maps?q=${encodeURIComponent(g.lat + ',' + g.lon)}`] : null,
    ['🌐', 'IP address', g.ip || '-'],
    ['📡', 'Network', g.net || '-'],
    ['💻', 'Device', [d.type, d.os, d.model].filter(Boolean).join(' · ')],
    ['🧩', 'Browser', d.browser],
  ];
};
// a free-text body, one icon per line
const bodyRows = (text, icon = '💬') => String(text || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean).slice(0, 25).map((l) => [icon, 'Text', l.slice(0, 300)]).map(([i, , l]) => `${i} ${l}`);
function authAlert(env, ctx, req, kind, how, f) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return;
  const brand = brandOf(env), isNew = /sign-up/i.test(kind), head = `${isNew ? '🎉' : '🔐'} ${brand} · ${String(kind).toUpperCase()}`;
  background(ctx, tg(env, card(brand, head, [
    ['👤', 'Name', f.name],
    ['📧', 'Email', f.email],
    ['📱', 'Phone', f.phone],
    ['🔑', 'Method', how],
    ...telemetryRows(req),
    ['⏰', 'Time (UTC)', new Date().toISOString().replace('T', ' ').slice(0, 19)],
  ])));
}
// generic founder card for events (payments, quotes, messages)
const eventCard = (env, ctx, icon, title, rows, req) => {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return;
  const brand = brandOf(env);
  background(ctx, tg(env, card(brand, `${icon} ${brand} · ${title}`, [...rows, ...(req ? [['🌐', 'IP address', geoOf(req).ip || '-'], ['🌍', 'Country', geoOf(req).country || '-']] : []), ['⏰', 'Time (UTC)', new Date().toISOString().replace('T', ' ').slice(0, 19)]])));
};
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
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'text/plain;charset=utf-8' }, body: JSON.stringify({ secret, to, subject, html }), redirect: 'follow', signal: AbortSignal.timeout(15000) });
      const t = (await r.text()).trim();
      if (r.ok && (t === 'ok' || /^\{\s*"ok"\s*:\s*true/.test(t))) return true;
    } catch { /* retry once */ }
    if (attempt === 0) await new Promise((res) => setTimeout(res, 600));
  }
  return false;
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
const profileOf = (u) => ({ logo: u.logo || '', email: u.email, name: u.name, phone: u.phone || '', company: u.company || '', addr: u.addr || '', cur: u.cur || 'USD', pay: payInfo(u), mfa: !!u.totp_on, social: u.social || '', verified: !!u.email_verified });
const cleanItems = (a) => (Array.isArray(a) ? a : []).slice(0, 50).map((i) => ({ name: String((i && i.name) || 'Item').slice(0, 100), qty: clamp(+(i && i.qty) || 1, 0.01, 1e6), price: clamp(+(i && i.price) || 0, 0, 1e9) })).filter((i) => i.name.trim());
const subOf = (items) => +items.reduce((a, i) => a + i.qty * i.price, 0).toFixed(2);
const splitCommission = (gross) => { const c = Math.round(gross * 100), f = Math.round(c * COMMISSION_PCT / 100); return { gross: c / 100, fee: f / 100, net: (c - f) / 100 }; };
const quoteView = (q) => ({ dueAt: q.due_at || 0, reminders: q.remind_n || 0, id: q.id, kind: q.kind, title: q.title, client: q.client, clientEmail: q.client_email, currency: q.currency, items: parse(q.items, []), tax: q.tax, total: q.total, sats: q.sats, notes: q.notes, status: q.status, views: q.views, signups: q.signups, acceptedBy: q.accepted_by, acceptedAt: q.accepted_at, paidAt: q.paid_at, created: q.created, url: `/s/${q.id}`, pdf: `/s/${q.id}/pdf` });

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
  await run(env, 'INSERT INTO quotes(id,owner,kind,title,client,client_email,currency,items,tax,total,sats,notes,status,created,due_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', id, u.ws, kind, title, client, ce, cur, JSON.stringify(items), tax, total, sats, String(b.notes || '').slice(0, 1000), 'sent', now, now + clamp(Math.round(+b.dueDays || 14), 1, 365) * 864e5);
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


// ---------- Turnstile (bot protection for AI runs) ----------
async function turnstileOk(env, req, token) {
  if (!env.TURNSTILE_SECRET_KEY) return true; // not configured: /api/health and the readiness check report it
  token = String(token || ''); if (token.length < 10 || token.length > 2100) return false;
  try {
    const f = new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY, response: token }), ip = req.headers.get('cf-connecting-ip'); if (ip) f.set('remoteip', ip);
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: f, signal: AbortSignal.timeout(8000) });
    return !!(await r.json()).success;
  } catch { return false; }
}

// ---------- referrals: bonus managed runs for the referrer and the new user once the new email is verified ----------
async function applyRef(env, email, ref) {
  ref = String(ref || ''); if (!/^[\w-]{6,20}$/.test(ref)) return;
  const q = await one(env, 'SELECT owner FROM quotes WHERE id=?', ref);
  if (q) await run(env, 'UPDATE quotes SET signups=signups+1 WHERE id=?', ref);
  const owner = q ? q.owner : ((await one(env, "SELECT email FROM users WHERE ref_code=? AND ref_code!=''", ref)) || {}).email;
  if (owner && owner !== email) await run(env, "UPDATE users SET ref_by=? WHERE email=? AND ref_by=''", owner, email);
}
async function grantReferral(env, ctx, email) {
  try {
    const u = await one(env, 'SELECT email,name,ref_by,ref_paid,email_verified FROM users WHERE email=?', email);
    if (!u || !u.ref_by || u.ref_paid || !u.email_verified) return;
    const r = await run(env, 'UPDATE users SET ref_paid=1,bonus_runs=MIN(bonus_runs+?,?) WHERE email=? AND ref_paid=0', REF_NEW, BONUS_CAP, email);
    if (!r.meta || !r.meta.changes) return;
    await run(env, 'UPDATE users SET bonus_runs=MIN(bonus_runs+?,?) WHERE email=?', REF_BONUS, BONUS_CAP, u.ref_by);
    await audit(env, u.ref_by, 'system', 'referral.reward', `${email} verified: +${REF_BONUS} runs`);
    eventCard(env, ctx, '🎁', 'REFERRAL REWARD', [['👤', 'New user', u.name], ['📧', 'Email', email], ['🤝', 'Referrer', u.ref_by], ['⚡', 'Bonus runs', `+${REF_BONUS} referrer, +${REF_NEW} new user`]]);
    const rf = await one(env, 'SELECT name FROM users WHERE email=?', u.ref_by);
    await sendMail(env, u.ref_by, `You earned ${REF_BONUS} bonus runs on ${brandOf(env)}`, mailHtml(brandOf(env), 'Referral bonus', `Hi ${(rf && rf.name) || ''}, someone you referred just verified their account. We added ${REF_BONUS} bonus managed runs to your workspace.`, '', ''));
  } catch (e) { await sentry(env, e, { where: 'referral' }); }
}
async function ensureRefCode(env, u) {
  if (u.ref_code) return u.ref_code;
  const code = 'r' + rid(5); await run(env, "UPDATE users SET ref_code=? WHERE email=? AND (ref_code='' OR ref_code IS NULL)", code, u.email);
  const row = await one(env, 'SELECT ref_code FROM users WHERE email=?', u.email); u.ref_code = (row && row.ref_code) || code; return u.ref_code;
}

// ---------- overdue reminders (called hourly from traffic, and from a cron trigger when one is configured) ----------
const BOT_UA = /bot|crawl|spider|preview|facebookexternalhit|whatsapp|slack|telegram|twitter|linkedin|skype|discord|embedly|curl|wget|python-requests|headless/i;
async function sweepOverdue(env, base, brand) {
  if (!base || !(env.MAIL_WEBHOOK_URL || DEFAULT_MAIL_URL) || !env.MAIL_WEBHOOK_SECRET) return 0;
  const now = Date.now(), DAY = 864e5; let sent = 0;
  const rows = await all(env, "SELECT * FROM quotes WHERE paid_at=0 AND status IN ('sent','accepted') AND client_email!='' AND remind_n<3 AND (CASE WHEN due_at>0 THEN due_at ELSE created+? END)<? AND (remind_at=0 OR remind_at<?) ORDER BY created LIMIT 15", 14 * DAY, now, now - 3 * DAY);
  for (const q of rows) {
    const claim = await run(env, 'UPDATE quotes SET remind_n=remind_n+1,remind_at=? WHERE id=? AND remind_n=?', now, q.id, q.remind_n);
    if (!claim.meta || !claim.meta.changes) continue;
    const owner = await one(env, 'SELECT name,company,email FROM users WHERE email=?', q.owner); if (!owner) continue;
    const seller = owner.company || owner.name, pay = q.status === 'accepted' || q.kind === 'invoice', link = `${base}/s/${q.id}`;
    const ok = await sendMail(env, q.client_email, `Reminder: ${q.title} from ${seller}`, mailHtml(brand, pay ? 'Payment reminder' : 'Following up on your quotation', `Hi ${q.client || ''}, a friendly reminder that "${q.title}" (${money(q.total, q.currency)}) from ${seller} ${pay ? 'is awaiting payment' : 'is still waiting for your reply'}. You can review it, accept and pay from the link below.`, link, pay ? 'View and pay' : 'View quotation'));
    if (!ok) { await run(env, 'UPDATE quotes SET remind_n=?,remind_at=? WHERE id=?', q.remind_n, q.remind_at, q.id); continue; }
    sent++;
    await sendMail(env, owner.email, `Reminder sent: ${q.title}`, mailHtml(brand, 'Overdue reminder sent', `We emailed ${q.client_email} a reminder about "${q.title}" (reminder ${q.remind_n + 1} of 3).`, link, 'Open link'));
    const h = await one(env, 'SELECT url,secret FROM hooks WHERE owner=?', q.owner); if (h) await fireHook(h, 'quote.reminder', { quote: q.id, to: q.client_email, n: q.remind_n + 1 });
  }
  return sent;
}
let LAST_SWEEP = 0;
async function maybeSweep(env, base, brand) {
  if (Date.now() - LAST_SWEEP < 6e5) return; LAST_SWEEP = Date.now();
  try { if (!env.QV_KV || await cooldown(env, 'cd:sweep', 3600)) return; await sweepOverdue(env, base, brand); } catch { /* never block a request */ }
}
// first open of a share link: count it, tell the owner (at most every 30 minutes per link)
async function trackView(env, ctx, qt, owner, base, brand) {
  await run(env, 'UPDATE quotes SET views=views+1,viewed_at=CASE WHEN viewed_at=0 THEN ? ELSE viewed_at END WHERE id=?', Date.now(), qt.id);
  try {
    if (!env.QV_KV || await cooldown(env, 'cd:qv:' + qt.id, 1800)) return;
    const who = qt.client || 'Your client';
    await sendMail(env, qt.owner, `👀 ${who} opened "${qt.title}"`, mailHtml(brand, 'Your link was just opened', `${who} is looking at "${qt.title}" (${money(qt.total, qt.currency)}) right now. Views so far: ${qt.views + 1}.`, base ? base + '/' : '', 'Open dashboard'));
    const h = await one(env, 'SELECT url,secret FROM hooks WHERE owner=?', qt.owner); if (h) await fireHook(h, 'quote.viewed', { quote: qt.id, views: qt.views + 1 });
  } catch { /* notifications are best effort */ }
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
function quotePdf(brand, qt, owner, base) {
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
  txt('Date: ' + new Date(qt.created).toISOString().slice(0, 10) + '    Ref: ' + qt.id + (qt.due_at ? '    Due: ' + new Date(qt.due_at).toISOString().slice(0, 10) : ''), 50); y -= 15;
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
  y = 40; txt('Powered by ' + brand + (base ? '   |   Send quotations in 60 seconds: ' + String(base).replace(/^https?:\/\//, '') : ''), 50, 9);
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
const CACHE='qvmpxt-v6';
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(['/','/manifest.webmanifest','/icon.svg'])).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==CACHE).map(x=>caches.delete(x)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{
 const r=e.request,u=new URL(r.url);
 if(r.method!=='GET'||u.origin!==location.origin||u.pathname.startsWith('/api/')||u.pathname.startsWith('/s/')||u.pathname==='/sw.js')return;
 if(r.mode==='navigate'&&u.pathname!=='/')return;
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
  const limitsOf = async (u) => { const c = capOf(u); return { runs: c.runs + (u.bonus_runs | 0), keys: { used: await keysUsed(u.ws), limit: c.keys }, seats: { used: await seatsUsed(u.ws), limit: c.seats } }; };
  const newUser = async (f) => { await run(env, 'INSERT INTO users(email,name,phone,salt,hash,social,email_verified,created) VALUES(?,?,?,?,?,?,?,?)', f.email, f.name, f.phone || '', f.salt || '', f.hash || '', f.social || '', f.verified ? 1 : 0, Date.now()); };
  const mailOwner = (qt, subject, text) => background(ctx, sendMail(env, qt.owner, subject, mailHtml(brand, subject, text, baseOf(env, url) + '/', 'Open dashboard')));
  const mailReady = () => !!((env.MAIL_WEBHOOK_URL || DEFAULT_MAIL_URL) && env.MAIL_WEBHOOK_SECRET);
  let mm;

  if (p === '/api/health') {
    return json({ ok: true, brand, time: Date.now(), db: true, storage: 'D1', kv: !!env.QV_KV, vault: !!env.QV_VAULT, mail: mailReady(), passkeys: true, ai: !!env.ANTHROPIC_API_KEY, stripe: !!(env.STRIPE_SECRET_KEY && env.STRIPE_WEBHOOK_SECRET), google: !!env.GOOGLE_CLIENT_ID, github: !!(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET), sentry: !!env.SENTRY_DSN, telegram: !!(env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID), turnstile: !!(env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET_KEY), lemon: !!(env.LEMON_API_KEY && env.LEMON_STORE_ID && env.LEMON_WEBHOOK_SECRET), audit: true });
  }
  if (p === '/api/config' && m === 'GET') {
    return json({ brand, turnstileSiteKey: env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET_KEY ? env.TURNSTILE_SITE_KEY : '', lemon: !!(env.LEMON_API_KEY && env.LEMON_STORE_ID && env.LEMON_WEBHOOK_SECRET), refBonus: { referrer: REF_BONUS, newUser: REF_NEW }, googleClientId: env.GOOGLE_CLIENT_ID || '', github: !!(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET), ai: !!env.ANTHROPIC_API_KEY, stripe: !!(env.STRIPE_SECRET_KEY && env.STRIPE_WEBHOOK_SECRET), plans: PLANS, free: FREE, commissionPct: COMMISSION_PCT, mail: mailReady(), passkeys: true, vault: !!env.QV_VAULT, glossary: GLOSSARY,
      platformPay: { bkash: env.BKASH_NUMBER || '', nagad: env.NAGAD_NUMBER || '', rocket: env.ROCKET_NUMBER || '', lightning: !!lnAddrOk(env.BTC_LIGHTNING_ADDRESS) } });
  }
  if (p === '/api/log' && m === 'POST') {
    if (limited(req, 'log', 20, 60000)) return json({ ok: false });
    const b = await readBody(20000); const u = await maybeUser();
    background(ctx, sentry(env, String(b.message || 'client error'), { stack: String(b.stack || '').slice(0, 2000), page: String(b.page || '').slice(0, 200), ua: req.headers.get('user-agent'), user: u ? u.email : null }));
    return json({ ok: true });
  }
  if (p === '/api/notify/signup' && m === 'POST') {
    if (limited(req, 'notify', 10, 60000)) return fail(429, 'Too many requests');
    const b = await readBody(5000), em = String(b.email || '').trim().toLowerCase();
    if (emailOk(em)) authAlert(env, ctx, req, 'new sign-up (device mode)', 'Local', { name: b.name, email: em, phone: b.phone });
    return json({ ok: true });
  }
  // Message to Founder: stored in D1 and relayed to Telegram
  if ((p === '/api/feedback' || p === '/api/founder') && m === 'POST') {
    if (limited(req, 'fb', 5, 60000)) return fail(429, 'Too many messages. Try again in a minute.');
    const b = await readBody(20000), msg = String(b.message || '').trim().slice(0, 3000), u = await maybeUser();
    if (msg.length < 3) return fail(400, 'Write a message first');
    const type = ['feedback', 'bug', 'idea', 'question', 'message'].includes(b.type) ? b.type : 'message', name = String(b.name || (u && u.name) || 'Guest').slice(0, 80), email = String(b.email || (u && u.email) || '').trim().slice(0, 120);
    await run(env, 'INSERT INTO feedback(id,type,name,email,message,at) VALUES(?,?,?,?,?,?)', rid(), type, name, email, msg, Date.now());
    const g = geoOf(req), sent = await tg(env, [`${{ bug: '🐞', idea: '💡', question: '❓', feedback: '📝' }[type] || '📩'} ${brand} · ${type.toUpperCase()}`, SEP, `👤 Name: ${clip(name, 80)}`, `📧 Email: ${clip(email, 120)}`, `🌍 Country: ${g.country ? flagOf(g.cc) + ' ' + g.country : '-'}`, `🌐 IP address: ${g.ip || '-'}`, `💻 Device: ${deviceOf(req.headers.get('user-agent')).type} · ${deviceOf(req.headers.get('user-agent')).browser}`, SEP, ...bodyRows(msg), SEP, `🛡️ Powered by ${brand}`].join('\n'));
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
    await applyRef(env, email, b.ref);
    await audit(env, email, email, 'account.create', 'email');
    authAlert(env, ctx, req, 'new sign-up', 'Email', { name, email, phone });
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
    authAlert(env, ctx, req, 'sign-in', u.totp_on ? 'Email + MFA' : 'Email', u);
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
      await run(env, 'UPDATE users SET email_verified=1 WHERE email=?', rec.email); await dropToken(env, 'ev', t); background(ctx, grantReferral(env, ctx, rec.email));
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
    const gb = await readBody(), tok = String(gb.access_token || ''); let ti, g;
    try {
      ti = await (await fetch('https://oauth2.googleapis.com/tokeninfo?access_token=' + encodeURIComponent(tok), { signal: AbortSignal.timeout(8000) })).json();
      g = await (await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { authorization: 'Bearer ' + tok }, signal: AbortSignal.timeout(8000) })).json();
    } catch { return fail(502, 'Google could not be reached'); }
    const email = String(g.email || '').toLowerCase();
    if ((ti.aud !== env.GOOGLE_CLIENT_ID && ti.azp !== env.GOOGLE_CLIENT_ID) || g.email_verified !== true || !emailOk(email)) return fail(401, 'Google sign-in could not be verified');
    const u = await one(env, 'SELECT hash,name,tv,phone FROM users WHERE email=?', email);
    if (u && u.hash) return fail(409, 'This email already has a password account. Sign in with your password.');
    const name = u ? u.name : String(g.name || email.split('@')[0]).slice(0, 60);
    if (!u) { await newUser({ email, name, social: 'google', how: 'Google', verified: true }); await applyRef(env, email, gb.ref); background(ctx, grantReferral(env, ctx, email)); }
    await audit(env, email, email, 'auth.login', 'google');
    authAlert(env, ctx, req, u ? 'sign-in' : 'new sign-up', 'Google', { name, email, phone: u && u.phone });
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
    const u = await one(env, 'SELECT hash,tv,phone FROM users WHERE email=?', email);
    if (u && u.hash) return back('This email already has a password account. Sign in with your password.');
    const ghName = String(me.name || me.login || email.split('@')[0]).slice(0, 60);
    if (!u) { await newUser({ email, name: ghName, social: 'github', how: 'GitHub', verified: true }); background(ctx, grantReferral(env, ctx, email)); }
    await audit(env, email, email, 'auth.login', 'github');
    authAlert(env, ctx, req, u ? 'sign-in' : 'new sign-up', 'GitHub', { name: ghName, email, phone: u && u.phone });
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
      authAlert(env, ctx, req, 'sign-in', 'Passkey', u);
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
    return json({ ...profileOf(u), plan: planOf(u), planUntil: (u.eff || u).plan_until || 0, role: u.role, workspace: u.ws, used: u.used, limit: capOf(u).runs + (u.bonus_runs | 0), bonusRuns: u.bonus_runs | 0, daily: DAILY[planOf(u)] || DAILY.free, referral: { code: await ensureRefCode(env, u), link: baseOf(env, url) + '/#ref=' + u.ref_code, invited: (await one(env, 'SELECT COUNT(*) n FROM users WHERE ref_by=?', u.email)).n, rewarded: (await one(env, 'SELECT COUNT(*) n FROM users WHERE ref_by=? AND ref_paid=1', u.email)).n, referrerBonus: REF_BONUS, newUserBonus: REF_NEW }, tokens: u.tokens, created: u.created, limits: await limitsOf(u), isOwner: isOwner(u), passkeys: (await one(env, 'SELECT COUNT(*) n FROM passkeys WHERE owner=?', u.email)).n, recoveryLeft: parse(u.recovery, []).length });
  }
  if (p === '/api/me' && m === 'PUT') {
    const u = await needUser(), b = await readBody();
    if (b.name !== undefined) { const n = String(b.name).trim().slice(0, 60); if (!n) return fail(400, 'Name cannot be empty'); u.name = n; }
    if (b.phone !== undefined) { const ph = String(b.phone).trim(); if (!phoneOk(ph)) return fail(400, 'A valid phone number is required'); u.phone = ph; }
    if (b.company !== undefined) u.company = String(b.company).trim().slice(0, 80);
    if (b.addr !== undefined) u.addr = String(b.addr).trim().slice(0, 200);
    if (b.logo !== undefined) { const lg = String(b.logo).trim(); if (lg && !/^https:\/\/[^\s"'<>]{4,290}$/.test(lg)) return fail(400, 'Logo must be a https:// image link'); u.logo = lg; }
    if (b.cur !== undefined) { if (!['USD', 'BDT', 'BTC'].includes(b.cur)) return fail(400, 'Currency must be USD, BDT or BTC'); u.cur = b.cur; }
    if (b.pay !== undefined) {
      const x = b.pay || {}, o = {};
      if (x.stripe) { if (!/^https:\/\/(buy|checkout)\.stripe\.com\/[\w\-/?=&%.]+$/.test(String(x.stripe).trim())) return fail(400, 'Stripe link must be a https://buy.stripe.com/... Payment Link'); o.stripe = String(x.stripe).trim(); }
      for (const k of MOBILE) if (x[k]) { if (!phoneOk(String(x[k]).trim())) return fail(400, `Enter a valid ${k} number`); o[k] = String(x[k]).trim(); }
      if (x.lightning) { if (!lnAddrOk(String(x.lightning).trim())) return fail(400, 'Lightning address must look like you@wallet.com'); o.lightning = String(x.lightning).trim(); }
      u.pay_json = JSON.stringify(o);
      await audit(env, u.ws, u.email, 'settings.payment.update', 'payout details');
    }
    await run(env, 'UPDATE users SET name=?,phone=?,company=?,addr=?,cur=?,pay_json=?,logo=? WHERE email=?', u.name, u.phone, u.company, u.addr, u.cur, u.pay_json, u.logo || '', u.email);
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
      if (qt.status !== 'accepted') { await run(env, "UPDATE quotes SET status='accepted',accepted_by=?,accepted_at=? WHERE id=?", name, Date.now(), qt.id); eventCard(env, ctx, '✅', 'QUOTE ACCEPTED', [['📄', 'Quote', qt.title], ['👤', 'Accepted by', name], ['💰', 'Total', money(qt.total, qt.currency)], ['🔗', 'Ref', qt.id]], req); mailOwner(qt, `✅ ${name} accepted "${qt.title}"`, `${name} accepted "${qt.title}" (${money(qt.total, qt.currency)}).`); await notifyOwnerHook(env, ctx, qt.owner, 'quote.accepted', { quote: qt.id, by: name }); }
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
      eventCard(env, ctx, '💳', 'QUOTE PAYMENT PROOF', [['📄', 'Quote', qt.title], ['💰', 'Amount', money(qt.total, qt.currency)], ['🏦', 'Method', prov], ['🧾', 'TxID', tx], ['👤', 'Payer', b.name]], req); mailOwner(qt, `💳 Payment proof for "${qt.title}"`, `A payment proof (${prov}, ${tx}) was submitted for "${qt.title}". Review it in Quotes.`);
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
    if (m === 'GET') return json(await all(env, 'SELECT id,note,at FROM agent_memory WHERE owner=? AND agent_id=? ORDER BY at DESC LIMIT 50', u.ws, mm[1]));
    if (m === 'POST') {
      await write(u); const note = String((await readBody(5000)).note || '').trim().slice(0, 400); if (!note) return fail(400, 'Write a note first');
      await run(env, 'INSERT INTO agent_memory(id,owner,agent_id,note,at) VALUES(?,?,?,?,?)', rid(), u.ws, mm[1], note, Date.now());
      await run(env, 'DELETE FROM agent_memory WHERE owner=? AND agent_id=? AND id NOT IN (SELECT id FROM agent_memory WHERE owner=? AND agent_id=? ORDER BY at DESC LIMIT 50)', u.ws, mm[1], u.ws, mm[1]);
      return json({ saved: true });
    }
    if (m === 'DELETE') {
      await write(u); const id = q.get('id');
      if (id) await run(env, 'DELETE FROM agent_memory WHERE id=? AND owner=? AND agent_id=?', id, u.ws, mm[1]); else await run(env, 'DELETE FROM agent_memory WHERE owner=? AND agent_id=?', u.ws, mm[1]);
      return json({ deleted: true });
    }
  }
  // run an agent: body { input, agent:{name,prompt}, byok:{provider,key} }; answer { output, tokens, gateway, steps, ms }
  if ((mm = p.match(/^\/api\/agents\/([\w-]{1,40})\/run$/)) && m === 'POST') {
    const viaKey = /^Bearer\s+qvm_live_/i.test(req.headers.get('authorization') || '');
    const u = await roll(env, await needUser()); await write(u); needVerified(u);
    const plan = planOf(u); if (limited(req, 'run:' + plan, RATE_LIMITS[plan] || 30, 60000, u.email)) return fail(429, 'Too many runs per minute for your plan. Slow down or upgrade.');
    const b = await readBody(200000), input = String(b.input || '').trim().slice(0, 12000); if (!input) return fail(400, 'Input is required');
    // bot protection: a Turnstile token (or a 15-minute pass issued after one) is required for browser sessions; API keys are exempt
    let passOut = '';
    if (!viaKey && env.TURNSTILE_SECRET_KEY) {
      const pass = await peekToken(env, 'tp', b.pass);
      if (!(pass && pass.email === u.email)) {
        if (!(await turnstileOk(env, req, b.turnstile))) return fail(403, 'Security check failed. Please complete the verification and try again.', { turnstile: true });
        passOut = await mintToken(env, 'tp', { email: u.email }, 900);
      }
    }
    const byok = byokOf(b.byok), id = mm[1];
    let agent = await one(env, 'SELECT id,owner,name,prompt,tools FROM agents WHERE id=? AND (owner=? OR owner=?)', id, 'system', u.ws);
    if (agent) agent.tools = parse(agent.tools, []);
    else {
      const doc = await one(env, "SELECT data FROM ws_docs WHERE owner=? AND kind='agent' AND id=? AND del=0", u.ws, id), d = doc ? parse(doc.data, {}) : {}, ca = b.agent && typeof b.agent === 'object' ? b.agent : {};
      const name = String(d.name || ca.name || '').trim().slice(0, 60), prompt = String(d.task || ca.prompt || '').trim().slice(0, 6000);
      if (!name || !prompt) return fail(404, 'Agent not found');
      agent = { id, owner: u.ws, name, prompt, tools: [] }; // client-defined agents never get tools
    }
    if (agent.rent_until && agent.rent_until < Date.now()) return fail(402, 'This rented agent has expired');
    const cap = capOf(u);
    const bonus = u.bonus_runs | 0, day = new Date().toISOString().slice(0, 10), budgetKey = 'ai:spend:' + day;
    if (!byok && u.used >= cap.runs + bonus) return fail(402, `You used all ${cap.runs + bonus} managed runs this month. Upgrade your plan, or connect your own API key.`, { limit: cap.runs + bonus, used: u.used });
    let spent = 0;
    if (!byok) {
      const dl = DAILY[plan] || DAILY.free, t = await one(env, "SELECT COUNT(*) n, COALESCE(SUM(cost),0) c FROM runs WHERE owner=? AND gateway='managed' AND at>=?", u.ws, Date.parse(day + 'T00:00:00Z'));
      if (t.n >= dl.runs) return fail(429, `Daily limit reached: ${dl.runs} managed runs per day on your plan. It resets at 00:00 UTC. Upgrade, or connect your own API key.`, { daily: true, limit: dl.runs });
      if (t.c >= dl.usd) return fail(429, 'Daily AI spending limit reached for your plan. It resets at 00:00 UTC. Upgrade, or connect your own API key.', { daily: true });
      if (env.QV_KV) { spent = (+(await env.QV_KV.get(budgetKey)) || 0) / 1e6; if (spent >= (+env.DAILY_AI_BUDGET_USD || 50)) return fail(503, 'AI capacity for today is used up. Please try again after 00:00 UTC.'); }
    }
    const r = await runAgent(env, u, agent, input, byok), cost = +(r.tokens / 1000 * RATE_PER_1K).toFixed(6), at = Date.now(), rid1 = rid();
    await run(env, 'INSERT INTO runs(id,owner,agent,input,output,steps,tokens,cost,gateway,ms,at) VALUES(?,?,?,?,?,?,?,?,?,?,?)', rid1, u.ws, agent.name, input.slice(0, 4000), r.text.slice(0, 20000), JSON.stringify(r.steps), r.tokens, cost, byok ? byok.provider : 'managed', r.ms, at);
    await run(env, 'UPDATE users SET used=used+?,tokens=tokens+?,cost=cost+? WHERE email=?', byok ? 0 : 1, r.tokens, cost, u.email);
    if (!byok && env.QV_KV) background(ctx, env.QV_KV.put(budgetKey, String(Math.round((spent + cost) * 1e6)), { expirationTtl: 172800 }));
    if (id !== 'qv-research') await logHistory(env, { owner: u.ws, type: 'run', title: agent.name, summary: `${r.tokens} tokens by ${u.email}`, detail: { runId: rid1, input: input.slice(0, 300), output: r.text.slice(0, 1500), by: u.email }, at });
    return json({ id: rid1, output: r.text, steps: r.steps, tokens: r.tokens, ms: r.ms, gateway: byok ? byok.provider : '', used: u.used + (byok ? 0 : 1), limit: cap.runs + bonus, ...(passOut ? { pass: passOut } : {}) });
  }
  if (p === '/api/runs' && m === 'GET') {
    const u = await needUser(); return json(await all(env, 'SELECT id,agent,input,output,tokens,gateway,ms,at FROM runs WHERE owner=? ORDER BY at DESC LIMIT ?', u.ws, intParam(q.get('limit'), 50, 1, 200)));
  }
  if (p === '/api/history' && m === 'GET') {
    const u = await needUser(), ty = q.get('type');
    return json((await all(env, 'SELECT id,type,title,summary,detail,at FROM history WHERE owner=? ' + (HISTORY_TYPES.includes(ty) ? 'AND type=? ' : '') + 'ORDER BY at DESC LIMIT ?', u.ws, ...(HISTORY_TYPES.includes(ty) ? [ty] : []), intParam(q.get('limit'), 100, 1, 300))).map((r) => ({ ...r, detail: parse(r.detail, {}) })));
  }

  // owner-only: shows which integrations are live and what is still missing (no secret values are ever returned)
  if (p === '/api/admin/readiness' && m === 'GET') {
    const u = await needUser(); needOwner(u);
    const chk = (name, ok, hint) => ({ name, ok: !!ok, hint: ok ? '' : hint });
    let dbOk = false; try { dbOk = !!(await one(env, 'SELECT 1 x')); } catch { /* reported below */ }
    return json({ checks: [
      chk('D1 database (DB)', dbOk, 'Bind a D1 database named DB'), chk('KV (QV_KV)', env.QV_KV, 'Bind the QV_KV namespace'), chk('Vault KV (QV_VAULT)', env.QV_VAULT, 'Bind the QV_VAULT namespace'),
      chk('JWT_SECRET', env.JWT_SECRET && env.JWT_SECRET.length >= 16, 'Set JWT_SECRET to 16+ random characters'), chk('Owner email', env.OWNER_EMAIL, 'Set OWNER_EMAIL so you can review manual payments'), chk('Public URL', env.PUBLIC_URL, 'Set PUBLIC_URL (needed for reminder emails and cron)'),
      chk('Email dispatch', mailReady(), 'Set MAIL_WEBHOOK_URL and MAIL_WEBHOOK_SECRET'), chk('AI model', env.ANTHROPIC_API_KEY, 'Set ANTHROPIC_API_KEY'),
      chk('Turnstile (AI bot protection)', env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET_KEY, 'Set TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY; until then AI runs are not bot-protected'),
      chk('Google sign-in', env.GOOGLE_CLIENT_ID, 'Set GOOGLE_CLIENT_ID and add your domain to Authorized JavaScript origins'), chk('GitHub sign-in', env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET, 'Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET; callback URL is ' + baseOf(env, url) + '/api/auth/github/callback'),
      chk('Telegram alerts', env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID, 'Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID'),
      chk('Stripe checkout', env.STRIPE_SECRET_KEY && env.STRIPE_WEBHOOK_SECRET, 'Set STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET and STRIPE_PRICE_<PLAN>'), chk('Lemon Squeezy (optional)', env.LEMON_API_KEY && env.LEMON_STORE_ID && env.LEMON_WEBHOOK_SECRET, 'Set LEMON_API_KEY, LEMON_STORE_ID, LEMON_WEBHOOK_SECRET and LEMON_VARIANT_<PLAN>'),
      chk('bKash number', env.BKASH_NUMBER, 'Set BKASH_NUMBER'), chk('Nagad number', env.NAGAD_NUMBER, 'Set NAGAD_NUMBER'), chk('Rocket number', env.ROCKET_NUMBER, 'Set ROCKET_NUMBER'), chk('Bitcoin Lightning', lnAddrOk(env.BTC_LIGHTNING_ADDRESS), 'Set BTC_LIGHTNING_ADDRESS (you@wallet.com)'),
      chk('Sandbox billing is off', !/^(1|true|yes)$/i.test(String(env.SANDBOX_BILLING || '')), 'Remove SANDBOX_BILLING in production'),
    ] });
  }
  // ----- API keys (shown once, stored as SHA-256) -----
  if (p === '/api/keys' && m === 'GET') { const u = await needUser(); await admin(u); return json(await all(env, 'SELECT id,hint,created FROM keys WHERE owner=? ORDER BY created DESC', u.ws)); }
  if (p === '/api/keys' && m === 'POST') {
    const u = await needUser(); await admin(u); const cap = capOf(u);
    if (await keysUsed(u.ws) >= cap.keys) return fail(402, `Your plan includes ${cap.keys} API key(s). Upgrade to create more.`);
    const key = 'qvm_live_' + rid(24), id = rid(6);
    await run(env, 'INSERT INTO keys(hash,id,owner,hint,created) VALUES(?,?,?,?,?)', await sha(key), id, u.ws, '…' + key.slice(-4), Date.now());
    await audit(env, u.ws, u.email, 'apikey.create', id);
    return json({ id, key, hint: '…' + key.slice(-4), note: 'Copy this key now. It is not shown again.' });
  }
  if ((mm = p.match(/^\/api\/keys\/([\w-]{3,40})$/)) && m === 'DELETE') {
    const u = await needUser(); await admin(u); const r = await run(env, 'DELETE FROM keys WHERE id=? AND owner=?', mm[1], u.ws);
    if (!r.meta || !r.meta.changes) return fail(404, 'Key not found'); await audit(env, u.ws, u.email, 'apikey.revoke', mm[1]); return json({ revoked: true });
  }

  // ----- webhook endpoint (signed with HMAC-SHA256, header x-qvmpxt-signature) -----
  if (p === '/api/hooks' && m === 'GET') { const u = await needUser(), h = await one(env, 'SELECT url FROM hooks WHERE owner=?', u.ws); return json({ url: h ? h.url : '', set: !!h }); }
  if (p === '/api/hooks' && m === 'PUT') {
    const u = await needUser(); await admin(u); if (planOf(u) === 'free') return fail(402, 'Webhook endpoints are included from the Starter plan.');
    const b = await readBody(5000), hu = String(b.url || '').trim().slice(0, 500); if (!validHookUrl(hu)) return fail(400, 'Enter a public http(s) URL (no localhost or private addresses)');
    const cur = await one(env, 'SELECT secret FROM hooks WHERE owner=?', u.ws), secret = cur ? cur.secret : 'whsec_' + rid(24);
    await run(env, 'INSERT INTO hooks(owner,url,secret) VALUES(?,?,?) ON CONFLICT(owner) DO UPDATE SET url=excluded.url', u.ws, hu, secret);
    await audit(env, u.ws, u.email, 'webhook.save', hu.slice(0, 80));
    return json({ url: hu, secret: cur ? undefined : secret, note: cur ? 'Endpoint updated. Your signing secret is unchanged.' : 'Copy the signing secret now. It is not shown again.' });
  }
  if (p === '/api/hooks' && m === 'DELETE') { const u = await needUser(); await admin(u); await run(env, 'DELETE FROM hooks WHERE owner=?', u.ws); await audit(env, u.ws, u.email, 'webhook.remove', ''); return json({ deleted: true }); }
  if (p === '/api/hooks/test' && m === 'POST') {
    const u = await needUser(); await write(u); if (limited(req, 'hooktest', 10, 60000)) return fail(429, 'Too many tests. Try again in a minute.');
    const h = await one(env, 'SELECT url,secret FROM hooks WHERE owner=?', u.ws); if (!h) return fail(404, 'Save an endpoint first');
    const r = await fireHook(h, 'webhook.test', { by: u.email }); return json({ delivered: r.status >= 200 && r.status < 300, status: r.status, error: r.error });
  }

  // ----- billing: manual proofs (mobile money, BTC), Stripe Checkout, Stripe webhook, sandbox -----
  const planCycle = (b) => { const plan = String(b.plan || '').toLowerCase(), cycle = b.cycle === 'yearly' || b.cycle === 'y' ? 'yearly' : 'monthly'; if (!PLANS[plan]) throw httpErr(400, 'Choose starter, growth or enterprise'); return { plan, cycle }; };
  const activate = (email, plan, cycle) => run(env, 'UPDATE users SET plan=?,plan_until=? WHERE email=?', plan, Date.now() + (cycle === 'yearly' ? 366 : 31) * 864e5, email);
  if (p === '/api/billing/proof' && m === 'POST') {
    const u = await needUser(); await admin(u); if (limited(req, 'bproof', 10, 60000)) return fail(429, 'Too many submissions. Try again in a minute.');
    const b = await readBody(5000), { plan, cycle } = planCycle(b), prov = String(b.provider || '').toLowerCase(), tx = String(b.txid || '').trim().toUpperCase().replace(/\s/g, '');
    if (!['btc', 'lightning', ...MOBILE].includes(prov)) return fail(400, 'Unknown payment method');
    if (prov === 'btc' || prov === 'lightning' ? !/^[A-Z0-9]{16,128}$/.test(tx) : !/^[A-Z0-9]{6,40}$/.test(tx)) return fail(400, 'Enter the transaction ID or receipt number');
    const ukey = `${prov}:${tx}`; if (await one(env, 'SELECT 1 x FROM payments WHERE ukey=?', ukey)) return fail(409, 'This transaction ID was already submitted');
    const pl = PLANS[plan], i = cycle === 'yearly' ? 1 : 0, mobile = MOBILE.includes(prov), amount = mobile ? pl.bdt[i] : prov === 'btc' || prov === 'lightning' ? pl.btc[i] : pl[cycle === 'yearly' ? 'yearly' : 'price'];
    const rec = { id: rid(), at: Date.now() };
    await run(env, "INSERT INTO payments(id,ukey,kind,txid,provider,plan,cycle,amount,currency,email,payer,status,at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending',?)", rec.id, ukey, 'plan', tx, prov, plan, cycle, amount, mobile ? 'BDT' : 'BTC', 'platform', u.email, rec.at);
    await audit(env, u.ws, u.email, 'billing.proof', `${plan}/${cycle} via ${prov}`);
    eventCard(env, ctx, '💳', 'PLAN PAYMENT PROOF', [['👤', 'User', u.name], ['📧', 'Email', u.email], ['📦', 'Plan', `${plan} (${cycle})`], ['🏦', 'Method', prov], ['🧾', 'TxID', tx], ['💰', 'Amount', `${amount} ${mobile ? 'BDT' : 'BTC'}`]], req);
    return json({ received: true, id: rec.id, message: 'Payment details received. Your plan turns on as soon as the founder confirms the transaction.' });
  }
  if (p === '/api/billing/checkout' && m === 'POST') {
    const u = await needUser(); await admin(u);
    const b = await readBody(5000), { plan, cycle } = planCycle(b);
    if (String(b.provider || '').toLowerCase() === 'lemon') {
      const variant = env['LEMON_VARIANT_' + plan.toUpperCase() + (cycle === 'yearly' ? '_YEARLY' : '')];
      if (!(env.LEMON_API_KEY && env.LEMON_STORE_ID && env.LEMON_WEBHOOK_SECRET)) return fail(503, 'Lemon Squeezy checkout is not configured on this server');
      if (!variant) return fail(503, `No Lemon Squeezy variant is set for ${plan} (${cycle})`);
      let lr, lj; try { lr = await fetch('https://api.lemonsqueezy.com/v1/checkouts', { method: 'POST', headers: { accept: 'application/vnd.api+json', 'content-type': 'application/vnd.api+json', authorization: 'Bearer ' + env.LEMON_API_KEY }, body: JSON.stringify({ data: { type: 'checkouts', attributes: { checkout_data: { email: u.email, name: u.name || '', custom: { email: u.email, plan, cycle } }, product_options: { redirect_url: baseOf(env, url) + '/#qv_msg=' + encodeURIComponent('Payment received. Your plan updates in a moment.') } }, relationships: { store: { data: { type: 'stores', id: String(env.LEMON_STORE_ID) } }, variant: { data: { type: 'variants', id: String(variant) } } } } }), signal: AbortSignal.timeout(15000) }); lj = await lr.json(); } catch { return fail(502, 'Lemon Squeezy did not respond. Try again.'); }
      const link = lj && lj.data && lj.data.attributes && lj.data.attributes.url;
      if (!lr.ok || !link) return fail(502, String((lj && lj.errors && lj.errors[0] && lj.errors[0].detail) || 'Lemon Squeezy rejected the request').replace(env.LEMON_API_KEY, '***').slice(0, 200));
      await audit(env, u.ws, u.email, 'billing.checkout', `${plan}/${cycle} lemon`); return json({ url: link });
    }
    if (!env.STRIPE_SECRET_KEY) return fail(503, 'Card checkout is not configured on this server');
    const price = env['STRIPE_PRICE_' + plan.toUpperCase() + (cycle === 'yearly' ? '_YEARLY' : '')];
    if (!price) return fail(503, `No Stripe price is set for ${plan} (${cycle})`);
    const base = baseOf(env, url), f = new URLSearchParams({ mode: 'subscription', 'line_items[0][price]': price, 'line_items[0][quantity]': '1', success_url: base + '/#qv_msg=' + encodeURIComponent('Payment received. Your plan updates in a moment.'), cancel_url: base + '/#qv_msg=' + encodeURIComponent('Checkout cancelled'), client_reference_id: u.email, 'metadata[email]': u.email, 'metadata[plan]': plan, 'metadata[cycle]': cycle, 'subscription_data[metadata][email]': u.email });
    if (u.stripe_customer) f.set('customer', u.stripe_customer); else f.set('customer_email', u.email);
    let r, j; try { r = await fetch('https://api.stripe.com/v1/checkout/sessions', { method: 'POST', headers: { authorization: 'Bearer ' + env.STRIPE_SECRET_KEY, 'content-type': 'application/x-www-form-urlencoded' }, body: f, signal: AbortSignal.timeout(15000) }); j = await r.json(); } catch { return fail(502, 'Stripe did not respond. Try again.'); }
    if (!r.ok || !j.url) return fail(502, String((j.error && j.error.message) || 'Stripe rejected the request').replace(env.STRIPE_SECRET_KEY, '***').slice(0, 200));
    await audit(env, u.ws, u.email, 'billing.checkout', `${plan}/${cycle}`); return json({ url: j.url });
  }
  if (p === '/api/stripe/webhook' && m === 'POST') {
    if (!env.STRIPE_WEBHOOK_SECRET) return fail(503, 'Stripe webhook is not configured');
    const raw = await req.text(), sg = String(req.headers.get('stripe-signature') || ''), parts = Object.fromEntries(sg.split(',').map((x) => x.split('=')).filter((x) => x.length === 2)), t = +parts.t;
    const want = t ? hex(await hmacRaw(env.STRIPE_WEBHOOK_SECRET, `${t}.${raw}`)) : '';
    if (!t || Math.abs(Date.now() / 1000 - t) > 300 || !parts.v1 || !safeEq(parts.v1, want)) return fail(400, 'Bad signature');
    const ev = parse(raw, null), o = ev && ev.data && ev.data.object; if (!o) return json({ received: true });
    if (ev.type === 'checkout.session.completed' && o.payment_status !== 'unpaid') {
      const md = o.metadata || {}, email = String(md.email || o.client_reference_id || '').toLowerCase(), plan = String(md.plan || ''), cycle = md.cycle === 'yearly' ? 'yearly' : 'monthly';
      if (PLANS[plan] && email && await one(env, 'SELECT 1 x FROM users WHERE email=?', email)) {
        const ins = await run(env, "INSERT OR IGNORE INTO payments(id,ukey,kind,txid,provider,plan,cycle,amount,currency,email,payer,status,reviewed_by,at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'approved','stripe',?)", rid(), 'stripe:' + o.id, 'plan', o.id, 'stripe', plan, cycle, (o.amount_total || 0) / 100, String(o.currency || 'usd').toUpperCase(), 'platform', email, Date.now());
        if (ins.meta && ins.meta.changes) { await activate(email, plan, cycle); if (o.customer) await run(env, 'UPDATE users SET stripe_customer=? WHERE email=?', String(o.customer), email); await audit(env, email, 'stripe', 'billing.paid', `${plan}/${cycle}`); eventCard(env, ctx, '💎', 'STRIPE PAYMENT', [['📧', 'Email', email], ['📦', 'Plan', `${plan} (${cycle})`], ['💰', 'Amount', `${(o.amount_total || 0) / 100} ${String(o.currency || 'usd').toUpperCase()}`]]); }
      }
    } else if (ev.type === 'invoice.paid' && o.billing_reason === 'subscription_cycle' && o.customer) {
      const us = await one(env, 'SELECT email,plan,plan_until FROM users WHERE stripe_customer=?', String(o.customer));
      if (us && us.plan !== 'free' && await run(env, "INSERT OR IGNORE INTO payments(id,ukey,kind,txid,provider,plan,amount,currency,email,payer,status,reviewed_by,at) VALUES(?,?,?,?,?,?,?,?,?,?,'approved','stripe',?)", rid(), 'stripe:' + o.id, 'plan', o.id, 'stripe', us.plan, (o.amount_paid || 0) / 100, String(o.currency || 'usd').toUpperCase(), 'platform', us.email, Date.now()).then((r) => r.meta && r.meta.changes))
        { const pe = +((((o.lines || {}).data || [])[0] || {}).period || {}).end * 1000, now = Date.now(); await run(env, 'UPDATE users SET plan_until=? WHERE email=?', pe > now && pe < now + 400 * 864e5 ? Math.max(pe + 864e5, us.plan_until || 0) : Math.max(now, us.plan_until || 0) + 31 * 864e5, us.email); }
    } else if (ev.type === 'customer.subscription.deleted' && o.customer) await run(env, "UPDATE users SET plan='free',plan_until=0 WHERE stripe_customer=?", String(o.customer));
    return json({ received: true });
  }
  if (p === '/api/lemon/webhook' && m === 'POST') {
    if (!env.LEMON_WEBHOOK_SECRET) return fail(503, 'Lemon Squeezy webhook is not configured');
    const raw = await req.text(), sig = String(req.headers.get('x-signature') || '').toLowerCase();
    if (!sig || !safeEq(sig, hex(await hmacRaw(env.LEMON_WEBHOOK_SECRET, raw)))) return fail(400, 'Bad signature');
    const ev = parse(raw, null), name = ev && ev.meta && ev.meta.event_name, cd = (ev && ev.meta && ev.meta.custom_data) || {}, d = (ev && ev.data) || {}, at = d.attributes || {};
    const email = String(cd.email || at.user_email || '').toLowerCase(), plan = String(cd.plan || ''), cycle = cd.cycle === 'yearly' ? 'yearly' : 'monthly';
    if (!name || !email || !(await one(env, 'SELECT 1 x FROM users WHERE email=?', email))) return json({ received: true });
    if (name === 'order_created' && at.status === 'paid' && PLANS[plan]) {
      const ins = await run(env, "INSERT OR IGNORE INTO payments(id,ukey,kind,txid,provider,plan,cycle,amount,currency,email,payer,status,reviewed_by,at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'approved','lemon',?)", rid(), 'lemon:order:' + d.id, 'plan', String(d.id), 'lemon', plan, cycle, (at.total || 0) / 100, String(at.currency || 'USD').toUpperCase(), 'platform', email, Date.now());
      if (ins.meta && ins.meta.changes) { await activate(email, plan, cycle); await audit(env, email, 'lemon', 'billing.paid', `${plan}/${cycle}`); eventCard(env, ctx, '🍋', 'LEMON SQUEEZY PAYMENT', [['📧', 'Email', email], ['📦', 'Plan', `${plan} (${cycle})`], ['💰', 'Amount', `${(at.total || 0) / 100} ${String(at.currency || 'USD').toUpperCase()}`]]); }
    } else if (name === 'subscription_payment_success' && at.billing_reason === 'renewal') {
      const last = await one(env, "SELECT plan,cycle FROM payments WHERE email=? AND provider='lemon' AND kind='plan' ORDER BY at DESC LIMIT 1", email), us = await one(env, 'SELECT plan,plan_until FROM users WHERE email=?', email);
      if (last && us && us.plan !== 'free') {
        const ins = await run(env, "INSERT OR IGNORE INTO payments(id,ukey,kind,txid,provider,plan,cycle,amount,currency,email,payer,status,reviewed_by,at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'approved','lemon',?)", rid(), 'lemon:pay:' + d.id, 'plan', String(d.id), 'lemon', last.plan, last.cycle, (at.total || 0) / 100, String(at.currency || 'USD').toUpperCase(), 'platform', email, Date.now());
        if (ins.meta && ins.meta.changes) await run(env, 'UPDATE users SET plan_until=? WHERE email=?', Math.max(Date.now(), us.plan_until || 0) + (last.cycle === 'yearly' ? 366 : 31) * 864e5, email);
      }
    } else if (name === 'subscription_expired' && await one(env, "SELECT 1 x FROM payments WHERE email=? AND provider='lemon' AND kind='plan'", email)) {
      await run(env, "UPDATE users SET plan='free',plan_until=0 WHERE email=?", email);
    }
    return json({ received: true });
  }
  // test mode only: set SANDBOX_BILLING=1 to let a signed-in Admin switch plans without paying. Never enable in production.
  if (p === '/api/billing/sandbox' && m === 'POST') {
    const u = await needUser(); await admin(u); if (!/^(1|true|yes)$/i.test(String(env.SANDBOX_BILLING || ''))) return fail(403, 'Sandbox billing is off');
    const { plan, cycle } = planCycle(await readBody(2000)); await activate(u.ws, plan, cycle);
    await run(env, "INSERT INTO payments(id,ukey,kind,txid,provider,plan,cycle,amount,currency,email,payer,status,reviewed_by,at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'approved','sandbox',?)", rid(), 'sandbox:' + rid(8), 'plan', 'sandbox', 'sandbox', plan, cycle, 0, 'USD', 'platform', u.ws, Date.now());
    await audit(env, u.ws, u.email, 'billing.sandbox', `${plan}/${cycle}`); return json({ plan, sandbox: true });
  }

  // ----- marketplace and orders (15% platform commission; the founder confirms payment, then the agent is delivered) -----
  if (p === '/api/market' && m === 'GET') return json((await all(env, 'SELECT id,by,name,task,tools,buy,rent,sales,created FROM market ORDER BY sales DESC,created DESC LIMIT 100')).map((r) => ({ ...r, tools: parse(r.tools, []) })));
  if (p === '/api/market' && m === 'POST') {
    const u = await needUser(); await write(u); needVerified(u); const b = await readBody(10000);
    const name = String(b.name || '').trim().slice(0, 60), task = String(b.task || '').trim().slice(0, 2000), buy = clamp(+b.buy || 0, 0, 1e5), rent = clamp(+b.rent || 0, 0, 1e5);
    if (!name || task.length < 10) return fail(400, 'Give your agent a name and a clear task (10+ characters)'); if (!(buy > 0 || rent > 0)) return fail(400, 'Set a buy price, a monthly rent price, or both');
    if ((await one(env, 'SELECT COUNT(*) n FROM market WHERE email=?', u.email)).n >= 20) return fail(409, 'You can list up to 20 agents');
    const id = rid(6); await run(env, 'INSERT INTO market(id,by,email,name,task,tools,buy,rent,sales,created) VALUES(?,?,?,?,?,?,?,?,0,?)', id, u.name, u.email, name, task, JSON.stringify((Array.isArray(b.tools) ? b.tools : []).filter((t) => TOOL_NAMES.includes(t))), buy, rent, Date.now());
    await audit(env, u.ws, u.email, 'market.list', id); return json({ id });
  }
  if ((mm = p.match(/^\/api\/market\/([\w-]{3,40})$/)) && m === 'DELETE') {
    const u = await needUser(), r = await run(env, 'DELETE FROM market WHERE id=? AND email=?', mm[1], u.email);
    if (!r.meta || !r.meta.changes) return fail(404, 'Listing not found'); await audit(env, u.ws, u.email, 'market.delist', mm[1]); return json({ deleted: true });
  }
  if (p === '/api/market/orders' && m === 'GET') {
    const u = await needUser(); return json(await all(env, 'SELECT id,item,mode,buyer,seller,gross,fee,net,settled,status,provider,at FROM orders WHERE buyer=? OR seller=? ORDER BY at DESC LIMIT 100', u.email, u.email));
  }
  if ((mm = p.match(/^\/api\/market\/([\w-]{3,40})\/order$/)) && m === 'POST') {
    const u = await needUser(); await write(u); needVerified(u); if (limited(req, 'order', 10, 60000)) return fail(429, 'Too many orders. Try again in a minute.');
    const it = await one(env, 'SELECT * FROM market WHERE id=?', mm[1]); if (!it) return fail(404, 'Listing not found'); if (it.email === u.email) return fail(400, 'You cannot order your own listing');
    const b = await readBody(5000), mode = b.mode === 'rent' ? 'rent' : 'buy', price = mode === 'rent' ? it.rent : it.buy; if (!(price > 0)) return fail(400, mode === 'rent' ? 'This agent is not offered for rent' : 'This agent is not for sale');
    const prov = String(b.provider || '').toLowerCase(), tx = String(b.txid || '').trim().toUpperCase().replace(/\s/g, '');
    if (!['btc', 'lightning', ...MOBILE].includes(prov)) return fail(400, 'Unknown payment method'); if (!/^[A-Z0-9]{6,128}$/.test(tx)) return fail(400, 'Enter the transaction ID or receipt number');
    if (await one(env, 'SELECT 1 x FROM orders WHERE txid=? AND provider=?', tx, prov)) return fail(409, 'This transaction ID was already submitted');
    const c = splitCommission(price), id = rid(6);
    await run(env, "INSERT INTO orders(id,item,mode,buyer,seller,gross,fee,net,settled,at,txid,provider,status) VALUES(?,?,?,?,?,?,?,?,0,?,?,?,'pending')", id, it.id, mode, u.email, it.email, c.gross, c.fee, c.net, Date.now(), tx, prov);
    await audit(env, u.ws, u.email, 'market.order', `${id} ${mode} ${it.id}`);
    eventCard(env, ctx, '🛒', 'MARKETPLACE ORDER', [['🆔', 'Order', id], ['📧', 'Buyer', u.email], ['🤖', 'Agent', it.name], ['🔁', 'Mode', mode], ['💰', 'Gross', `${c.gross} (fee ${c.fee})`], ['🏦', 'Method', prov], ['🧾', 'TxID', tx]], req);
    return json({ id, ...c, status: 'pending', message: 'Order received. The agent is added to your workspace as soon as the payment is confirmed.' });
  }
  if ((mm = p.match(/^\/api\/market\/orders\/([\w-]{3,40})\/(settle|reject)$/)) && m === 'POST') {
    const u = await needUser(); needOwner(u); const o = await one(env, 'SELECT * FROM orders WHERE id=?', mm[1]); if (!o) return fail(404, 'Order not found'); if (o.status !== 'pending') return fail(409, 'Already ' + o.status);
    if (mm[2] === 'reject') { await run(env, "UPDATE orders SET status='rejected' WHERE id=?", o.id); await audit(env, u.ws, u.email, 'market.order.reject', o.id); return json({ id: o.id, status: 'rejected' }); }
    const it = await one(env, 'SELECT * FROM market WHERE id=?', o.item); if (!it) return fail(410, 'The listing no longer exists');
    const t = await one(env, 'SELECT owner FROM teams WHERE email=? AND accepted=1', o.buyer), ws = t ? t.owner : o.buyer, rentUntil = o.mode === 'rent' ? Date.now() + 31 * 864e5 : 0;
    await run(env, 'INSERT INTO ws_docs(owner,kind,id,data,by,at,del) VALUES(?,?,?,?,?,?,0) ON CONFLICT(owner,kind,id) DO UPDATE SET data=excluded.data,by=excluded.by,at=excluded.at,del=0', ws, 'agent', 'mk-' + o.id, JSON.stringify({ name: it.name, task: it.task, rentUntil }), 'marketplace', Date.now());
    await run(env, "UPDATE orders SET status='approved',settled=1 WHERE id=?", o.id); await run(env, 'UPDATE market SET sales=sales+1 WHERE id=?', it.id);
    await audit(env, ws, u.email, 'market.order.settle', o.id); await audit(env, u.ws, u.email, 'market.order.settle', o.id);
    return json({ id: o.id, status: 'approved', delivered: true });
  }

  return fail(404, 'Not found');
}

// ---------- public pages: quote link, PDF, sitemap ----------
const NON_LATIN = /[^\x20-\x7e\u09f3\n]/;
function sharePage(brand, qt, owner, base) {
  const items = parse(qt.items, []), sub = subOf(items), taxAmt = +(qt.total - sub).toFixed(2), cur = qt.currency === 'BDT' ? '\u09f3' : '$', doc = qt.kind === 'invoice' ? 'Invoice' : 'Quotation';
  const fm = (n) => cur + Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const rows = items.map((i) => `<tr><td>${esc(i.name)}</td><td class="n">${+i.qty}</td><td class="n">${fm(i.price)}</td><td class="n">${fm(i.qty * i.price)}</td></tr>`).join('');
  const css = ':root{--bg:#f6f7fb;--card:#fff;--tx:#0b1020;--mu:#5b6478;--ac:#4f46e5;--ln:#e3e6ef;--ok:#047857;--bad:#b91c1c}@media(prefers-color-scheme:dark){:root{--bg:#070b18;--card:#0f1730;--tx:#f1f5f9;--mu:#94a3b8;--ac:#818cf8;--ln:#24305a;--ok:#34d399;--bad:#f87171}}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:16px/1.6 system-ui,-apple-system,"Noto Sans Bengali","Hind Siliguri","Nirmala UI",sans-serif;padding:max(16px,env(safe-area-inset-top)) 16px 40px}main{max-width:720px;margin:auto}.card{background:var(--card);border:1px solid var(--ln);border-radius:16px;padding:20px;margin:14px 0}h1{margin:0 0 4px;font-size:26px}h2{font-size:17px;margin:0 0 10px}.mu{color:var(--mu);margin:2px 0}table{width:100%;border-collapse:collapse}th,td{padding:8px 6px;border-bottom:1px solid var(--ln);text-align:left}.n{text-align:right;white-space:nowrap}.tot{font-size:22px;font-weight:800;text-align:right;margin-top:12px}.chip{display:inline-block;padding:2px 10px;border-radius:99px;border:1px solid var(--ln);font-size:13px;color:var(--ac);font-weight:700;text-transform:uppercase}button,.btn{display:inline-block;background:var(--ac);color:#fff;border:0;border-radius:10px;padding:10px 16px;font:inherit;font-weight:700;cursor:pointer;text-decoration:none;margin:4px 6px 4px 0}.btn.alt,button.alt{background:transparent;color:var(--ac);border:1px solid var(--ac)}input{width:100%;padding:10px;border-radius:10px;border:1px solid var(--ln);background:var(--bg);color:var(--tx);font:inherit;margin:6px 0}.ok{color:var(--ok)}.bad{color:var(--bad)}code{word-break:break-all;font-size:12px}@media print{body{background:#fff;color:#000}.noprint{display:none}.card{border-color:#ccc}}.pbx{display:inline-block;padding:7px 14px;border:1px solid var(--ln);border-radius:10px;color:var(--mu);font-size:11px;letter-spacing:.16em;text-transform:uppercase;text-decoration:none}.pbx b{color:var(--ac);letter-spacing:.2em}.logo{display:block;max-height:52px;max-width:180px;margin:0 0 10px}';
  const js = "const ID=" + JSON.stringify(qt.id) + ",$=s=>document.querySelector(s),api=(p,o)=>fetch('/api/public/quotes/'+ID+'/'+p,o).then(async r=>{const j=await r.json().catch(()=>({}));if(!r.ok)throw Error(j.error||'Request failed');return j}),msg=(t,bad)=>{const e=$('#msg');e.textContent=t;e.className=bad?'bad':'ok'},el=(t,x,c)=>{const e=document.createElement(t);if(x)e.textContent=x;if(c)e.className=c;return e};"
    + "const post=(p,b)=>api(p,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)});"
    + "function proof(box,prov,label){const i=el('input');i.placeholder=label;const b=el('button','I have paid');b.onclick=async()=>{try{const nm=($('#nm')||{}).value||'';const r=await post('proof',{provider:prov,txid:i.value,name:nm});msg(r.message)}catch(e){msg(e.message,1)}};box.append(i,b)}"
    + "async function pay(){const m=await api('methods');if(m.status==='paid'){$('#pay').replaceChildren(el('p','This link is paid. Thank you!','ok'));return}const box=$('#pay');"
    + "if(m.stripe){const d=el('div');d.append(el('h3','Card (Stripe)'));const a=el('a','Pay with card','btn');a.href=m.stripe;a.target='_blank';a.rel='noopener';d.append(a);proof(d,'stripe','Stripe receipt or payment ID');box.append(d)}"
    + "for(const k of Object.keys(m.mobile||{})){const d=el('div');d.append(el('h3',k.charAt(0).toUpperCase()+k.slice(1)));d.append(el('p','Send '+m.currency+' '+m.total+' to '+m.mobile[k]+', then paste the transaction ID.','mu'));proof(d,k,'Transaction ID');box.append(d)}"
    + "if(m.lightning){const d=el('div');d.append(el('h3','Bitcoin Lightning'));try{const l=await api('lightning');d.append(el('p',l.sats+' sats','mu'));const c=el('code',l.invoice||l.address);d.append(c);const a=el('a','Open in wallet','btn alt');a.href=l.qr;d.append(a)}catch(e){d.append(el('p',e.message,'bad'))}proof(d,'lightning','Payment hash or preimage');box.append(d)}"
    + "if(!box.children.length)box.append(el('p','The seller has not added payment methods yet. Please contact them directly.','mu'))}"
    + "$('#acc')&&($('#acc').onclick=async()=>{try{const r=await post('accept',{name:$('#nm').value});$('#st').textContent=r.status;msg('Accepted. Thank you!');$('#acc').hidden=true}catch(e){msg(e.message,1)}});"
    + "pay().catch(e=>msg(e.message,1));if(location.search.indexOf('print=1')>-1)setTimeout(()=>print(),400);";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="robots" content="noindex"><title>${esc(qt.title)} \u00b7 ${esc(brand)}</title><link rel="icon" href="/icon.svg"><style>${css}</style></head><body><main><div class="card">${/^https:\/\//.test(owner.logo || '') ? `<img class="logo" src="${esc(owner.logo)}" alt="${esc(owner.company || owner.name)}" referrerpolicy="no-referrer">` : ''}<span class="chip" id="st">${esc(qt.status)}</span><h1>${esc(doc)}: ${esc(qt.title)}</h1><p class="mu">From ${esc(owner.company || owner.name)}${qt.client ? ' \u00b7 For ' + esc(qt.client) : ''}</p><p class="mu">${new Date(qt.created).toISOString().slice(0, 10)} \u00b7 Ref ${esc(qt.id)}${qt.due_at ? ' \u00b7 Due ' + new Date(qt.due_at).toISOString().slice(0, 10) : ''}</p></div>`
    + `<div class="card"><table><tr><th>Item</th><th class="n">Qty</th><th class="n">Price</th><th class="n">Amount</th></tr>${rows}</table>${qt.tax ? `<p class="mu n">Subtotal ${fm(sub)}<br>Tax ${+qt.tax}% ${fm(taxAmt)}</p>` : ''}<div class="tot">${fm(qt.total)}</div>${qt.notes ? `<p class="mu" style="white-space:pre-wrap">${esc(qt.notes)}</p>` : ''}</div>`
    + `<div class="card noprint"><h2>Your name</h2><input id="nm" maxlength="80" placeholder="Full name" autocomplete="name">${qt.status === 'sent' ? '<button id="acc">Accept this ' + esc(doc.toLowerCase()) + '</button>' : ''}<a class="btn alt" href="/s/${esc(qt.id)}/pdf">Download PDF</a><button class="alt" onclick="print()">Print</button><p id="msg" class="mu" role="status"></p></div><div class="card noprint"><h2>Pay</h2><div id="pay"><p class="mu">Loading payment options\u2026</p></div></div><div style="text-align:center;margin:20px 0 6px"><a class="pbx" href="https://www.google.com/search?q=${encodeURIComponent(brand)}" target="_blank" rel="noopener noreferrer">Powered by <b>${esc(brand)}</b></a><p class="mu noprint" style="font-size:13px"><a href="${esc(base || '')}/#ref=${esc(qt.id)}" style="color:var(--ac)">Send your own quotation in 60 seconds, get paid \u2192</a></p></div></main><script>${js}</script></body></html>`;
}
const notFoundPage = (brand) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Not found \u00b7 ${esc(brand)}</title><body style="font:16px system-ui;text-align:center;padding:60px"><h1>This link is not available</h1><p>It may have been removed by the sender.</p></body>`;
const html = (body, status = 200) => new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'x-robots-tag': 'noindex, nofollow' } });

let TAIL_READY = false;
async function ensureTail(env) {
  if (TAIL_READY) return; // per-isolate flag
  const cols = ((await env.DB.prepare("SELECT name FROM pragma_table_info('orders')").all()).results || []).map((r) => r.name);
  for (const [c, d] of [['txid', "TEXT DEFAULT ''"], ['provider', "TEXT DEFAULT ''"], ['status', "TEXT DEFAULT 'pending'"]]) if (!cols.includes(c)) await env.DB.prepare(`ALTER TABLE orders ADD COLUMN ${c} ${d}`).run();
  const qc = ((await env.DB.prepare("SELECT name FROM pragma_table_info('quotes')").all()).results || []).map((r) => r.name);
  for (const [c, d] of [['due_at', 'INTEGER DEFAULT 0'], ['remind_n', 'INTEGER DEFAULT 0'], ['remind_at', 'INTEGER DEFAULT 0'], ['viewed_at', 'INTEGER DEFAULT 0']]) if (!qc.includes(c)) await env.DB.prepare(`ALTER TABLE quotes ADD COLUMN ${c} ${d}`).run();
  TAIL_READY = true;
}

async function pages(req, env, ctx, url) {
  const p = url.pathname, brand = brandOf(env), base = baseOf(env, url);
  let mm;
  if ((mm = p.match(/^\/s\/([\w-]{3,40})(\/pdf)?$/)) && (req.method === 'GET' || req.method === 'HEAD')) {
    const qt = await one(env, 'SELECT * FROM quotes WHERE id=?', mm[1]); if (!qt) return html(notFoundPage(brand), 404);
    const owner = await one(env, 'SELECT * FROM users WHERE email=?', qt.owner) || { name: '', company: '' };
    if (!mm[2]) { if (req.method === 'GET' && !BOT_UA.test(req.headers.get('user-agent') || '') && !url.searchParams.has('print')) background(ctx, trackView(env, ctx, qt, owner, base, brand)); return html(sharePage(brand, qt, owner, base)); }
    // PDF text is Helvetica only; Bengali or other scripts would turn into "?", so those go to the print page (the browser shapes the text correctly)
    const texts = [qt.title, qt.client, qt.notes, owner.company, owner.name, ...parse(qt.items, []).map((i) => i.name)].map((x) => String(x || ''));
    if (texts.some((s) => NON_LATIN.test(s))) return new Response(null, { status: 302, headers: { location: `/s/${qt.id}?print=1`, 'cache-control': 'no-store' } });
    return new Response(quotePdf(brand, qt, owner, base), { headers: { 'content-type': 'application/pdf', 'content-disposition': `inline; filename="${qt.kind}-${qt.id}.pdf"`, 'cache-control': 'no-store' } });
  }
  if (p === '/sw.js') return new Response(SW_SOURCE(brand), { headers: { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-cache', 'service-worker-allowed': '/' } });
  if (p === '/manifest.webmanifest') return new Response(MANIFEST(brand), { headers: { 'content-type': 'application/manifest+json; charset=utf-8', 'cache-control': 'public, max-age=3600' } });
  if (p === '/icon.svg') return new Response(ICON_SVG, { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'public, max-age=86400' } });
  return null;
}

// ---------- SEO: server-rendered, crawlable public pages ----------
// The app itself is a single-page app with #/hash routes. Google ignores everything after "#", so every public page
// below is also served here as real HTML at its own clean URL, with its own title, description, canonical link, structured
// data and internal links. /sitemap.xml lists all of them. Bump SITE_UPDATED when you change page content.
const SITE_UPDATED = '2026-11-10', LEGAL_UPDATED = '2026-11-09';
const FOUNDER = 'M Maruf Chowdhury', FOUNDER_ROLE = 'Founder & Chief Architect, QVMPXT', FOUNDER_COUNTRY = 'Bangladesh';
const FOUNDER_PHONE = '+8801347272307', FOUNDER_WA = '8801347272307', FOUNDER_EMAIL = 'marufchowdhury579@gmail.com';
const SEO_DESC = 'QVMPXT: send a quotation in 60 seconds and get paid. AI agents, quote links, compliance audits and an agent marketplace. Pay by card, Bitcoin or bKash / Nagad / Rocket.';
const SEO_BN = 'QVMPXT: ৬০ সেকেন্ডে কোটেশন পাঠান, পেমেন্ট নিন। এআই এজেন্ট, কোটেশন লিংক, কমপ্লায়েন্স অডিট ও এজেন্ট মার্কেটপ্লেস। কার্ড, বিটকয়েন এবং বিকাশ / নগদ / রকেটে পেমেন্ট গ্রহণ করুন।';
const NAV_LINKS = [['/', 'Home'], ['/meet-maruf', 'Meet Maruf'], ['/products', 'Products'], ['/solutions', 'Solutions'], ['/pricing', 'Pricing'], ['/contact', 'Contact']];
const PLAN_FEATURES = {
  starter: ['Everything in Free', '300 agent runs / month', 'Priority run queue', '5 team seats with role-based access', '3 API keys', 'Webhook for run events'],
  growth: ['Everything in Starter', '2,000 agent runs / month', '15 team seats with role-based access', '10 API keys'],
  enterprise: ['Everything in Growth', '20,000 agent runs / month', 'Unlimited team seats with role-based access', 'Unlimited API keys'],
};
// old or guessed URLs that should 301 to the real page
const SEO_ALIASES = { maruf: 'meet-maruf', founder: 'meet-maruf', about: 'meet-maruf', 'about-us': 'meet-maruf', 'meet-the-founder': 'meet-maruf', agents: 'ai-agents', agent: 'ai-agents', market: 'marketplace', saas: 'quotations', quotes: 'quotations', quote: 'quotations', pay: 'payments', billing: 'pricing', plans: 'pricing', audit: 'compliance-audits', audits: 'compliance-audits', iam: 'security', stats: 'developers', api: 'developers', dev: 'developers', 'privacy-policy': 'privacy', 'terms-of-service': 'terms', 'refund-policy': 'refund', 'contact-us': 'contact' };
const LEGAL_PAGES = {"privacy":["Privacy Policy",[["Who we are","QVMPXT is operated by M Maruf Chowdhury, Founder & Chief Architect. This policy explains what we collect, why, and the choices you have."],["What we collect","Account details you give us (name, email, phone number), your sign-in method (password, Google, GitHub or passkey), your plan and billing records (plan, amount, payment method and transaction ID), and the content you create (quotations, agents, runs and notes). Passwords are never stored in readable form: the server keeps only a salted PBKDF2-SHA256 hash. Passkeys store only a public key."],["Security and sign-in alerts","When you sign up or sign in, the founder receives a private security alert containing your name, email, phone number, browser and device type, and an approximate location (country and city) taken from the network request. We use this only to run, protect and support the service. It never includes your password or session token."],["Encrypted vault","With end-to-end encryption on, vault notes and audit input are encrypted in your browser with AES-256-GCM. The key comes from your passphrase and never leaves your browser. We store only ciphertext, so we cannot read it and cannot recover a forgotten passphrase."],["Who processes data for us","Cloudflare (hosting, database and bot protection), Stripe (card payments), Google and GitHub (sign-in), and Telegram (private founder alerts). Bitcoin, bKash, Nagad and Rocket payments are confirmed by us from the transaction ID you submit. We do not sell personal data and we do not share it for advertising."],["Quotation recipients","When you share a quotation link, the recipient sees its contents and the QVMPXT branding. We count views on the link so you can follow up. We do not give the recipient your other data."],["Your rights","You can edit your profile in Settings, export your workspace at any time, and ask us to delete your account and data through Message to the Founder (available when signed in). We keep payment records for as long as tax and accounting rules require."],["Retention and changes","We keep account data while your account is open and delete it after a deletion request, except records we must keep by law. If this policy changes in a material way we will show a notice in the app."]]],"terms":["Terms of Service",[["Acceptance","By creating an account or using QVMPXT you agree to these terms, the Privacy Policy and the Refund Policy. If you use QVMPXT for a business, you confirm you can bind that business."],["Your account","Give accurate details and keep your sign-in methods secure. You are responsible for activity on your account. AI features may require a verified email address, and use is limited per plan to protect the service."],["Acceptable use","Use the platform lawfully. Do not send unlawful, deceptive or abusive content, attack or overload the service, resell access without permission, or use it to harm others. We may suspend accounts that break these rules."],["Your content","You own your data and content. You give us only the permission needed to store, process and display it to run the service and to show quotation links you choose to share."],["Quotations and payments between you and your clients","QVMPXT provides the tool to create, share and track quotations. Any agreement or payment between you and your client is between the two of you. QVMPXT is not a party to it and does not guarantee payment."],["Plans and billing","Paid plans renew monthly or yearly until cancelled. Prices are in US dollars, or in Bangladeshi taka where bKash, Nagad or Rocket is used. Marketplace sales carry a 15% platform commission. Cancelling stops the next renewal; access continues to the end of the paid period."],["AI output","AI features can make mistakes. Check results before relying on them, especially for financial, legal or compliance decisions. QVMPXT does not provide legal, tax or financial advice."],["Availability and liability","We work to keep the service available but do not promise uninterrupted access. To the extent the law allows, QVMPXT is not liable for indirect or consequential losses, and our total liability is limited to the amount you paid in the three months before the claim."],["Changes and contact","We may update these terms and will show a notice for material changes. Questions can be sent through Message to the Founder when signed in."]]],"refund":["Refund Policy",[["Subscriptions","If you are not satisfied, ask for a refund of your first payment for a plan within 7 days of paying. Renewals are refundable within 48 hours of the renewal charge if the plan was not used after it. After that, cancel any time and keep access until the period ends."],["Usage","Refunds are not given for AI runs and tokens already used. If a technical fault on our side stopped a paid feature from working, we will fix it, extend your period or refund the affected time."],["How refunds are paid","Card payments (Stripe) go back to the original card. bKash, Nagad and Rocket payments go back to the same wallet number in taka. Bitcoin refunds are sent in BTC for the amount received, less network fees, to an address you give us. Banks and wallets may need several business days to show the money."],["Duplicate or wrong charges","If you were charged twice or the wrong amount, tell us with your transaction ID and we will correct it in full."],["Marketplace and quotation payments","Marketplace purchases and rentals are refunded by the seller under the listing terms; the 15% commission is returned with any full refund. Payments clients make to you for a quotation are between you and your client, so refunds for those are handled by you."],["How to ask","Open Message to the Founder (menu, when signed in) and include your account email, the transaction ID and the reason. We reply after verifying the payment."]]]};
const legalSections = (k) => LEGAL_PAGES[k][1].map(([h, p]) => ({ h, p }));

const SEO_PAGES = {
  'meet-maruf': {
    app: 'maruf', kind: 'profile', pri: '0.9', cf: 'monthly', lm: SITE_UPDATED, label: 'Meet Maruf',
    title: 'Meet Maruf | M Maruf Chowdhury, Founder of QVMPXT',
    desc: 'Meet M Maruf Chowdhury (Maruf), Founder & Chief Architect of QVMPXT from Bangladesh. His vision, mission, skills and how to contact him.',
    eyebrow: 'Meet the founder', h1: FOUNDER + ': Founder & Chief Architect of QVMPXT',
    lead: 'Building a sovereign AI and payments ecosystem for people everywhere: practical tools that help anyone quote, automate and get paid.',
    bn: 'এম মারুফ চৌধুরী (M Maruf Chowdhury) বাংলাদেশের উদ্যোক্তা এবং QVMPXT-এর প্রতিষ্ঠাতা ও চিফ আর্কিটেক্ট। তিনি এমন একটি সহজ ও নিরাপদ প্ল্যাটফর্ম তৈরি করছেন যেখানে যে কেউ কোটেশন পাঠাতে, এআই অটোমেশন চালাতে এবং পেমেন্ট নিতে পারে।',
    sections: [
      { h: 'Skills & strengths', p: 'What Maruf brings to building QVMPXT.', cards: [
        ['Product Thinking: from real-world observation', 'Turns everyday problems people face into simple, usable products.'],
        ['Quick Learner: with hands-on execution', 'Learns by building, ships fast and improves from real feedback.'],
        ['Natural Networker & Public Speaker', 'Connects easily with people and explains ideas in plain, confident words.'],
        ['Founder Mindset: early-stage builder', 'Owns the whole journey from first idea to a live product.'],
        ['AI Workflow Architect', 'Designs agent and automation workflows that save real time.'],
        ['Sovereign System Strategist', 'Plans systems that keep data, control and trust with their owners.'],
      ] },
      { h: 'Vision', p: 'A world where anyone, anywhere, can offer their work, win trust and get paid without needing a big company or a perfect bank account behind them.' },
      { h: 'Mission', p: 'Put advanced AI agents, instant global payments and secure automation into one simple, private, future-proof platform that stays easy for everyday people.' },
      { quote: ["Age doesn't limit ideas. Action does. Let's connect.", FOUNDER] },
      { h: 'About QVMPXT', p: 'QVMPXT lets freelancers, small businesses and teams send a branded quotation link in 60 seconds, run AI agents, audit records for compliance and get paid by card, Bitcoin or bKash / Nagad / Rocket.', links: [['Explore products', '/products'], ['See pricing', '/pricing']] },
      { h: "Let's connect", p: 'Questions, ideas or partnership? Message directly.', links: [['Chat on WhatsApp', 'https://wa.me/' + FOUNDER_WA, 1], ['Contact page', '/contact']] },
    ],
  },
  contact: {
    app: 'contact', kind: 'contact', pri: '0.7', cf: 'yearly', lm: SITE_UPDATED, label: 'Contact',
    title: 'Contact QVMPXT | WhatsApp, Phone & Email',
    desc: 'Contact QVMPXT and its founder Maruf by WhatsApp, phone or email. We read every message.',
    eyebrow: 'Contact', h1: 'Contact us', lead: 'We read every message. WhatsApp is the fastest way to reach Maruf.',
    sections: [
      { h: 'Ways to reach us', cards: [
        ['WhatsApp', 'The fastest way to reach Maruf: ' + FOUNDER_PHONE, 'https://wa.me/' + FOUNDER_WA],
        ['Phone', FOUNDER_PHONE, 'tel:' + FOUNDER_PHONE],
        ['Email', FOUNDER_EMAIL, 'mailto:' + FOUNDER_EMAIL],
        ['Message to the founder', 'Signed-in users can send a note from inside the app (menu > Message to the Founder).', '/#/contact'],
      ] },
      { h: 'Before you write', paras: ['For a refund, include your account email, the transaction ID and the reason. See our Refund Policy for the timelines.', 'For a business partnership, tell us a little about your company and what you have in mind.'], links: [['Refund Policy', '/refund'], ['Meet Maruf', '/meet-maruf']] },
    ],
  },
  products: {
    app: 'products', kind: 'page', pri: '0.8', cf: 'monthly', lm: SITE_UPDATED, label: 'Products',
    title: 'Products & Services | QVMPXT',
    desc: 'The building blocks of QVMPXT: AI agents, agent marketplace, quote links, payments and invoices, compliance audits, secure vault and a developer console.',
    eyebrow: 'Products', h1: 'Products & Services', lead: 'The building blocks of the QVMPXT ecosystem.',
    sections: [{ cards: [
      ['AI Agents', 'Voice commands, document OCR, a visual flow builder and a live research crawler.', '/ai-agents'],
      ['Agent Marketplace', 'List, rent or buy AI workflows. A 15% platform commission is routed automatically.', '/marketplace'],
      ['Quote Links', 'Branded, shareable quotes. Every view shows Powered by QVMPXT.', '/quotations'],
      ['Payments & Invoices', 'Stripe card, Bitcoin (including Lightning) and BDT mobile money with PDF invoices.', '/payments'],
      ['Compliance Audits', 'Rule checks plus anomaly detection with a readable report.', '/compliance-audits'],
      ['Vault & Access Control', 'Client-side AES-256-GCM vault, MFA, passkeys and role-based permissions.', '/security'],
      ['Developer Console', 'API keys, webhooks, system status and an activity logger.', '/developers'],
      ['Storage & Compute', 'See your workloads, quotas and the storage behind your workspace.'],
    ] }],
  },
  solutions: {
    app: 'solutions', kind: 'page', pri: '0.8', cf: 'monthly', lm: SITE_UPDATED, label: 'Solutions',
    title: 'Solutions for Freelancers, Agencies & Teams | QVMPXT',
    desc: 'QVMPXT solutions for freelancers, small businesses, agencies, compliance-minded teams, developers and builders who sell AI workflows.',
    eyebrow: 'Solutions', h1: 'Solutions', lead: 'Pick the situation that sounds like yours.',
    sections: [{ cards: [
      ['Freelancers & creators', 'Send a professional quote link in 60 seconds and get paid in the currency your client prefers.', '/quotations'],
      ['Small businesses', 'Take card, Bitcoin or mobile-money payments and keep PDF invoices in one place.', '/payments'],
      ['Agencies & teams', 'Share agents and quotes across a team with Admin, Editor and Viewer roles.', '/security'],
      ['Compliance-minded work', 'Scan content against rules and keep an audit trail of important actions.', '/compliance-audits'],
      ['Developers', 'Create API keys, test signed webhooks and connect QVMPXT to your own tools.', '/developers'],
      ['Builders who sell workflows', 'List an AI workflow on the marketplace and earn when others rent or buy it.', '/marketplace'],
    ] }],
  },
  pricing: {
    app: 'pay', kind: 'pricing', pri: '0.9', cf: 'monthly', lm: SITE_UPDATED, label: 'Pricing',
    title: 'Pricing: Free, Starter, Growth & Enterprise | QVMPXT',
    desc: 'QVMPXT plans from free to Enterprise. Starter $9, Growth $29, Enterprise $99 per month. Pay by card, Bitcoin or bKash / Nagad / Rocket (BDT).',
    eyebrow: 'Pricing', h1: 'Simple pricing that grows with you', lead: 'Start free. Upgrade only when you grow. Pay in USD by card, in Bitcoin (including Lightning) or in Bangladeshi taka with bKash, Nagad or Rocket. Yearly billing saves about two months.',
    sections: 'pricing',
  },
  'ai-agents': {
    app: 'agents', kind: 'page', pri: '0.8', cf: 'monthly', lm: SITE_UPDATED, label: 'AI Agents',
    title: 'AI Agents with Voice, OCR & Automation | QVMPXT',
    desc: 'Build and run AI agents by typing or by voice. Document OCR, live research, a visual flow builder, memory and tools that create quotes, invoices and audits.',
    eyebrow: 'AI Agents', h1: 'AI agents that do real work', lead: 'Describe a task once and let an agent run it again and again, from your keyboard, your voice or the API.',
    sections: [
      { h: 'What agents can do', list: [
        'Create a quotation or an invoice from a plain-language job description and return a shareable link plus a PDF.',
        'Audit pasted records for duplicates, missing approvals and anomalies, then explain the findings in plain language.',
        'Remember client preferences, rates and terms between runs (agent memory).',
        'Send a signed notification to your own webhook endpoint.',
        'Analyze documents with OCR, run live research and chain steps on a visual flow builder.',
      ] },
      { h: 'Use your own model key', p: 'Managed runs are powered by Claude. You can also connect your own OpenAI, Claude or DeepSeek API key, and your key runs do not use up the managed quota.' },
      { h: 'Plans and limits', p: 'Free includes 50 managed runs a month. Starter has 300, Growth 2,000 and Enterprise 20,000. Daily fair-use limits protect the service.', links: [['See pricing', '/pricing'], ['Open AI Agents', '/#/agents', 1]] },
      { h: 'Related', links: [['Agent marketplace', '/marketplace'], ['Developer API', '/developers'], ['Quotations', '/quotations']] },
    ],
  },
  marketplace: {
    app: 'market', kind: 'page', pri: '0.7', cf: 'monthly', lm: SITE_UPDATED, label: 'Marketplace',
    title: 'AI Agent Marketplace: List, Rent or Buy | QVMPXT',
    desc: 'List, rent or buy ready-made AI workflows on the QVMPXT agent marketplace. A 15% platform commission is split out automatically.',
    eyebrow: 'Marketplace', h1: 'The AI agent marketplace', lead: 'Turn a workflow that works into something others can rent or buy.',
    sections: [
      { h: 'How it works', list: ['Sellers list an agent with a buy price, a monthly rent price, or both.', 'Buyers pay by Bitcoin, Lightning, bKash, Nagad or Rocket and submit the transaction ID.', 'Once the payment is confirmed, the agent is delivered straight into the buyer\u2019s workspace. Rentals run for 31 days.', 'The platform keeps a 15% commission and the seller receives the rest.'] },
      { h: 'Good to know', p: 'Verified email is required to list or order. Each seller can list up to 20 agents. Refunds follow the listing terms and the 15% commission is returned with any full refund.', links: [['Refund Policy', '/refund'], ['Open the marketplace', '/#/market', 1]] },
      { h: 'Related', links: [['AI agents', '/ai-agents'], ['Payments', '/payments']] },
    ],
  },
  quotations: {
    app: 'saas', kind: 'page', pri: '0.9', cf: 'monthly', lm: SITE_UPDATED, label: 'Quotations',
    title: 'Send a Quotation in 60 Seconds, Get Paid | QVMPXT',
    desc: 'Create a branded quotation or invoice link in 60 seconds. Clients view, accept and pay on any device. Track views, get reminders and download a PDF.',
    eyebrow: 'Quote links', h1: 'Send a quotation in 60 seconds, get paid', lead: 'No heavy setup and nothing to install. Your client opens a link on any device, no account needed.',
    sections: [
      { h: 'From idea to paid in three steps', cards: [
        ['1. Create', 'Describe the work or let an AI agent draft your quote and documents.'],
        ['2. Share', 'Send a branded quote link. Your client opens it on any device.'],
        ['3. Get paid', 'Receive payment in the currency that suits your client, then track it in your history and invoices.'],
      ] },
      { h: 'What you get', list: [
        'Itemized quotes and invoices in USD or BDT, with tax and your logo.',
        'A shareable link and a downloadable PDF for every document.',
        'View tracking, so you know when your client opened it.',
        'One-tap acceptance by name, then payment by card, Bitcoin or mobile money.',
        'Automatic email reminders for overdue quotes and invoices (up to three).',
      ], links: [['Payments', '/payments'], ['Pricing', '/pricing'], ['Make a quote', '/#/saas', 1]] },
    ],
  },
  payments: {
    app: 'pay', kind: 'page', pri: '0.8', cf: 'monthly', lm: SITE_UPDATED, label: 'Payments',
    title: 'Payments: Card, Bitcoin, bKash, Nagad & Rocket | QVMPXT',
    desc: 'Get paid by card (Stripe), Bitcoin including Lightning, or bKash, Nagad and Rocket in Bangladeshi taka. PDF invoices for every plan.',
    eyebrow: 'Payments', h1: 'Local and global payments together', lead: 'bKash, Nagad and Rocket sit beside card and Bitcoin, so more of your clients can actually pay.',
    sections: [
      { h: 'Payment methods', cards: [
        ['Card (Stripe)', 'Pay a plan or a quotation with a credit or debit card.'],
        ['Bitcoin and Lightning', 'Pay on-chain or over the Lightning Network.'],
        ['bKash, Nagad and Rocket', 'Pay in Bangladeshi taka and submit the transaction ID for confirmation.'],
      ] },
      { h: 'Invoices and proof of payment', p: 'Every quotation and invoice has a PDF. When a client pays with a manual method, the seller reviews the transaction ID and marks the document as paid.', links: [['Quotations', '/quotations'], ['Pricing', '/pricing'], ['Refund Policy', '/refund']] },
    ],
  },
  'compliance-audits': {
    app: 'audit', kind: 'page', pri: '0.7', cf: 'monthly', lm: SITE_UPDATED, label: 'Compliance Audits',
    title: 'Compliance Audits & Anomaly Detection | QVMPXT',
    desc: 'Scan records for duplicate ids, missing approvals, weekend postings and statistical outliers. Get a risk score and a tamper-evident audit trail.',
    eyebrow: 'Compliance', h1: 'Compliance audits and anomaly detection', lead: 'Paste your records, get a readable report, highest risk first.',
    sections: [
      { h: 'What is checked', list: ['Duplicate ids.', 'Amounts above 1,000 without an approver, and above 10,000 without approval.', 'Entries posted on a weekend.', 'Statistical outliers compared with the average of the dataset.'] },
      { h: 'A trail you can trust', p: 'Sensitive actions are written to an append-only, hash-chained audit log. Rows cannot be edited or deleted, and any tampering breaks the chain. Audit input can also be end-to-end encrypted in your browser.', links: [['Security', '/security'], ['Open audits', '/#/audit', 1]] },
    ],
  },
  security: {
    app: 'iam', kind: 'page', pri: '0.7', cf: 'monthly', lm: SITE_UPDATED, label: 'Security',
    title: 'Security: Vault, MFA, Passkeys & Roles | QVMPXT',
    desc: 'AES-256-GCM encrypted vault, authenticator MFA, passkeys, role-based access and an immutable audit log. Your keys stay in your browser.',
    eyebrow: 'Security', h1: 'Privacy first, by design', lead: 'Built for real working life, so security does not need a security team.',
    sections: [
      { h: 'Protections', cards: [
        ['Encrypted vault', 'Notes are encrypted in your browser with AES-256-GCM. The key comes from your passphrase and never leaves your device. The server stores ciphertext only.'],
        ['MFA and passkeys', 'Authenticator-app codes with one-time recovery codes, plus passkeys (WebAuthn) for passwordless sign-in.'],
        ['Role-based access', 'Admin, Editor and Viewer roles are enforced on the server for every request.'],
        ['Immutable audit log', 'Append-only and hash-chained, so changes to history can be detected.'],
        ['Account safety', 'Passwords are stored only as salted PBKDF2-SHA256 hashes. Sessions can be revoked on all devices.'],
        ['Bot protection', 'Cloudflare Turnstile guards AI runs against abuse.'],
      ] },
      { h: 'Read more', links: [['Privacy Policy', '/privacy'], ['Terms of Service', '/terms'], ['Compliance audits', '/compliance-audits']] },
    ],
  },
  developers: {
    app: 'stats', kind: 'page', pri: '0.6', cf: 'monthly', lm: SITE_UPDATED, label: 'Developers',
    title: 'Developer API, Webhooks & API Keys | QVMPXT',
    desc: 'Create API keys, run agents over HTTP and receive HMAC-signed webhooks for quotes and agent events. Connect QVMPXT to your own tools.',
    eyebrow: 'Developers', h1: 'Connect QVMPXT to your own tools', lead: 'API keys, signed webhooks and a system status endpoint.',
    sections: [
      { h: 'API keys', p: 'Create keys in the developer console. A key starts with qvm_live_, is shown once and is stored only as a SHA-256 hash. Send it as a Bearer token to run agents and read your data.' },
      { h: 'Signed webhooks', p: 'Save a public https endpoint (from the Starter plan). Every delivery is signed with HMAC-SHA256 in the x-qvmpxt-signature header. Events include quote.viewed, quote.accepted, quote.paid, quote.reminder and agent.message.' },
      { h: 'Status', p: 'GET /api/health reports which services are live.', links: [['Pricing', '/pricing'], ['AI agents', '/ai-agents'], ['Open the console', '/#/stats', 1]] },
    ],
  },
  privacy: { app: 'privacy', kind: 'legal', pri: '0.4', cf: 'yearly', lm: LEGAL_UPDATED, label: 'Privacy Policy', title: 'Privacy Policy | QVMPXT', desc: 'How QVMPXT collects, uses and protects your data, and the choices you have.', eyebrow: 'Legal', h1: 'Privacy Policy', lead: 'Last updated 9 November 2026.', sections: legalSections('privacy') },
  terms: { app: 'terms', kind: 'legal', pri: '0.4', cf: 'yearly', lm: LEGAL_UPDATED, label: 'Terms of Service', title: 'Terms of Service | QVMPXT', desc: 'The terms for using QVMPXT: accounts, acceptable use, plans and billing, AI output and liability.', eyebrow: 'Legal', h1: 'Terms of Service', lead: 'Last updated 9 November 2026.', sections: legalSections('terms') },
  refund: { app: 'refund', kind: 'legal', pri: '0.4', cf: 'yearly', lm: LEGAL_UPDATED, label: 'Refund Policy', title: 'Refund Policy | QVMPXT', desc: 'QVMPXT refund policy for subscriptions, usage, duplicate charges, marketplace and quotation payments.', eyebrow: 'Legal', h1: 'Refund Policy', lead: 'Last updated 9 November 2026.', sections: legalSections('refund') },
};
const FOOT_GROUPS = [
  ['Company', ['meet-maruf', 'contact']],
  ['Product', ['ai-agents', 'marketplace', 'quotations', 'payments', 'compliance-audits', 'security', 'developers']],
  ['Explore', ['products', 'solutions', 'pricing']],
  ['Legal', ['privacy', 'terms', 'refund']],
];

const jsonLd = (o) => '<script type="application/ld+json">' + JSON.stringify(o).replace(/</g, '\\u003c') + '</script>';
const SEO_CSS = ':root{--bg:#03050c;--card:#0a1226;--tx:#f1f5f9;--mu:#94a3b8;--ln:rgba(148,163,184,.24);--cy:#00f0ff;--in:#6366f1}@media(prefers-color-scheme:light){:root{--bg:#f6f7fb;--card:#fff;--tx:#0b1020;--mu:#4b5568;--ln:#dfe3ee;--cy:#0369a1;--in:#4f46e5}}*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}body{margin:0;background:var(--bg);color:var(--tx);font:16px/1.65 system-ui,-apple-system,"Segoe UI","Noto Sans Bengali","Hind Siliguri","Nirmala UI",sans-serif;padding-top:env(safe-area-inset-top)}a{color:var(--cy)}.w{max-width:1000px;margin:auto;padding:0 16px}header{border-bottom:1px solid var(--ln);position:sticky;top:0;background:var(--bg);z-index:5}.hd{display:flex;align-items:center;gap:8px 18px;flex-wrap:wrap;padding:10px 0}.brand{display:flex;align-items:center;gap:10px;font-weight:800;letter-spacing:.14em;text-decoration:none;color:var(--tx)}.brand svg{width:34px;height:34px}nav.m{display:flex;gap:2px 16px;flex-wrap:wrap;margin-left:auto}nav.m a{color:var(--mu);text-decoration:none;padding:4px 2px;font-size:15px}nav.m a:hover,nav.m a[aria-current]{color:var(--cy)}.crumb{font-size:13px;color:var(--mu);margin-top:18px}.crumb a{color:var(--mu)}.eye{display:inline-block;color:var(--cy);font-size:12px;letter-spacing:.16em;text-transform:uppercase;font-weight:700;margin-top:14px}h1{font-size:clamp(28px,5vw,42px);line-height:1.15;margin:8px 0 12px}h2{font-size:24px;margin:38px 0 10px}h3{font-size:17px;margin:0 0 6px}.lead{color:var(--mu);font-size:18px;max-width:46em}.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));margin-top:14px}.card{background:var(--card);border:1px solid var(--ln);border-radius:14px;padding:16px}.card p{margin:0;color:var(--mu)}.card a{text-decoration:none}.price{font-size:26px;font-weight:800;margin:2px 0 6px}.price small{font-size:14px;font-weight:400;color:var(--mu)}ul{padding-left:20px}li{margin:5px 0}blockquote{margin:22px 0;padding:16px 20px;border-left:3px solid var(--cy);background:var(--card);border-radius:10px;font-size:20px}blockquote cite{display:block;font-size:14px;color:var(--mu);margin-top:8px;font-style:normal}.btn{display:inline-block;background:var(--in);color:#fff;padding:11px 18px;border-radius:10px;text-decoration:none;font-weight:700;margin:8px 8px 4px 0}.btn.alt{background:transparent;color:var(--cy);border:1px solid var(--cy)}.band{margin:44px 0 10px;padding:26px;border:1px solid var(--ln);border-radius:16px;background:var(--card);text-align:center}.band h2{margin-top:0}.bn{margin-top:26px;padding:14px 16px;border:1px dashed var(--ln);border-radius:12px;color:var(--mu)}footer{margin-top:50px;border-top:1px solid var(--ln);padding:26px 0 44px;color:var(--mu);font-size:14px}.fg{display:grid;gap:20px;grid-template-columns:repeat(auto-fit,minmax(170px,1fr))}footer b{display:block;color:var(--tx);margin-bottom:6px}footer a{display:block;color:var(--mu);text-decoration:none;padding:2px 0}footer a:hover{color:var(--cy)}.cp{margin-top:22px}';

function seoSection(s) {
  const link = (l) => `<a class="btn${l[2] ? '' : ' alt'}" href="${esc(l[1])}"${/^https?:/.test(l[1]) ? ' target="_blank" rel="noopener noreferrer"' : ''}>${esc(l[0])}</a>`;
  return '<section>' + (s.h ? `<h2>${esc(s.h)}</h2>` : '') + (s.p ? `<p${s.h ? '' : ' class="lead"'}>${esc(s.p)}</p>` : '')
    + (s.paras ? s.paras.map((x) => `<p>${esc(x)}</p>`).join('') : '')
    + (s.list ? `<ul>${s.list.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : '')
    + (s.cards ? `<div class="grid">${s.cards.map((c) => `<article class="card"><h3>${c[2] ? `<a href="${esc(c[2])}"${/^https?:/.test(c[2]) ? ' target="_blank" rel="noopener noreferrer"' : ''}>${esc(c[0])}</a>` : esc(c[0])}</h3><p>${esc(c[1])}</p></article>`).join('')}</div>` : '')
    + (s.quote ? `<blockquote>\u201c${esc(s.quote[0])}\u201d<cite>\u2014 ${esc(s.quote[1])}</cite></blockquote>` : '')
    + (s.links ? `<p>${s.links.map(link).join('')}</p>` : '') + '</section>';
}
function pricingSections() {
  const fm = (n) => Number(n).toLocaleString('en-US'), card = (name, price, sub, feats) => `<article class="card"><h3>${esc(name)}</h3><div class="price">${price}</div><p>${esc(sub)}</p><ul>${feats.map((f) => `<li>${esc(f)}</li>`).join('')}</ul></article>`;
  const free = card('Free', '$0 <small>/ month</small>', 'Try everything at no cost.', [`${FREE.runs} managed AI runs / month`, `${FREE.seats} team seats`, `${FREE.keys} API key`, 'Quote links, PDF and payments']);
  const paid = Object.entries(PLANS).map(([id, p]) => card(id[0].toUpperCase() + id.slice(1), `$${p.price} <small>/ month</small>`, `or $${p.yearly} / year \u00b7 \u09f3${fm(p.bdt[0])} / month in BDT`, PLAN_FEATURES[id] || []));
  return `<section><h2>Plans</h2><div class="grid">${free}${paid.join('')}</div></section>`
    + seoSection({ h: 'How you can pay', list: ['Card (Stripe), in US dollars.', 'Bitcoin, including the Lightning Network.', 'bKash, Nagad and Rocket in Bangladeshi taka.'], links: [['Read the Refund Policy', '/refund'], ['Compare in the app', '/#/pay', 1]] });
}

// A complete, self-contained HTML document for a public page (no database access, so it stays fast and always works)
function seoDoc(env, url, slug, pg, opts = {}) {
  const base = baseOf(env, url), brand = brandOf(env), canon = slug ? `${base}/${slug}` : base + '/', crumbName = pg.label || pg.h1;
  const robots = opts.noindex ? 'noindex,follow' : 'index,follow,max-snippet:-1,max-image-preview:large,max-video-preview:-1';
  const org = { '@type': 'Organization', '@id': base + '/#org', name: brand, url: base + '/', logo: { '@type': 'ImageObject', url: base + '/icon.svg' }, founder: { '@id': `${base}/meet-maruf#person` } };
  const site = { '@type': 'WebSite', '@id': base + '/#website', url: base + '/', name: brand, alternateName: ['Qvmpxt', 'QVMPXT AI', 'QVMPXT Sovereign AI & Financial Ecosystem'], inLanguage: 'en', publisher: { '@id': base + '/#org' } };
  const graph = [site, org];
  if (!opts.noindex) {
    const typ = { profile: 'ProfilePage', contact: 'ContactPage' }[pg.kind] || 'WebPage';
    graph.push({ '@type': typ, '@id': canon + '#page', url: canon, name: pg.title, description: pg.desc, inLanguage: 'en', isPartOf: { '@id': base + '/#website' }, dateModified: pg.lm || SITE_UPDATED, breadcrumb: { '@id': canon + '#crumbs' }, ...(pg.kind === 'profile' ? { mainEntity: { '@id': `${base}/meet-maruf#person` } } : {}) });
    graph.push({ '@type': 'BreadcrumbList', '@id': canon + '#crumbs', itemListElement: [{ '@type': 'ListItem', position: 1, name: 'Home', item: base + '/' }, { '@type': 'ListItem', position: 2, name: crumbName, item: canon }] });
    if (pg.kind === 'profile') graph.push({ '@type': 'Person', '@id': `${base}/meet-maruf#person`, name: FOUNDER, alternateName: ['Maruf Chowdhury', 'Maruf', 'M Maruf Chowdhury'], jobTitle: FOUNDER_ROLE, description: pg.lead, url: canon, nationality: { '@type': 'Country', name: FOUNDER_COUNTRY }, worksFor: { '@id': base + '/#org' }, knowsAbout: ['Artificial intelligence', 'AI agents', 'Online payments', 'Automation', 'Quotations and invoicing'] });
    if (pg.kind === 'pricing') graph.push({ '@type': 'SoftwareApplication', '@id': base + '/#app', name: brand, applicationCategory: 'BusinessApplication', operatingSystem: 'Web', url: base + '/', offers: [{ '@type': 'Offer', name: 'Free', price: '0', priceCurrency: 'USD', url: canon }, ...Object.entries(PLANS).map(([id, p]) => ({ '@type': 'Offer', name: id[0].toUpperCase() + id.slice(1), price: String(p.price), priceCurrency: 'USD', url: canon }))] });
  }
  const body = pg.sections === 'pricing' ? pricingSections() : (pg.sections || []).map(seoSection).join('');
  const nav = NAV_LINKS.map(([h, l]) => `<a href="${h}"${h === '/' + slug && slug ? ' aria-current="page"' : ''}>${esc(l)}</a>`).join('');
  const foot = FOOT_GROUPS.map(([t, ids]) => `<div><b>${esc(t)}</b>${ids.map((id) => `<a href="/${id}">${esc(SEO_PAGES[id].label)}</a>`).join('')}</div>`).join('');
  const cta = opts.noindex ? '' : `<div class="band"><h2>Ready to send your first quote?</h2><p>Start on the free plan. Upgrade only when you grow.</p><a class="btn" href="${esc(base)}/#/${esc(pg.app || 'saas')}">Open ${esc(brand)}</a><a class="btn alt" href="/pricing">See pricing</a></div>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>${esc(pg.title)}</title><meta name="description" content="${esc(pg.desc)}"><meta name="robots" content="${robots}">`
    + (opts.noindex ? '' : `<link rel="canonical" href="${esc(canon)}"><link rel="alternate" hreflang="en" href="${esc(canon)}"><link rel="alternate" hreflang="x-default" href="${esc(canon)}">`)
    + `<meta name="theme-color" content="#03050C"><meta property="og:site_name" content="${esc(brand)}"><meta property="og:type" content="${pg.kind === 'profile' ? 'profile' : 'website'}"><meta property="og:title" content="${esc(pg.title)}"><meta property="og:description" content="${esc(pg.desc)}"><meta property="og:url" content="${esc(canon)}"><meta name="twitter:card" content="summary"><meta name="twitter:title" content="${esc(pg.title)}"><meta name="twitter:description" content="${esc(pg.desc)}">`
    + `<link rel="icon" type="image/svg+xml" href="/icon.svg" sizes="any"><link rel="manifest" href="/manifest.webmanifest"><style>${SEO_CSS}</style>${jsonLd({ '@context': 'https://schema.org', '@graph': graph })}</head><body>`
    + `<header><div class="w hd"><a class="brand" href="/" aria-label="${esc(brand)} home">${ICON_SVG}<span>${esc(brand)}</span></a><nav class="m" aria-label="Main">${nav}</nav></div></header>`
    + `<main class="w">${opts.noindex ? '' : `<p class="crumb"><a href="/">Home</a> \u203a ${esc(crumbName)}</p>`}<span class="eye">${esc(pg.eyebrow || '')}</span><h1>${esc(pg.h1)}</h1><p class="lead">${esc(pg.lead || '')}</p>${body}${pg.bn ? `<p class="bn" lang="bn">${esc(pg.bn)}</p>` : ''}${cta}</main>`
    + `<footer><div class="w"><div class="fg">${foot}</div><p class="cp">\u00a9 2026 ${esc(brand)} Holding. ${esc(FOUNDER)}, ${esc(FOUNDER_ROLE)}. <a href="${esc(base)}/">Open the app</a></p></div></footer></body></html>`;
}
const seoHeaders = (type, extra) => ({ 'content-type': type, 'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin', 'x-frame-options': 'SAMEORIGIN', ...extra });
const seoRedirect = (url, path) => new Response(null, { status: 301, headers: { location: url.origin + path, 'cache-control': 'public, max-age=3600' } });
const seoNotFound = (env, url) => new Response(seoDoc(env, url, '', { title: 'Page not found | ' + brandOf(env), desc: 'This page does not exist.', eyebrow: '404', h1: 'We could not find that page', lead: 'The link may be old or mistyped. Try one of these pages.', sections: [{ cards: Object.entries(SEO_PAGES).slice(0, 6).map(([id, p]) => [p.label, p.desc, '/' + id]) }] }, { noindex: true }), { status: 404, headers: seoHeaders('text/html; charset=utf-8', { 'cache-control': 'no-store', 'x-robots-tag': 'noindex' }) });

// extra <head> tags and a crawlable site map for the home page (the home page itself is the app, so for guests it shows the sign-in screen)
function seoHomeParts(env, url) {
  const base = baseOf(env, url), brand = brandOf(env);
  const head = `<link rel="canonical" href="${esc(base)}/"><link rel="alternate" hreflang="en" href="${esc(base)}/"><link rel="alternate" hreflang="x-default" href="${esc(base)}/"><meta name="robots" content="index,follow,max-snippet:-1,max-image-preview:large,max-video-preview:-1"><meta property="og:url" content="${esc(base)}/"><meta property="og:site_name" content="${esc(brand)}"><meta name="twitter:card" content="summary"><link rel="icon" type="image/svg+xml" href="/icon.svg" sizes="any">`
    + jsonLd({ '@context': 'https://schema.org', '@graph': [
      { '@type': 'WebSite', '@id': base + '/#website', url: base + '/', name: brand, alternateName: ['Qvmpxt', 'QVMPXT AI', 'QVMPXT Sovereign AI & Financial Ecosystem'], inLanguage: 'en', publisher: { '@id': base + '/#org' } },
      { '@type': 'Organization', '@id': base + '/#org', name: brand, url: base + '/', logo: { '@type': 'ImageObject', url: base + '/icon.svg' }, founder: { '@id': `${base}/meet-maruf#person` } },
      { '@type': 'Person', '@id': `${base}/meet-maruf#person`, name: FOUNDER, alternateName: ['Maruf Chowdhury', 'Maruf'], jobTitle: FOUNDER_ROLE, url: base + '/meet-maruf', worksFor: { '@id': base + '/#org' } },
      { '@type': 'SiteNavigationElement', name: Object.values(SEO_PAGES).map((p) => p.label), url: Object.keys(SEO_PAGES).map((id) => `${base}/${id}`) },
    ] });
  const hide = 'position:absolute!important;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);clip-path:inset(50%);white-space:nowrap;border:0';
  const block = `<div id="qv-seo" style="${hide}"><h1>${esc(brand)}: Send a quotation in 60 seconds, get paid</h1><p>${esc(SEO_DESC)}</p><p lang="bn">${esc(SEO_BN)}</p><nav aria-label="${esc(brand)} pages"><ul>${Object.entries(SEO_PAGES).map(([id, p]) => `<li><a href="/${id}">${esc(p.label)}</a>: ${esc(p.desc)}</li>`).join('')}</ul></nav></div><noscript><p>${esc(brand)} needs JavaScript to run the app. You can still read about it: <a href="/products">Products</a>, <a href="/pricing">Pricing</a>, <a href="/meet-maruf">Meet Maruf</a>.</p></noscript>`;
  return { head, block };
}
function seoHome(env, url, r) {
  const ct = r && r.headers.get('content-type') || '';
  if (!r || !r.ok || !/text\/html/i.test(ct) || typeof HTMLRewriter === 'undefined') {
    if (r && r.ok && /text\/html/i.test(ct)) return r;
    // static assets missing: still serve a real home page instead of an error
    return new Response(seoDoc(env, url, '', { title: brandOf(env) + ' | Send quotation in 60 seconds, get paid', desc: SEO_DESC, eyebrow: 'Sovereign AI & Financial Ecosystem', h1: 'Smart Solutions, Limitless Possibilities: Your Complete AI Ecosystem', lead: SEO_DESC, bn: SEO_BN, app: 'saas', kind: 'page', label: 'Home', sections: [{ cards: Object.entries(SEO_PAGES).map(([id, p]) => [p.label, p.desc, '/' + id]) }] }), { status: 200, headers: seoHeaders('text/html; charset=utf-8', { 'cache-control': 'public, max-age=300' }) });
  }
  const { head, block } = seoHomeParts(env, url);
  const out = new HTMLRewriter().on('head', { element(e) { e.append(head, { html: true }); } }).on('body', { element(e) { e.append(block, { html: true }); } }).transform(r);
  const h = new Headers(r.headers); h.delete('content-length'); h.set('x-content-type-options', 'nosniff'); h.set('referrer-policy', 'strict-origin-when-cross-origin'); h.set('x-frame-options', 'SAMEORIGIN'); h.set('x-robots-tag', 'index, follow');
  return new Response(out.body, { status: r.status, headers: h });
}
function seoSitemap(env, url) {
  const base = baseOf(env, url), u = [['/', SITE_UPDATED, 'weekly', '1.0'], ...Object.entries(SEO_PAGES).map(([id, p]) => ['/' + id, p.lm || SITE_UPDATED, p.cf || 'monthly', p.pri || '0.6'])];
  return new Response('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + u.map(([path, lm, cf, pr]) => `  <url><loc>${esc(base + path)}</loc><lastmod>${lm}</lastmod><changefreq>${cf}</changefreq><priority>${pr}</priority></url>`).join('\n') + '\n</urlset>\n', { headers: { 'content-type': 'application/xml; charset=utf-8', 'cache-control': 'public, max-age=3600' } });
}
// routes that need no database: sitemap, robots, favicon, clean-URL public pages and their redirects
function seoRoute(req, env, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return null;
  const p = url.pathname, base = baseOf(env, url);
  if (p === '/sitemap.xml') return seoSitemap(env, url);
  if (p === '/robots.txt') return new Response(`User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /s/\nDisallow: /*?print=\n\nSitemap: ${base}/sitemap.xml\n`, { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'public, max-age=3600' } });
  if (p === '/favicon.ico') return seoRedirect(url, '/icon.svg');
  if (p === '/index.html') return seoRedirect(url, '/');
  const clean = p.length > 1 ? p.replace(/\/+$/, '').toLowerCase() : p, slug = clean.slice(1), own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
  if (!slug || slug.includes('/')) return null;
  if (own(SEO_ALIASES, slug)) return seoRedirect(url, '/' + SEO_ALIASES[slug]);
  if (!own(SEO_PAGES, slug)) return null;
  const pg = SEO_PAGES[slug];
  if (clean !== p) return seoRedirect(url, '/' + slug);
  return new Response(req.method === 'HEAD' ? null : seoDoc(env, url, slug, pg), { headers: seoHeaders('text/html; charset=utf-8', { 'cache-control': 'public, max-age=600, s-maxage=3600, stale-while-revalidate=86400', 'x-robots-tag': 'index, follow', link: `<${base}/${slug}>; rel="canonical"` }) });
}

function cors(env, req, res) {
  const o = req.headers.get('origin'), allow = String(env.ALLOWED_ORIGIN || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!o || !allow.includes(o)) return res;
  const h = new Headers(res.headers); h.set('access-control-allow-origin', o); h.set('vary', 'origin'); h.set('access-control-allow-headers', 'authorization,content-type'); h.set('access-control-allow-methods', 'GET,POST,PUT,DELETE,OPTIONS');
  return new Response(res.body, { status: res.status, headers: h });
}

export default {
  // optional cron trigger (Workers): sends overdue reminders even when nobody visits. Pages ignores this; traffic triggers the same job hourly.
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => { await ensureSchema(env); await ensureTail(env); await sweepOverdue(env, baseOf(env, { origin: '' }), brandOf(env)); })().catch(() => {}));
  },
  async fetch(req, env, ctx) {
    const url = new URL(req.url), p = url.pathname;
    try {
      if (req.method === 'OPTIONS' && p.startsWith('/api/')) return cors(env, req, new Response(null, { status: 204 }));
      const isApi = p.startsWith('/api/');
      if (isApi || p.startsWith('/s/')) { await ensureSchema(env); await ensureTail(env); background(ctx, maybeSweep(env, baseOf(env, url), brandOf(env))); }
      if (isApi) return cors(env, req, await api(req, env, ctx, url));
      const sr = seoRoute(req, env, url); if (sr) return sr;
      const pg = await pages(req, env, ctx, url); if (pg) return pg;
      if (!env.ASSETS) return p === '/' ? seoHome(env, url, null) : seoNotFound(env, url);
      let r = await env.ASSETS.fetch(req);
      if (p === '/') { if (!r.ok) { const r2 = await env.ASSETS.fetch(new Request(new URL('/qvmpxt.html', url), req)).catch(() => null); if (r2 && r2.ok) r = r2; } return seoHome(env, url, r); }
      // unknown page addresses return a real 404 (not the home page with status 200, which Google counts as a soft 404)
      if (r.status === 404 && !/\.[a-z0-9]{1,8}$/i.test(p)) return seoNotFound(env, url);
      const h = new Headers(r.headers); h.set('x-content-type-options', 'nosniff'); h.set('referrer-policy', 'strict-origin-when-cross-origin'); h.set('x-frame-options', 'SAMEORIGIN');
      return new Response(r.body, { status: r.status, headers: h });
    } catch (e) {
      if (e && e.status) return cors(env, req, fail(e.status, e.message, e.extra));
      background(ctx, sentry(env, e, { path: p, method: req.method }));
      return cors(env, req, fail(500, 'Something went wrong on our side. Please try again.'));
    }
  },
};
