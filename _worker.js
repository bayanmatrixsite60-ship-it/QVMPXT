// Qvmpxt unified backend: ONE script for Cloudflare Workers / Pages (_worker.js) and Node 18+ (node _worker.js).
// Router, data store, auth, agents, audit engine, billing, feed, team, API keys, webhooks, i18n packs,
// share pages, service worker and PWA manifest. No dependencies.
//
// Cloudflare Pages: put this file next to index.html (the Qvmpxt frontend; qvmpxt.html also works) and deploy.
//   Optional bindings: QV_KV (KV namespace that stores the data snapshot).
//   Env vars: JWT_SECRET (required in production), ANTHROPIC_API_KEY, MODEL, PUBLIC_URL, ALLOWED_ORIGIN, BRAND,
//   OWNER_EMAIL (reviews mobile-banking payments), SITEMAP_PATHS (comma list of extra public paths),
//   STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_STARTER/GROWTH/ENTERPRISE (+ _YEARLY variants),
//   SANDBOX_BILLING=1 (lets /api/billing/subscribe activate plans without Stripe; for testing only).
// Node: node _worker.js (Node 22+ detects ESM; on Node 18/20 save as server.mjs or add {"type":"module"} to package.json).
//   Reads index.html (or qvmpxt.html) from the same folder. PORT sets the port (default 3000).
//   Data persists to ./qvmpxt-data.json (override with QV_DATA=/path, disable with QV_DATA=off). Keep it out of git.

const DEFAULT_BRAND = 'Qvmpxt';
// price = USD monthly, yearly = USD yearly, bdt / btc = [monthly, yearly]
const PLANS = {
  starter: { price: 9, yearly: 89, runs: 300, bdt: [990, 9900], btc: [0.00009, 0.0009] },
  growth: { price: 29, yearly: 289, runs: 2000, bdt: [2990, 28900], btc: [0.0003, 0.0028] },
  enterprise: { price: 99, yearly: 989, runs: 20000, bdt: [9900, 98900], btc: [0.001, 0.01] },
};
const COMMISSION_PCT = 15, MOBILE = ['bkash', 'nagad', 'rocket'];
const FREE_RUNS = 50, RATE_PER_1K_TOKENS = 0.002, TOKEN_TTL_MS = 864e5, PBKDF2_ITER = 100000, DB_KEY = 'qvmpxt:db';
const enc = new TextEncoder(), dec = new TextDecoder();

// ---------- helpers ----------
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const rid = (n = 5) => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const fail = (status, error) => json({ error }, status);
const httpErr = (status, message) => Object.assign(new Error(message), { status });
const safeEq = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const emailOk = (e) => /^\S+@\S+\.\S+$/.test(e || '') && e.length <= 120;
const brandOf = (env) => env.BRAND || DEFAULT_BRAND;
const splitCommission = (gross) => { const c = Math.round(gross * 100), f = Math.round(c * COMMISSION_PCT / 100); return { gross: c / 100, fee: f / 100, net: (c - f) / 100 }; };
const publicItem = ({ id, by, name, task, buy, rent, sales }) => ({ id, by, name, task, buy, rent, sales });
const cleanItems = (a) => (Array.isArray(a) ? a : []).slice(0, 50).map((i) => ({ name: String((i && i.name) || 'Item').slice(0, 80), qty: Math.max(1, Math.min(1e6, +(i && i.qty) || 1)), price: Math.max(0, Math.min(1e9, +(i && i.price) || 0)) }));
const feedView = (p, u) => ({ ...p, likes: p.likes.length, liked: !!u && p.likes.includes(u.email), cm: p.cm.slice(-50) }); // never expose who liked
const PRIVATE_HOST = /^(localhost|.*\.localhost|.*\.local|.*\.internal|127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|\[|\d+$|0x)/i;
const validHookUrl = (s) => { try { const u = new URL(s); return /^https?:$/.test(u.protocol) && !u.username && !u.password && !PRIVATE_HOST.test(u.hostname); } catch { return false; } };
const normLang = (c) => /^[a-z]{2,3}(-[A-Za-z0-9]{2,8}){0,2}$/.test(c || '') ? c : null;

// ---------- data store: in-memory, snapshotted to env.QV_KV (Workers KV, or a file when running on Node) ----------
const seedAgents = () => [
  ['Market Researcher', 'Find 3 trends and summarize them in plain language.'],
  ['Support Triage', 'Classify the message by urgency and draft a short reply.'],
  ['Invoice Chaser', 'Write a polite reminder for an overdue invoice.'],
].map(([name, prompt]) => ({ id: rid(), name, prompt, owner: 'system', created: Date.now() }));
const seedFeed = () => [
  { id: 'p1', by: 'Ava Chen', type: 'agent', t: 'Lead Qualifier', x: 'Scores inbound leads and drafts a first reply.', data: { name: 'Lead Qualifier', prompt: 'Score the lead 1-10 and draft a first reply.' }, likes: ['seed1', 'seed2'], cm: [{ by: 'Noor', x: 'Forking this for our sales team.' }], forks: 3 },
  { id: 'p2', by: 'Rafi Ahmed', type: 'quote', t: 'Brand kit', x: 'A 60-second quote link for a design package.', data: { title: 'Brand kit', to: 'Studio Nine', items: [{ name: 'Logo + palette', qty: 1, price: 480 }] }, likes: ['seed3'], cm: [], forks: 1 },
];
const seedMarket = () => [
  ['Ava Chen', 'Lead Qualifier Pro', 'Score the lead 1-10 and draft a first reply.', 29, 5],
  ['Rafi Ahmed', 'Contract Risk Reader', 'List risky clauses and suggest safer wording.', 49, 9],
  ['Noor Hasan', 'Bangla Support Replier', 'Draft a polite support reply in Bangla and English.', 19, 0],
].map(([by, name, task, buy, rent]) => ({ id: rid(), by, email: 'seed@qvmpxt.demo', name, task, buy, rent, sales: 0, created: Date.now() }));
const freshDB = () => ({ users: {}, agents: seedAgents(), runs: [], shares: {}, feed: seedFeed(), keys: {}, hooks: {}, teams: {}, packs: {}, hits: {}, market: seedMarket(), orders: [], payments: {} });

let DB = null, DB_AT = 0, WROTE = 0, dirty = false, flushing = false;
async function loadDB(env) {
  // Keep the in-memory copy while writes are pending or recent: KV is eventually consistent and a stale read would erase them.
  if (DB && (!env.QV_KV || dirty || flushing || Date.now() - DB_AT < 5000 || Date.now() - WROTE < 60000)) return DB;
  if (env.QV_KV) { try { const s = await env.QV_KV.get(DB_KEY); if (s) { DB = Object.assign(freshDB(), JSON.parse(s)); DB.hits = {}; DB_AT = Date.now(); return DB; } } catch { /* use fresh */ } }
  DB = DB || freshDB(); DB_AT = Date.now(); return DB;
}
async function flush(env) { // coalesces bursts of changes into as few writes as possible
  if (flushing) return;
  flushing = true;
  try {
    while (dirty) {
      dirty = false;
      try { await env.QV_KV.put(DB_KEY, JSON.stringify({ ...DB, hits: {} })); WROTE = Date.now(); } catch { dirty = true; break; }
    }
  } finally { flushing = false; }
}
async function saveDB(env, ctx) {
  if (!env.QV_KV || !DB) return;
  dirty = true;
  const job = flush(env);
  if (ctx && ctx.waitUntil) ctx.waitUntil(job); else await job;
}

// ---------- crypto: PBKDF2 passwords, HMAC tokens and signatures (Web Crypto: Workers and Node) ----------
let EPHEMERAL = null;
const secretOf = (env) => env.JWT_SECRET || (EPHEMERAL ||= rid(32));
async function hmacRaw(secret, data) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return crypto.subtle.sign('HMAC', k, enc.encode(data));
}
const hmac = async (secret, data) => b64u(await hmacRaw(secret, data));
const hmacHex = async (secret, data) => hex(await hmacRaw(secret, data));
async function hashPw(pw, salt) { // any password length is accepted
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: PBKDF2_ITER, hash: 'SHA-256' }, k, 256));
}
async function signToken(env, email) {
  const body = b64u(enc.encode(JSON.stringify({ email, exp: Date.now() + TOKEN_TTL_MS })));
  return body + '.' + await hmac(secretOf(env), body);
}
async function userFrom(env, db, req) {
  const tok = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (tok.startsWith('qvm_live_')) { const k = db.keys[await sha(tok)] || db.keys[tok]; return k && db.users[k.owner] ? db.users[k.owner] : null; } // keys are stored hashed; plain keys from older snapshots still work
  const [b, sig] = tok.split('.');
  if (!b || !sig || !safeEq(sig, await hmac(secretOf(env), b))) return null;
  try { const p = JSON.parse(dec.decode(unb64u(b))); return p.exp > Date.now() && db.users[p.email] ? db.users[p.email] : null; } catch { return null; }
}

// ---------- rate limiting (per isolate, per IP + bucket) ----------
function limited(db, req, bucket, max, windowMs) {
  const ip = req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || 'local', k = bucket + ':' + ip, now = Date.now(), h = db.hits[k];
  if (!h || now - h.t > windowMs) { if (Object.keys(db.hits).length > 5000) db.hits = {}; db.hits[k] = { t: now, n: 1 }; return false; }
  return ++h.n > max;
}

// ---------- business logic ----------
const planOf = (u) => (u.planUntil && u.planUntil < Date.now() ? 'free' : u.plan); // mobile-banking plans expire; Stripe plans are managed by webhooks
const limitFor = (u) => (PLANS[planOf(u)] ? PLANS[planOf(u)].runs : FREE_RUNS);
const roll = (u) => { const p = new Date().toISOString().slice(0, 7); if (u.period !== p) { u.period = p; u.used = 0; } return u; }; // run counter resets every month

async function llm(env, agent, input) {
  if (!env.ANTHROPIC_API_KEY) return `[simulated] ${agent.name} processed: "${input.slice(0, 80)}". Set ANTHROPIC_API_KEY for live model output.`;
  let res, j;
  try {
    res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: env.MODEL || 'claude-sonnet-5-5', max_tokens: 500, system: agent.prompt, messages: [{ role: 'user', content: input }] }),
      signal: AbortSignal.timeout(25000),
    });
    j = await res.json();
  } catch { throw new Error('Model request failed or timed out'); }
  if (!res.ok) throw new Error((j.error && j.error.message) || 'Model request failed');
  return (j.content || []).map((c) => c.text || '').join('');
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
    const z = (a - mean) / sd; if (Math.abs(z) > 1.9) f('ai-anomaly', 'high', `Amount is ${z.toFixed(1)} std devs from average`);
  });
  const w = { high: 25, medium: 12, low: 4 };
  return { checked: rows.length, flagged: out.length, mean: +mean.toFixed(2), sd: +sd.toFixed(2), score: Math.min(100, out.reduce((s, f) => s + w[f.severity], 0)), findings: out };
}
async function fireHook(h, event, payload) {
  const body = JSON.stringify({ event, id: rid(), at: Date.now(), ...payload });
  try {
    const sig = await hmac(h.secret, body); // HMAC-SHA256 with the per-endpoint secret returned when the endpoint was saved
    const r = await fetch(h.url, { method: 'POST', headers: { 'content-type': 'application/json', 'x-qvmpxt-signature': 'sha256=' + sig }, body, redirect: 'manual', signal: AbortSignal.timeout(5000) });
    return { status: r.status, signature: 'sha256=' + sig.slice(0, 16) + '...' };
  } catch { return { status: 0, error: 'Delivery failed' }; }
}

// ---------- PWA assets served by this script ----------
// Stale-while-revalidate: the app shell opens instantly from cache and refreshes in the background.
const SW_SOURCE = (brand) => `// ${brand} service worker (served by the backend at /sw.js)
const CACHE='qvmpxt-v2';
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

// ---------- API router ----------
async function api(req, env, ctx, url) {
  const p = url.pathname, m = req.method, brand = brandOf(env), db = await loadDB(env);
  const readBody = async () => {
    if (m === 'GET' || m === 'DELETE') return {};
    const t = await req.text(); if (t.length > 400000) throw httpErr(413, 'Payload too large');
    try { return t ? JSON.parse(t) : {}; } catch { throw httpErr(400, 'Invalid JSON body'); }
  };
  const maybeUser = () => userFrom(env, db, req);
  const needUser = async () => { const u = await maybeUser(); if (!u) throw httpErr(401, 'Sign in required'); return u; };
  const roleOf = (u) => { const t = db.teams[u.email]; return t && t.accepted ? t.role : 'Admin'; }; // a role only applies after the invitee accepts
  const write = (u) => { if (roleOf(u) === 'Viewer') throw httpErr(403, 'Role Viewer cannot change data'); };
  const admin = (u) => { if (roleOf(u) !== 'Admin') throw httpErr(403, 'Admin role required'); };
  const owner = (u) => { if (!env.OWNER_EMAIL) throw httpErr(403, 'Set OWNER_EMAIL to review payments'); if (u.email !== String(env.OWNER_EMAIL).trim().toLowerCase()) throw httpErr(403, 'Owner only'); };
  let mm;

  if (p === '/api/health') return json({ ok: true, brand, time: Date.now(), storage: env.QV_KV ? (env.QV_KV.kind || 'kv') : 'memory', model: env.ANTHROPIC_API_KEY ? 'live' : 'simulated' });

  // auth
  if (p === '/api/auth/register' && m === 'POST') {
    if (limited(db, req, 'auth', 20, 60000)) return fail(429, 'Too many attempts. Try again in a minute.');
    const b = await readBody(), email = String(b.email || '').trim().toLowerCase();
    if (!emailOk(email) || !String(b.password || '')) return fail(400, 'A valid email and a password are required');
    if (db.users[email]) return fail(409, 'Account already exists');
    const salt = rid(8), name = String(b.name || email.split('@')[0]).slice(0, 60);
    db.users[email] = { email, name, salt, hash: await hashPw(String(b.password), salt), plan: 'free', used: 0, tokens: 0, cost: 0, created: Date.now() };
    if (b.ref && db.shares[b.ref]) db.shares[b.ref].signups++;
    await saveDB(env, ctx);
    return json({ token: await signToken(env, email), plan: 'free', name });
  }
  if (p === '/api/auth/login' && m === 'POST') {
    if (limited(db, req, 'auth', 20, 60000)) return fail(429, 'Too many attempts. Try again in a minute.');
    const b = await readBody(), u = db.users[String(b.email || '').trim().toLowerCase()], pw = String(b.password || '');
    const ok = u ? safeEq(await hashPw(pw, u.salt), u.hash) : (await hashPw(pw, 'x'), false); // same work either way, so timing does not reveal which emails exist
    if (!ok) return fail(401, 'Wrong email or password');
    return json({ token: await signToken(env, u.email), plan: planOf(u), name: u.name });
  }
  if (p === '/api/me' && m === 'GET') {
    const u = roll(await needUser());
    return json({ email: u.email, name: u.name, plan: planOf(u), role: roleOf(u), used: u.used, limit: limitFor(u), tokens: u.tokens, created: u.created });
  }

  // agents + runs: you only see system agents and your own
  if (p === '/api/agents' && m === 'GET') {
    const u = await maybeUser();
    return json(db.agents.filter((a) => a.owner === 'system' || (u && a.owner === u.email)).map(({ id, name, prompt, owner: o, created }) => ({ id, name, prompt, owner: o, created })));
  }
  if (p === '/api/agents' && m === 'POST') {
    const u = await needUser(); write(u); const b = await readBody();
    if (!b.name || !b.prompt) return fail(400, 'Name and task are required');
    const a = { id: rid(), name: String(b.name).slice(0, 60), prompt: String(b.prompt).slice(0, 1000), owner: u.email, created: Date.now() };
    db.agents.unshift(a); await saveDB(env, ctx); return json(a);
  }
  if ((mm = p.match(/^\/api\/agents\/([\w-]+)\/run$/)) && m === 'POST') {
    const u = roll(await needUser());
    if (limited(db, req, 'run', 30, 60000)) return fail(429, 'Too many runs. Try again in a minute.');
    const a = db.agents.find((x) => x.id === mm[1] && (x.owner === 'system' || x.owner === u.email)), input = String((await readBody()).input || '').slice(0, 2000);
    if (!a) return fail(404, 'Agent not found');
    if (a.rentUntil && Date.now() > a.rentUntil) return fail(402, 'Rental expired. Rent it again in the marketplace.');
    if (!input.trim()) return fail(400, 'Type an input first');
    if (u.used >= limitFor(u)) return fail(402, 'Run limit reached. Upgrade your plan.');
    const t0 = Date.now(), steps = [{ step: 'plan', at: 0, note: 'Read task and input' }];
    let output; try { output = await llm(env, a, input); } catch (e) { return fail(502, e.message); }
    steps.push({ step: 'model', at: Date.now() - t0, note: env.ANTHROPIC_API_KEY ? 'Live model call' : 'Simulated call' }, { step: 'done', at: Date.now() - t0, note: 'Result ready' });
    const tokens = Math.ceil((a.prompt.length + input.length + output.length) / 4), cost = +(tokens / 1000 * RATE_PER_1K_TOKENS).toFixed(5);
    u.used++; u.tokens += tokens; u.cost = +(u.cost + cost).toFixed(5);
    const run = { id: rid(), agent: a.name, owner: u.email, input, output, steps, tokens, cost, ms: Date.now() - t0, at: Date.now() };
    db.runs.unshift(run); db.runs.length = Math.min(db.runs.length, 500); await saveDB(env, ctx);
    const hook = db.hooks[u.email]; if (hook && ctx && ctx.waitUntil) ctx.waitUntil(fireHook(hook, 'agent.run.completed', { run: run.id, agent: a.name, tokens }));
    return json(run);
  }
  if (p === '/api/runs' && m === 'GET') { const u = await needUser(); return json(db.runs.filter((x) => x.owner === u.email).slice(0, 20)); }

  // micro-SaaS quote links
  if (p === '/api/share' && m === 'POST') {
    const u = await needUser(); write(u); const b = await readBody(), items = cleanItems(b.items);
    if (!items.length) return fail(400, 'Add at least one line item');
    const id = rid(); db.shares[id] = { id, owner: u.email, title: String(b.title || 'Quote').slice(0, 80), to: String(b.to || '').slice(0, 80), items, views: 0, signups: 0, created: Date.now() };
    await saveDB(env, ctx); return json({ id, url: `/s/${id}` });
  }
  if (p === '/api/share/stats' && m === 'GET') {
    const u = await needUser(), mine = Object.values(db.shares).filter((s) => s.owner === u.email);
    return json({ links: mine.length, views: mine.reduce((a, s) => a + s.views, 0), signups: mine.reduce((a, s) => a + s.signups, 0), items: mine.map((s) => ({ id: s.id, title: s.title, views: s.views, signups: s.signups })) });
  }

  // compliance audit
  if (p === '/api/audit' && m === 'POST') {
    await needUser(); if (limited(db, req, 'audit', 30, 60000)) return fail(429, 'Too many audits. Try again in a minute.');
    const rows = (await readBody()).rows;
    if (!Array.isArray(rows) || !rows.length) return fail(400, 'Provide rows to audit');
    return json(auditRows(rows.slice(0, 5000).map((x) => (x && typeof x === 'object' ? x : {}))));
  }

  // billing
  if (p === '/api/billing/plans' && m === 'GET') return json(PLANS);
  if (p === '/api/billing/usage' && m === 'GET') { const u = roll(await needUser()); return json({ plan: planOf(u), used: u.used, limit: limitFor(u), tokens: u.tokens, usageCost: u.cost, ratePer1kTokens: RATE_PER_1K_TOKENS, planUntil: u.planUntil || null }); }
  if (p === '/api/billing/subscribe' && m === 'POST') {
    const u = await needUser(); admin(u); const b0 = await readBody(), plan = b0.plan, yearly = b0.cycle === 'yearly';
    if (!PLANS[plan]) return fail(400, 'Unknown plan');
    const sk = env.STRIPE_SECRET_KEY, price = env['STRIPE_PRICE_' + plan.toUpperCase() + (yearly ? '_YEARLY' : '')];
    if (!sk || !price) {
      if (env.SANDBOX_BILLING !== '1') return fail(503, 'Card payments are not configured yet');
      u.plan = plan; u.planUntil = 0; await saveDB(env, ctx);
      return json({ mode: 'sandbox', plan, cycle: yearly ? 'yearly' : 'monthly', message: 'Plan activated in sandbox mode. Add Stripe keys for real payments.' });
    }
    const base = env.PUBLIC_URL || url.origin;
    const body = new URLSearchParams({ mode: 'subscription', 'line_items[0][price]': price, 'line_items[0][quantity]': '1', customer_email: u.email, client_reference_id: u.email, 'metadata[plan]': plan, 'subscription_data[metadata][plan]': plan, success_url: base + '/?paid=1', cancel_url: base + '/' });
    const r = await fetch('https://api.stripe.com/v1/checkout/sessions', { method: 'POST', headers: { authorization: 'Bearer ' + sk, 'content-type': 'application/x-www-form-urlencoded' }, body, signal: AbortSignal.timeout(15000) });
    const j = await r.json().catch(() => ({})); return r.ok ? json({ mode: 'stripe', url: j.url }) : fail(502, (j.error && j.error.message) || 'Payment error');
  }
  if (p === '/api/stripe/webhook' && m === 'POST') { // activates the plan once Stripe confirms payment, and downgrades on cancellation
    if (!env.STRIPE_WEBHOOK_SECRET) return fail(503, 'Stripe webhook is not configured');
    const raw = await req.text(), sig = Object.fromEntries((req.headers.get('stripe-signature') || '').split(',').map((s) => s.split('=')).filter((a) => a.length === 2)), t = +sig.t;
    if (!t || Math.abs(Date.now() / 1000 - t) > 300 || !sig.v1 || !safeEq(sig.v1, await hmacHex(env.STRIPE_WEBHOOK_SECRET, t + '.' + raw))) return fail(400, 'Bad signature');
    let ev; try { ev = JSON.parse(raw); } catch { return fail(400, 'Invalid JSON body'); }
    const o = (ev.data && ev.data.object) || {};
    if (ev.type === 'checkout.session.completed' && db.users[o.client_reference_id] && o.metadata && PLANS[o.metadata.plan]) {
      const u = db.users[o.client_reference_id]; u.plan = o.metadata.plan; u.planUntil = 0; u.stripeCustomer = o.customer || ''; await saveDB(env, ctx);
    } else if (ev.type === 'customer.subscription.deleted') {
      const u = Object.values(db.users).find((x) => x.stripeCustomer && x.stripeCustomer === o.customer); if (u) { u.plan = 'free'; u.planUntil = 0; await saveDB(env, ctx); }
    }
    return json({ received: true });
  }

  // mobile banking (bKash / Nagad / Rocket): the TxID goes into a pending queue and the owner approves it after checking the merchant app
  if (p === '/api/billing/mobile' && m === 'POST') {
    const u = await needUser(); admin(u); const b = await readBody(), tx = String(b.txid || '').trim().toUpperCase();
    if (!MOBILE.includes(b.provider)) return fail(400, 'Provider must be bkash, nagad or rocket');
    if (!PLANS[b.plan]) return fail(400, 'Unknown plan');
    if (!/^[A-Z0-9]{8,12}$/.test(tx)) return fail(400, 'TxID must be 8-12 letters or digits');
    if (db.payments[tx]) return fail(409, 'This TxID was already submitted');
    const yearly = b.cycle === 'yearly', rec = { id: rid(), txid: tx, provider: b.provider, plan: b.plan, cycle: yearly ? 'yearly' : 'monthly', amount: PLANS[b.plan].bdt[yearly ? 1 : 0], currency: 'BDT', email: u.email, status: 'pending', at: Date.now() };
    db.payments[tx] = rec; await saveDB(env, ctx); return json({ ...rec, message: 'Received. Your plan activates once the payment is verified.' });
  }
  if (p === '/api/billing/pending' && m === 'GET') { const u = await needUser(); owner(u); return json(Object.values(db.payments).filter((x) => x.status === 'pending')); }
  if ((mm = p.match(/^\/api\/billing\/(approve|reject)\/(\w+)$/)) && m === 'POST') {
    const u = await needUser(); owner(u); const rec = Object.values(db.payments).find((x) => x.id === mm[2]);
    if (!rec) return fail(404, 'Payment not found'); if (rec.status !== 'pending') return fail(409, 'Already ' + rec.status);
    if (mm[1] === 'approve') {
      const t = db.users[rec.email]; if (!t) return fail(404, 'User not found');
      t.plan = rec.plan; t.planUntil = Date.now() + (rec.cycle === 'yearly' ? 366 : 31) * 864e5; rec.status = 'approved';
    } else rec.status = 'rejected'; // the TxID stays blocked so it cannot be resubmitted
    rec.by = u.email; await saveDB(env, ctx); return json(rec);
  }

  // marketplace: list, rent or buy agent workflows; the platform commission is split out automatically
  if (p === '/api/market' && m === 'GET') return json(db.market.slice(0, 200).map(publicItem));
  if (p === '/api/market' && m === 'POST') {
    const u = await needUser(); write(u); const b = await readBody(), a = db.agents.find((x) => x.id === b.agent && x.owner === u.email && !x.rentUntil);
    const buy = Math.max(0, +b.buy || 0), rent = Math.max(0, +b.rent || 0);
    if (!a) return fail(404, 'Pick one of your own agents');
    if (buy <= 0 && rent <= 0) return fail(400, 'Set a buy or rent price');
    if (buy > 10000 || rent > 10000) return fail(400, 'Prices are limited to 10,000');
    const item = { id: rid(), by: u.name, email: u.email, name: a.name, task: a.prompt, buy: +buy.toFixed(2), rent: +rent.toFixed(2), sales: 0, created: Date.now() };
    db.market.unshift(item); db.market.length = Math.min(db.market.length, 1000); await saveDB(env, ctx); return json(publicItem(item));
  }
  if (p === '/api/market/orders' && m === 'GET') {
    const u = await needUser(), mine = db.orders.filter((o) => o.buyer === u.email || o.seller === u.email), sold = mine.filter((o) => o.seller === u.email);
    const sum = (k) => +sold.reduce((s, o) => s + o[k], 0).toFixed(2);
    return json({ orders: mine.slice(0, 100), earnings: { gross: sum('gross'), fee: sum('fee'), net: sum('net'), commissionPct: COMMISSION_PCT } });
  }
  if ((mm = p.match(/^\/api\/market\/([\w-]+)\/buy$/)) && m === 'POST') {
    const u = await needUser(); write(u); const item = db.market.find((x) => x.id === mm[1]), mode = (await readBody()).mode;
    if (!item) return fail(404, 'Listing not found');
    if (!['buy', 'rent'].includes(mode) || !(item[mode] > 0)) return fail(400, 'That option is not available');
    if (item.email === u.email) return fail(400, 'You cannot purchase your own listing');
    const order = { id: rid(), item: item.name, mode, buyer: u.email, seller: item.email, ...splitCommission(item[mode]), settled: false, at: Date.now() };
    const agent = { id: rid(), name: item.name + (mode === 'rent' ? ' (rented 30d)' : ''), prompt: item.task, owner: u.email, created: Date.now(), rentUntil: mode === 'rent' ? Date.now() + 30 * 864e5 : 0 };
    db.agents.unshift(agent); db.orders.unshift(order); db.orders.length = Math.min(db.orders.length, 1000); item.sales++; await saveDB(env, ctx);
    return json({ order, agent, note: 'Ledger entry recorded. Connect a payout provider (for example Stripe Connect) to settle seller payouts.' });
  }

  // community feed
  if (p === '/api/feed' && m === 'GET') { const u = await maybeUser(); return json(db.feed.slice(0, 100).map((x) => feedView(x, u))); }
  if (p === '/api/feed' && m === 'POST') {
    const u = await needUser(); write(u); const b = await readBody();
    if (!['agent', 'quote'].includes(b.type) || !b.t) return fail(400, 'type (agent|quote) and t (title) are required');
    const data = b.data && typeof b.data === 'object' && JSON.stringify(b.data).length <= 5000 ? b.data : {};
    const post = { id: rid(), by: u.name, type: b.type, t: String(b.t).slice(0, 80), x: String(b.x || '').slice(0, 300), data, likes: [], cm: [], forks: 0 };
    db.feed.unshift(post); db.feed.length = Math.min(db.feed.length, 500); await saveDB(env, ctx); return json(feedView(post, u));
  }
  if ((mm = p.match(/^\/api\/feed\/([\w-]+)\/(like|comment|fork)$/)) && m === 'POST') {
    const u = await needUser(), post = db.feed.find((x) => x.id === mm[1]);
    if (!post) return fail(404, 'Post not found');
    if (mm[2] === 'like') post.likes = post.likes.includes(u.email) ? post.likes.filter((x) => x !== u.email) : [...post.likes, u.email];
    else if (mm[2] === 'comment') { const t = String((await readBody()).text || '').trim().slice(0, 300); if (!t) return fail(400, 'Write a comment first'); post.cm.push({ by: u.name, x: t }); }
    else {
      write(u); post.forks++;
      if (post.type === 'agent') {
        const a = { id: rid(), name: String(post.data.name || post.t).slice(0, 52) + ' (fork)', prompt: String(post.data.prompt || post.data.task || 'Describe the task').slice(0, 1000), owner: u.email, created: Date.now() };
        db.agents.unshift(a); await saveDB(env, ctx); return json({ forked: 'agent', agent: a });
      }
      const id = rid(), d = post.data; db.shares[id] = { id, owner: u.email, title: String(d.title || post.t).slice(0, 72) + ' (fork)', to: String(d.to || '').slice(0, 80), items: cleanItems(d.items), views: 0, signups: 0, created: Date.now() };
      await saveDB(env, ctx); return json({ forked: 'quote', url: `/s/${id}` });
    }
    await saveDB(env, ctx); return json(feedView(post, u));
  }

  // team (RBAC): invitations only take effect after the invited person accepts
  if (p === '/api/team' && m === 'GET') { const u = await needUser(); return json({ you: roleOf(u), members: Object.values(db.teams).filter((t) => t.owner === u.email || t.email === u.email) }); }
  if (p === '/api/team/invite' && m === 'POST') {
    const u = await needUser(); admin(u); const b = await readBody(), email = String(b.email || '').trim().toLowerCase();
    if (!emailOk(email)) return fail(400, 'Enter a valid email'); if (!['Admin', 'Editor', 'Viewer'].includes(b.role)) return fail(400, 'Role must be Admin, Editor or Viewer');
    if (email === u.email) return fail(400, 'You cannot invite yourself');
    if (db.teams[email] && db.teams[email].owner !== u.email) return fail(409, 'That person already belongs to another workspace');
    db.teams[email] = { email, role: b.role, owner: u.email, invited: Date.now(), accepted: false }; await saveDB(env, ctx); return json(db.teams[email]);
  }
  if (p === '/api/team/accept' && m === 'POST') {
    const u = await needUser(), t = db.teams[u.email];
    if (!t) return fail(404, 'No invitation found'); t.accepted = true; await saveDB(env, ctx); return json(t);
  }

  // developer API keys (stored hashed) + webhooks
  if (p === '/api/keys' && m === 'GET') { const u = await needUser(); return json(Object.entries(db.keys).filter(([, k]) => k.owner === u.email).map(([k, v]) => ({ key: v.hint || k.slice(0, 14) + '...' + k.slice(-4), id: v.id, created: v.created }))); }
  if (p === '/api/keys' && m === 'POST') {
    const u = await needUser(); admin(u); const k = 'qvm_live_' + rid(16);
    db.keys[await sha(k)] = { id: rid(4), owner: u.email, hint: k.slice(0, 14) + '...' + k.slice(-4), created: Date.now() }; await saveDB(env, ctx); return json({ key: k, note: 'Store this key now. It is only shown in full once.' });
  }
  if ((mm = p.match(/^\/api\/keys\/([\w]+)$/)) && m === 'DELETE') {
    const u = await needUser(); admin(u); const e = Object.entries(db.keys).find(([, v]) => v.id === mm[1] && v.owner === u.email);
    if (!e) return fail(404, 'Key not found'); delete db.keys[e[0]]; await saveDB(env, ctx); return json({ revoked: true });
  }
  if (p === '/api/webhook' && m === 'PUT') {
    const u = await needUser(); admin(u); const url2 = String((await readBody()).url || '');
    if (!validHookUrl(url2)) return fail(400, 'Enter a public http(s) URL');
    const secret = 'whsec_' + rid(16); db.hooks[u.email] = { url: url2, secret }; await saveDB(env, ctx); return json({ saved: true, secret, note: 'Verify the x-qvmpxt-signature header as sha256=HMAC_SHA256_base64url(secret, rawBody). The secret is shown once.' });
  }
  if (p === '/api/webhook/test' && m === 'POST') {
    const u = await needUser(); admin(u); const h = db.hooks[u.email];
    if (!h) return fail(400, 'Save an endpoint first'); return json(await fireHook(h, 'webhook.test', {}));
  }

  // i18n packs: community-contributed UI translations, validated and escaped on the client
  if (p === '/api/i18n' && m === 'GET') return json({ languages: Object.keys(db.packs).sort() });
  if ((mm = p.match(/^\/api\/i18n\/([A-Za-z0-9-]{2,16})$/))) {
    const lang = normLang(mm[1]); if (!lang) return fail(400, 'Invalid language code');
    if (m === 'GET') return db.packs[lang] ? json({ lang, strings: db.packs[lang].strings }) : fail(404, 'No pack for this language');
    if (m === 'PUT') {
      const u = await needUser(); admin(u); const s = (await readBody()).strings, clean = {};
      if (!s || typeof s !== 'object') return fail(400, 'strings object required');
      for (const [k, v] of Object.entries(s)) if (/^[a-z0-9_]{1,24}$/.test(k) && typeof v === 'string' && v.length <= 200) clean[k] = v;
      if (!Object.keys(clean).length) return fail(400, 'No valid strings found');
      db.packs[lang] = { strings: clean, by: u.email, at: Date.now() }; await saveDB(env, ctx); return json({ lang, saved: Object.keys(clean).length });
    }
  }
  return fail(404, 'Unknown endpoint');
}

// ---------- entry: routes API, PWA files, share pages, then the frontend ----------
const SECURITY_HEADERS = { 'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin', 'x-frame-options': 'SAMEORIGIN' };
async function handle(req, env, ctx, serveFront) {
  const url = new URL(req.url), p = url.pathname;
  const cors = env.ALLOWED_ORIGIN ? { 'access-control-allow-origin': env.ALLOWED_ORIGIN, 'access-control-allow-headers': 'content-type,authorization', 'access-control-allow-methods': 'GET,POST,PUT,DELETE,OPTIONS', 'access-control-max-age': '86400', vary: 'origin' } : null;
  // Rebuild the response: headers of fetched responses (Pages ASSETS) are immutable, so they cannot be edited in place.
  const done = (r) => { const h = new Headers(r.headers); for (const [k, v] of Object.entries(SECURITY_HEADERS)) h.set(k, v); if (cors) for (const [k, v] of Object.entries(cors)) h.set(k, v); return new Response(r.body, { status: r.status, statusText: r.statusText, headers: h }); };
  if (req.method === 'OPTIONS') return done(new Response(null, { status: 204 }));
  if (p === '/sw.js') return done(new Response(SW_SOURCE(brandOf(env)), { headers: { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-cache', 'service-worker-allowed': '/' } }));
  if (p === '/manifest.webmanifest') return done(new Response(MANIFEST(brandOf(env)), { headers: { 'content-type': 'application/manifest+json', 'cache-control': 'no-cache' } }));
  if (p === '/icon.svg') return done(new Response(ICON_SVG, { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'public, max-age=86400' } }));
  if (p === '/robots.txt') return done(new Response('User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /s/\nSitemap: ' + (env.PUBLIC_URL || url.origin).replace(/\/+$/, '') + '/sitemap.xml\n', { headers: { 'content-type': 'text/plain; charset=utf-8' } }));
  if (p === '/sitemap.xml') {
    // quote pages (/s/...) hold private client quotes, so they are never listed; add public pages with SITEMAP_PATHS
    const base = (env.PUBLIC_URL || url.origin).replace(/\/+$/, ''), day = new Date().toISOString().slice(0, 10);
    const extra = String(env.SITEMAP_PATHS || '').split(',').map((s) => s.trim()).filter((s) => /^\/[\w\-./]*$/.test(s));
    const xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + ['/', ...extra].map((x, i) => `  <url><loc>${esc(base + x)}</loc><lastmod>${day}</lastmod><priority>${i ? '0.6' : '1.0'}</priority></url>`).join('\n') + '\n</urlset>';
    return done(new Response(xml, { headers: { 'content-type': 'application/xml; charset=utf-8', 'cache-control': 'public, max-age=3600' } }));
  }
  try {
    if (p.startsWith('/api/')) return done(await api(req, env, ctx, url));
    let mm;
    if ((mm = p.match(/^\/s\/([\w-]+)$/)) && req.method === 'GET') {
      const db = await loadDB(env), s = db.shares[mm[1]], brand = brandOf(env);
      if (!s) return done(new Response('Link not found', { status: 404 }));
      s.views++; await saveDB(env, ctx);
      const total = s.items.reduce((a, i) => a + i.qty * i.price, 0);
      const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="robots" content="noindex"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(s.title)}</title>
<body style="font-family:system-ui,sans-serif;background:#03050C;color:#f1f5f9;margin:0;padding:24px"><main style="max-width:560px;margin:auto;background:#0f172a;border:1px solid #1e293b;border-radius:16px;padding:24px">
<h1 style="margin:0 0 4px">${esc(s.title)}</h1><p style="color:#94a3b8;margin:0 0 16px">${s.to ? 'For ' + esc(s.to) : ''}</p>
${s.items.map((i) => `<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #1e293b"><span>${esc(i.name)} x${+i.qty || 1}</span><b>$${((+i.qty || 1) * (+i.price || 0)).toFixed(2)}</b></div>`).join('')}
<p style="text-align:right;font-size:20px">Total <b style="color:#10b981">$${total.toFixed(2)}</b></p></main>
<p style="text-align:center;margin-top:16px"><a href="/?ref=${esc(s.id)}" style="color:#00f0ff">Powered by ${esc(brand)} - make your own in 60 seconds</a></p></body>`;
      return done(new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'" } }));
    }
    return done(await serveFront(req, p));
  } catch (e) { return done(fail(e.status || 500, e.status ? e.message : 'Internal error')); }
}

// Cloudflare Workers / Pages entry
export default {
  async fetch(req, env, ctx) {
    return handle(req, env || {}, ctx, async (r, p) => {
      if (env && env.ASSETS) {
        const a = await env.ASSETS.fetch(r);
        if (a.status !== 404 || p !== '/') return a;
        const b = await env.ASSETS.fetch(new Request(new URL('/qvmpxt', r.url), r)); // lets qvmpxt.html serve as the entry page
        if (b.ok) return b;
      }
      return new Response('Frontend not found: deploy index.html (or qvmpxt.html) next to this script.', { status: 404 });
    });
  },
};

// Node entry: starts an HTTP server only when running under Node (never inside Workers)
const isNode = typeof process !== 'undefined' && process.versions && process.versions.node && !(typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers');
if (isNode) {
  const imp = (n) => import(n); // non-literal specifiers keep Worker bundlers from resolving Node modules
  const [http, fs, nurl, npath, zlib, util] = await Promise.all([imp('node:http'), imp('node:fs/promises'), imp('node:url'), imp('node:path'), imp('node:zlib'), imp('node:util')]);
  const gzip = util.promisify(zlib.gzip), dir = npath.dirname(nurl.fileURLToPath(import.meta.url)), env = { ...process.env }, PORT = +env.PORT || 3000;
  if (!env.QV_KV && env.QV_DATA !== 'off') { // file-backed store so data survives restarts
    const file = npath.resolve(env.QV_DATA || npath.join(dir, 'qvmpxt-data.json'));
    env.QV_KV = { kind: 'file', get: () => fs.readFile(file, 'utf8').catch(() => null), put: async (k, v) => { await fs.writeFile(file + '.tmp', v); await fs.rename(file + '.tmp', file); } };
  }
  if (!env.JWT_SECRET) console.warn('JWT_SECRET is not set: sign-ins reset on every restart. Set it in production.');
  const front = { f: '', m: 0, buf: null }; // the frontend file is read once and re-read only when it changes
  const serveFront = async (req, p) => {
    if (p === '/' || p === '/index.html') {
      for (const f of ['index.html', 'qvmpxt.html']) {
        try {
          const st = await fs.stat(npath.join(dir, f));
          if (front.f !== f || front.m !== st.mtimeMs) { front.buf = await fs.readFile(npath.join(dir, f)); front.f = f; front.m = st.mtimeMs; }
          return new Response(front.buf, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' } });
        } catch { /* try next */ }
      }
    }
    return new Response('Not found', { status: 404 });
  };
  http.createServer(async (rq, rs) => {
    try {
      let size = 0; const chunks = [];
      for await (const c of rq) { size += c.length; if (size > 500000) { rs.writeHead(413).end('Payload too large'); return; } chunks.push(c); }
      const headers = new Headers(); for (const [k, v] of Object.entries(rq.headers)) headers.set(k, Array.isArray(v) ? v.join(',') : v);
      const req = new Request(`http://${rq.headers.host || 'localhost'}${rq.url}`, { method: rq.method, headers, body: ['GET', 'HEAD'].includes(rq.method) ? undefined : Buffer.concat(chunks) });
      const res = await handle(req, env, null, serveFront), h = Object.fromEntries(res.headers);
      let buf = Buffer.from(await res.arrayBuffer());
      if (buf.length > 1024 && /gzip/.test(rq.headers['accept-encoding'] || '') && /text|json|javascript|xml|svg/.test(h['content-type'] || '')) { // gzip shrinks the ~100 KB page to roughly a quarter
        buf = await gzip(buf, { level: 5 }); h['content-encoding'] = 'gzip'; h.vary = h.vary ? h.vary + ', accept-encoding' : 'accept-encoding';
      }
      h['content-length'] = buf.length;
      rs.writeHead(res.status, h); rs.end(buf);
    } catch { rs.writeHead(500).end('Internal error'); }
  }).listen(PORT, () => console.log(`${brandOf(env)} API on http://localhost:${PORT}`));
}
