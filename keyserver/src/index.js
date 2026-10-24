// LunarTweaks key server as a Cloudflare Worker (D1 database).
// Serves lunartweaks.se/api/* with the same paths and answers LunarTweaks 2.1.1+ expects (SiteLicense in the app).
// Secrets (set in Cloudflare, never in this repo): SIGNING_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_SECRET_KEY, ADMIN_TOKEN, RATE_SALT.

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32: no I, L, O, U
const enc = new TextEncoder();

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS lt_keys (key_hash TEXT PRIMARY KEY, license_key TEXT NOT NULL, plan TEXT NOT NULL,
     devices INTEGER NOT NULL, email TEXT, session_id TEXT UNIQUE, payment_intent TEXT, revoked INTEGER NOT NULL DEFAULT 0,
     emailed INTEGER NOT NULL DEFAULT 0, note TEXT, created INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS lt_keys_email ON lt_keys(email)`,
  `CREATE INDEX IF NOT EXISTS lt_keys_pi ON lt_keys(payment_intent)`,
  `CREATE TABLE IF NOT EXISTS lt_activations (key_hash TEXT NOT NULL, device TEXT NOT NULL, activation TEXT NOT NULL,
     label TEXT, created INTEGER NOT NULL, last_seen INTEGER NOT NULL, PRIMARY KEY (key_hash, device))`,
  `CREATE TABLE IF NOT EXISTS lt_events (id TEXT PRIMARY KEY, created INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS lt_rate (bucket TEXT PRIMARY KEY, win INTEGER NOT NULL, n INTEGER NOT NULL)`,
];
let schemaReady = false;

class Reply extends Error {
  constructor(response) { super('reply'); this.response = response; }
}
const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extra } });
const stop = (data, status = 200) => { throw new Reply(json(data, status)); };
const now = () => Math.floor(Date.now() / 1000);
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const sha256 = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const randHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));

function plans(env) {
  // PLANS (wrangler.toml var): {"pro":{"devices":1,"payment_links":["plink_..."],"amounts":[1499]}, "duo":{...}}
  return typeof env.PLANS === 'string' ? JSON.parse(env.PLANS) : env.PLANS;
}
const planName = p => (p === 'duo' ? 'Duo' : 'Pro');

async function db(env) {
  if (!schemaReady) {
    await env.DB.batch(SCHEMA.map(s => env.DB.prepare(s)));
    schemaReady = true;
  }
  return env.DB;
}

async function rateLimit(env, request, action, max, windowSec) {
  const ip = request.headers.get('CF-Connecting-IP') || '0';
  const bucket = await sha256(`${env.RATE_SALT || ''}|${action}|${ip}`);
  const win = Math.floor(now() / windowSec);
  const d = await db(env);
  const row = await d.prepare(
    `INSERT INTO lt_rate (bucket, win, n) VALUES (?1, ?2, 1)
     ON CONFLICT(bucket) DO UPDATE SET n = CASE WHEN win = ?2 THEN n + 1 ELSE 1 END, win = ?2
     RETURNING n`).bind(bucket, win).first();
  if (row && row.n > max) stop({ status: 'error', error: 'Too many attempts. Wait a minute and try again.' }, 429);
}

// Same rules as the app: upper case, no spaces, O -> 0 and I/L -> 1 after "LT-".
function normalizeKey(key) {
  const k = String(key || '').replace(/\s+/g, '').toUpperCase();
  if (!k.startsWith('LT-')) return k;
  return 'LT-' + k.slice(3).replace(/O/g, '0').replace(/[IL]/g, '1');
}
const validKey = k => /^LT-[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$/.test(k);

function newKey() {
  const r = crypto.getRandomValues(new Uint8Array(20));
  const chars = [...r].map(b => ALPHABET[b & 31]).join('');
  return 'LT-' + chars.match(/.{5}/g).join('-');
}

async function findKey(env, key) {
  return (await db(env)).prepare('SELECT * FROM lt_keys WHERE key_hash = ?').bind(await sha256(key)).first();
}
async function keyForSession(env, sessionId) {
  return (await db(env)).prepare('SELECT * FROM lt_keys WHERE session_id = ?').bind(sessionId).first();
}

async function createKey(env, plan, email, sessionId = null, paymentIntent = null, note = null) {
  const p = plans(env)[plan];
  if (!p) throw new Error('Unknown plan');
  const d = await db(env);
  for (let i = 0; i < 5; i++) {
    const key = newKey();
    try {
      await d.prepare(`INSERT INTO lt_keys (key_hash, license_key, plan, devices, email, session_id, payment_intent, note, created)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(await sha256(key), key, plan, Math.max(1, p.devices | 0), email ? String(email).trim().toLowerCase() : null,
              sessionId, paymentIntent, note, now()).run();
      return await findKey(env, key);
    } catch (e) {
      if (sessionId) { const existing = await keyForSession(env, sessionId); if (existing) return existing; }
    }
  }
  throw new Error('Could not create a key');
}

function planForSession(env, s) {
  const all = plans(env);
  if (typeof s.payment_link === 'string')
    for (const [name, p] of Object.entries(all)) if ((p.payment_links || []).includes(s.payment_link)) return name;
  for (const a of [s.amount_subtotal, s.amount_total])
    if (Number.isInteger(a)) for (const [name, p] of Object.entries(all)) if ((p.amounts || []).includes(a)) return name;
  return env.DEFAULT_PLAN || 'pro';
}
const sessionPaid = s => ['paid', 'no_payment_required'].includes(s.payment_status);

// How many separate keys a plan gives (Duo: 2 keys, one PC each). Configured with "keys" in PLANS.
const planKeyCount = (env, plan) => Math.max(1, (plans(env)[plan] || {}).keys | 0 || 1);

// All keys bought in one checkout. The first key uses the session id, extra keys "<session id>#2", "#3", ...
async function keysForSession(env, sessionId) {
  const { results } = await (await db(env)).prepare('SELECT * FROM lt_keys WHERE session_id = ? OR session_id LIKE ? ORDER BY session_id')
    .bind(sessionId, sessionId + '#%').all();
  return results;
}

// Gives a paid Checkout Session its keys (once) and emails them (once).
async function issueForSession(env, s) {
  let rows = await keysForSession(env, s.id);
  if (!rows.length) {
    const plan = planForSession(env, s);
    const email = s.customer_details?.email || null;
    const pi = typeof s.payment_intent === 'string' ? s.payment_intent : null;
    for (let i = 1; i <= planKeyCount(env, plan); i++) await createKey(env, plan, email, i === 1 ? s.id : `${s.id}#${i}`, pi);
    rows = await keysForSession(env, s.id);
  }
  if (rows.some(r => !r.emailed) && rows[0].email && (await sendKeyEmail(env, rows))) {
    const d = await db(env);
    for (const r of rows) await d.prepare('UPDATE lt_keys SET emailed = 1 WHERE key_hash = ?').bind(r.key_hash).run();
  }
  return rows;
}

// Email needs the optional EMAIL binding (Cloudflare Email Service). Without it, buyers get the keys on the thank-you page.
// rows: one or more keys for the same email address.
async function sendKeyEmail(env, rows) {
  rows = Array.isArray(rows) ? rows : [rows];
  if (!env.EMAIL || !rows.length || !rows[0].email) return false;
  const site = String(env.SITE_URL || 'https://lunartweaks.se').replace(/\/$/, '');
  const many = rows.length > 1;
  const list = rows.map(r => `    ${r.license_key}   (${planName(r.plan)}, ${r.devices} PC${r.devices > 1 ? 's' : ''})`).join('\n');
  const text = `Thanks for buying LunarTweaks!\n\nYour license key${many ? 's' : ''}:\n\n${list}\n\n` +
    `To activate: open LunarTweaks, paste a key and click Activate.${many ? ' Use one key per PC.' : ''}\n` +
    `Moving to a new PC? Click "Sign out" in LunarTweaks on the old one first.\n\n` +
    `Lost this email? Get your keys again at ${site}/lost-key.html\n\n- LunarTweaks\n`;
  try {
    await env.EMAIL.send({ to: rows[0].email, from: { email: env.MAIL_FROM || 'noreply@lunartweaks.se', name: 'LunarTweaks' },
                           subject: `Your LunarTweaks key${many ? 's' : ''}`, text });
    return true;
  } catch (e) {
    console.log('email failed', e && e.code);
    return false;
  }
}

// ---- Signing (the app verifies with the public key built into it) ----
let signingKey = null;
function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
function derLen(n) { return n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255]; }
// Accepts the server's "BEGIN EC PRIVATE KEY" (SEC1) or "BEGIN PRIVATE KEY" (PKCS#8) PEM.
async function getSigningKey(env) {
  if (signingKey) return signingKey;
  const pem = String(env.SIGNING_KEY || '');
  let der = pemToDer(pem);
  if (pem.includes('BEGIN EC PRIVATE KEY')) {
    const alg = [0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    const body = [0x02, 0x01, 0x00, ...alg, 0x04, ...derLen(der.length), ...der];
    der = Uint8Array.from([0x30, ...derLen(body.length), ...body]);
  }
  signingKey = await crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  return signingKey;
}
async function signAnswer(env, op, nonce, device, key, status, plan, activation) {
  const msg = `LunarTweaks/key/v1\n${op}\n${nonce}\n${device}\n${await sha256(key)}\n${status}\n${plan}\n${activation}`;
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, await getSigningKey(env), enc.encode(msg));
  return hex(sig); // WebCrypto gives raw r||s (64 bytes), the format the app expects
}

async function readJson(request) {
  const text = await request.text();
  if (text.length > 8192) stop({ status: 'error', error: 'Invalid request' }, 400);
  try { const j = JSON.parse(text); if (j && typeof j === 'object') return j; } catch {}
  stop({ status: 'error', error: 'Invalid request' }, 400);
}

// ---- App: activate / validate / deactivate ----
async function handleApp(env, request, op) {
  if (request.method !== 'POST') stop({ status: 'error', error: 'POST only' }, 405);
  await rateLimit(env, request, 'app', 30, 60);
  const b = await readJson(request);
  const key = normalizeKey(b.key);
  const device = String(b.device || ''), nonce = String(b.nonce || '');
  const label = String(b.label || '').trim().slice(0, 64);
  if (!/^[0-9a-f]{40}$/.test(device) || !/^[0-9a-f]{64}$/.test(nonce)) stop({ status: 'error', error: 'Invalid request' }, 400);
  if (!validKey(key)) stop({ status: 'not_found' });
  const d = await db(env);
  const row = await findKey(env, key);
  if (!row) stop({ status: 'not_found' });
  const kh = row.key_hash;

  if (op === 'deactivate') {
    await d.prepare('DELETE FROM lt_activations WHERE key_hash = ? AND device = ?').bind(kh, device).run();
    stop({ status: 'ok' });
  }
  if (row.revoked) stop({ status: 'revoked' });

  let act = await d.prepare('SELECT activation FROM lt_activations WHERE key_hash = ? AND device = ?').bind(kh, device).first();
  let activation = act && act.activation;
  if (!activation) {
    if (op === 'validate') stop({ status: 'not_activated' });
    const used = (await d.prepare('SELECT COUNT(*) AS n FROM lt_activations WHERE key_hash = ?').bind(kh).first()).n;
    if (used >= row.devices) stop({ status: 'limit', devices_used: used, devices_max: row.devices });
    activation = randHex(8);
    const t = now();
    await d.prepare(`INSERT INTO lt_activations (key_hash, device, activation, label, created, last_seen) VALUES (?, ?, ?, ?, ?, ?)
                     ON CONFLICT(key_hash, device) DO NOTHING`).bind(kh, device, activation, label, t, t).run();
    activation = (await d.prepare('SELECT activation FROM lt_activations WHERE key_hash = ? AND device = ?').bind(kh, device).first()).activation;
  } else {
    await d.prepare('UPDATE lt_activations SET last_seen = ?, label = ? WHERE key_hash = ? AND device = ?').bind(now(), label, kh, device).run();
  }
  return json({ status: 'granted', plan: row.plan, activation,
                sig: await signAnswer(env, op, nonce, device, key, 'granted', row.plan, activation) });
}

// ---- Stripe webhook ----
async function handleWebhook(env, request) {
  if (request.method !== 'POST') stop({ status: 'error', error: 'POST only' }, 405);
  const payload = await request.text();
  const secret = env.STRIPE_WEBHOOK_SECRET;
  if (!secret) stop({ error: 'Webhook secret not set' }, 500);
  let t = null; const sigs = [];
  for (const part of (request.headers.get('Stripe-Signature') || '').split(',')) {
    const [k, v] = part.trim().split('=', 2);
    if (k === 't') t = v;
    if (k === 'v1') sigs.push(v);
  }
  if (!t || !/^\d+$/.test(t) || Math.abs(now() - Number(t)) > 300) stop({ error: 'Bad timestamp' }, 400);
  const hkey = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  let ok = false;
  for (const s of sigs) {
    if (!/^[0-9a-f]{64}$/.test(s)) continue;
    const bytes = Uint8Array.from(s.match(/../g), h => parseInt(h, 16));
    if (await crypto.subtle.verify('HMAC', hkey, bytes, enc.encode(`${t}.${payload}`))) ok = true;
  }
  if (!ok) stop({ error: 'Bad signature' }, 400);

  let event;
  try { event = JSON.parse(payload); } catch { stop({ error: 'Bad event' }, 400); }
  if (!event || !event.id || !event.type) stop({ error: 'Bad event' }, 400);
  const d = await db(env);
  if (await d.prepare('SELECT 1 AS x FROM lt_events WHERE id = ?').bind(event.id).first()) return json({ received: true, duplicate: true });

  const obj = (event.data && event.data.object) || {};
  switch (event.type) {
    case 'checkout.session.completed':
    case 'checkout.session.async_payment_succeeded':
      if (sessionPaid(obj)) await issueForSession(env, obj);
      break;
    case 'charge.refunded':
      if (obj.refunded === true && typeof obj.payment_intent === 'string')
        await d.prepare('UPDATE lt_keys SET revoked = 1 WHERE payment_intent = ?').bind(obj.payment_intent).run();
      break;
    case 'charge.dispute.created':
      if (typeof obj.payment_intent === 'string')
        await d.prepare('UPDATE lt_keys SET revoked = 1 WHERE payment_intent = ?').bind(obj.payment_intent).run();
      break;
  }
  await d.prepare('INSERT INTO lt_events (id, created) VALUES (?, ?) ON CONFLICT(id) DO NOTHING').bind(event.id, now()).run();
  return json({ received: true });
}

// ---- Thank-you page lookup ----
async function stripeGet(env, path) {
  if (!env.STRIPE_SECRET_KEY) return null;
  const r = await fetch('https://api.stripe.com/v1/' + path, { headers: { Authorization: 'Bearer ' + env.STRIPE_SECRET_KEY } });
  return r.ok ? r.json() : null;
}
async function handleSession(env, request, url) {
  const id = url.searchParams.get('session_id') || '';
  if (!/^cs_(test|live)_[A-Za-z0-9]{10,200}$/.test(id)) stop({ status: 'error', error: 'Invalid session' }, 400);
  await rateLimit(env, request, 'session', 20, 60);
  let rows = await keysForSession(env, id);
  if (!rows.length) {
    const s = await stripeGet(env, 'checkout/sessions/' + encodeURIComponent(id));
    if (!s) stop({ status: 'not_found' });
    if (!sessionPaid(s)) stop({ status: 'pending' });
    rows = await issueForSession(env, s);
  }
  if (rows.every(r => r.revoked)) stop({ status: 'revoked' });
  rows = rows.filter(r => !r.revoked);
  return json({ status: 'ok', key: rows[0].license_key, keys: rows.map(r => r.license_key), plan: planName(rows[0].plan),
                devices: rows[0].devices, email: rows[0].email, emailed: !!env.EMAIL });
}

// ---- Lost key ----
async function handleLostKey(env, request) {
  if (request.method !== 'POST') stop({ status: 'error', error: 'POST only' }, 405);
  if (!env.EMAIL) stop({ status: 'error', error: 'Email is not set up yet. Contact support and we will send your key.' }, 503);
  await rateLimit(env, request, 'lost', 5, 600);
  const email = String((await readJson(request)).email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 190) stop({ status: 'error', error: 'Enter a valid email address' }, 400);
  const { results } = await (await db(env)).prepare('SELECT * FROM lt_keys WHERE email = ? AND revoked = 0').bind(email).all();
  if (results.length) await sendKeyEmail(env, results);
  return json({ status: 'sent' });
}

// ---- Admin page ----
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
async function hmacHex(secret, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
async function adminSession(env, request) {
  const m = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)lt_admin=(\d+)\.([0-9a-f]{64})/);
  if (!m || Number(m[1]) < now()) return null;
  const good = await hmacHex(env.ADMIN_TOKEN, 'admin|' + m[1]);
  return good === m[2] ? { exp: m[1], csrf: await hmacHex(env.ADMIN_TOKEN, 'csrf|' + m[1]) } : null;
}
function timingSafeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function handleAdmin(env, request, url) {
  if (!env.ADMIN_TOKEN) stop({ error: 'ADMIN_TOKEN not set' }, 500);
  const headers = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY',
                    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'" };
  let session = await adminSession(env, request);
  let msg = '';
  const form = request.method === 'POST' ? await request.formData() : null;
  if (form && form.has('token')) {
    await rateLimit(env, request, 'admin', 10, 600);
    if (timingSafeEqual(form.get('token'), env.ADMIN_TOKEN)) {
      const exp = String(now() + 8 * 3600);
      const cookie = `lt_admin=${exp}.${await hmacHex(env.ADMIN_TOKEN, 'admin|' + exp)}; Path=/api/; Secure; HttpOnly; SameSite=Strict`;
      return new Response(null, { status: 303, headers: { Location: '/api/admin.php', 'Set-Cookie': cookie } });
    }
    msg = 'Wrong password.';
  }
  if (form && form.get('action') === 'logout')
    return new Response(null, { status: 303, headers: { Location: '/api/admin.php', 'Set-Cookie': 'lt_admin=; Path=/api/; Max-Age=0; Secure; HttpOnly; SameSite=Strict' } });

  const d = await db(env);
  if (session && form && form.has('action')) {
    if (form.get('csrf') !== session.csrf) return new Response('Bad form', { status: 400 });
    const key = normalizeKey(form.get('key') || '');
    const row = key ? await findKey(env, key) : null;
    switch (form.get('action')) {
      case 'create': {
        const plan = form.get('plan') === 'duo' ? 'duo' : 'pro';
        const email = String(form.get('email') || '').trim();
        const made = [];
        for (let i = 0; i < planKeyCount(env, plan); i++)
          made.push(await createKey(env, plan, email || null, null, null, String(form.get('note') || '').slice(0, 200)));
        msg = 'Created ' + made.map(r => r.license_key).join(', ');
        if (form.get('send') && made[0].email && (await sendKeyEmail(env, made))) msg += ' and emailed ' + (made.length > 1 ? 'them.' : 'it.');
        break;
      }
      case 'resend': if (row) msg = (await sendKeyEmail(env, row)) ? 'Sent.' : 'Email is not set up or failed.'; break;
      case 'reset': if (row) { await d.prepare('DELETE FROM lt_activations WHERE key_hash = ?').bind(row.key_hash).run(); msg = 'All PCs freed.'; } break;
      case 'revoke': if (row) { await d.prepare('UPDATE lt_keys SET revoked = 1 WHERE key_hash = ?').bind(row.key_hash).run(); msg = 'Revoked.'; } break;
      case 'restore': if (row) { await d.prepare('UPDATE lt_keys SET revoked = 0 WHERE key_hash = ?').bind(row.key_hash).run(); msg = 'Restored.'; } break;
    }
  }

  const css = `body{margin:0;background:#07060D;color:#F2EFFA;font:15px/1.5 system-ui,sans-serif}main{max-width:980px;margin:0 auto;padding:24px 16px}
h1{font-size:22px}input,select,button{font:inherit;padding:8px 10px;border-radius:8px;border:1px solid #262139;background:#110F1C;color:inherit}
button{background:#7C3AED;border:0;color:#fff;cursor:pointer}button.alt{background:#1A1729}form.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
.card{background:#110F1C;border:1px solid #262139;border-radius:14px;padding:14px;margin:10px 0}.k{font-family:ui-monospace,monospace;font-size:16px}
.muted{color:#A49EBC}.bad{color:#ff8a8a}.msg{background:#1A1729;padding:10px;border-radius:8px}`;
  let body = `<h1>LunarTweaks keys</h1>${msg ? `<p class="msg">${esc(msg)}</p>` : ''}`;
  if (!session) {
    body += `<form method="post" class="row"><label>Admin password <input type="password" name="token" autocomplete="current-password" required></label><button>Sign in</button></form>`;
  } else {
    const q = (url.searchParams.get('q') || '').trim();
    const rows = q
      ? (await d.prepare('SELECT * FROM lt_keys WHERE email = ? OR key_hash = ? OR session_id = ? ORDER BY created DESC LIMIT 50')
           .bind(q.toLowerCase(), await sha256(normalizeKey(q)), q).all()).results
      : (await d.prepare('SELECT * FROM lt_keys ORDER BY created DESC LIMIT 20').all()).results;
    const c = esc(session.csrf);
    body += `<form method="get" class="row"><input name="q" value="${esc(q)}" placeholder="Email, key or checkout session" size="40"><button>Search</button></form>
<details class="card"><summary>Create a key (giveaway, support)</summary><form method="post" class="row"><input type="hidden" name="csrf" value="${c}"><input type="hidden" name="action" value="create">
<select name="plan"><option value="pro">Pro (1 PC)</option><option value="duo">Duo (2 keys, 1 PC each)</option></select><input name="email" type="email" placeholder="Email (optional)">
<input name="note" placeholder="Note (optional)"><label><input type="checkbox" name="send" value="1"> Email it</label><button>Create</button></form></details>`;
    for (const r of rows) {
      const devs = (await d.prepare('SELECT label FROM lt_activations WHERE key_hash = ?').bind(r.key_hash).all()).results;
      body += `<div class="card"><div class="k">${esc(r.license_key)} ${r.revoked ? '<span class="bad">revoked</span>' : ''}</div>
<div class="muted">${planName(r.plan)} · ${devs.length}/${r.devices} PCs${devs.length ? ' (' + esc(devs.map(x => x.label).join(', ')) + ')' : ''} · ${esc(r.email || 'no email')} · ${new Date(r.created * 1000).toISOString().slice(0, 16).replace('T', ' ')}${r.note ? ' · ' + esc(r.note) : ''}</div>
<form method="post" class="row"><input type="hidden" name="csrf" value="${c}"><input type="hidden" name="key" value="${esc(r.license_key)}">
${r.email ? '<button name="action" value="resend" class="alt">Resend email</button>' : ''}<button name="action" value="reset" class="alt">Free all PCs</button>
${r.revoked ? '<button name="action" value="restore" class="alt">Restore</button>' : '<button name="action" value="revoke" class="alt">Revoke</button>'}</form></div>`;
    }
    body += `<form method="post"><input type="hidden" name="action" value="logout"><button class="alt">Sign out</button></form>`;
  }
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>LunarTweaks keys</title><style>${css}</style></head><body><main>${body}</main></body></html>`, { headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/api/, '').replace(/\/$/, '');
    try {
      switch (path) {
        case '/activate.php': return await handleApp(env, request, 'activate');
        case '/validate.php': return await handleApp(env, request, 'validate');
        case '/deactivate.php': return await handleApp(env, request, 'deactivate');
        case '/webhook.php': return await handleWebhook(env, request);
        case '/session.php': return await handleSession(env, request, url);
        case '/lost-key.php': return await handleLostKey(env, request);
        case '/admin.php': return await handleAdmin(env, request, url);
        case '/health': return json({ ok: true });
        default: return json({ status: 'error', error: 'Not found' }, 404);
      }
    } catch (e) {
      if (e instanceof Reply) return e.response;
      console.log('error', e && e.stack);
      return json({ status: 'error', error: 'Service unavailable' }, 500);
    }
  },
};
