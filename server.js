import express from 'express';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { initDb, kvGet, kvSet, kvList, kvDelete, kvCleanup } from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.set('trust proxy', 1); // needed on Railway/Render so rate-limiting sees the real client IP

app.use(helmet({ contentSecurityPolicy: false })); // CSP off: pages use inline <style>/<script> by design
app.use(express.json({ limit: '32kb' })); // kept small globally — screenshot uploads get their own raised-limit parser below
app.use(express.static(path.join(__dirname, 'public')));

// ==== Admin password ====
// Set ADMIN_PASSWORD in your host's environment variables (Railway → Variables).
// Nothing secret is hardcoded here. If you forget to set it, a random
// one-time password is generated and printed to the server logs on boot.
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
if (!process.env.ADMIN_PASSWORD) {
  console.warn('⚠ ADMIN_PASSWORD is not set.');
  console.warn(`⚠ Using a random one-time password for this boot: ${ADMIN_PASSWORD}`);
  console.warn('⚠ Set ADMIN_PASSWORD in your environment variables to keep it fixed across restarts.');
}

// ==== Admin 2FA (TOTP, RFC 6238) ====
// Set ADMIN_TOTP_SECRET in your environment variables (a base32 string).
// If you don't have one yet, leave it unset — a fresh one is generated and
// printed to the server logs on boot so you can add it to Google
// Authenticator / Authy (manual entry, not a QR code — nothing is sent to
// any third party to generate this).
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function randomBase32Secret(len = 20) {
  let out = '';
  for (let i = 0; i < len; i++) out += BASE32_ALPHABET[crypto.randomInt(0, 32)];
  return out;
}
function base32Decode(input) {
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const char of clean) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
function totpAt(secretBase32, timeStepCounter) {
  const key = base32Decode(secretBase32);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(timeStepCounter));
  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
}
function verifyTotp(secretBase32, code) {
  if (!/^\d{6}$/.test(String(code || ''))) return false;
  const counter = Math.floor(Date.now() / 1000 / 30);
  // allow the previous/current/next 30s window for clock drift
  for (const c of [counter - 1, counter, counter + 1]) {
    if (safeEqual(totpAt(secretBase32, c), String(code))) return true;
  }
  return false;
}
// (2FA removed — see conversation history if you want to re-enable it later.
// The TOTP helper functions above are unused now but left in place in case.)

function genKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I — avoids visual mix-ups
  let out = 'CORE-';
  for (let i = 0; i < 8; i++) {
    if (i === 4) out += '-';
    out += chars[crypto.randomInt(0, chars.length)];
  }
  return out;
}

// Constant-time string compare so admin-login timing can't leak the password.
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// ==== Password hashing for real user accounts (scrypt + per-user salt —
// no external dependency needed, this is Node's built-in crypto) ====
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || '').split(':');
  if (!salt || !hash) return false;
  const hashBuffer = Buffer.from(hash, 'hex');
  const testHash = crypto.scryptSync(password, salt, 64);
  if (hashBuffer.length !== testHash.length) return false;
  return crypto.timingSafeEqual(hashBuffer, testHash);
}
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function checkAdmin(req) {
  const header = req.headers['x-admin-pass'];
  return typeof header === 'string' && safeEqual(header, ADMIN_PASSWORD);
}

// ==== Rate limiters ====
const keyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again in a bit.' } });
const adminLoginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts. Try again in a bit.' } });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again in a bit.' } });
const chatLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Slow down — too many messages at once.' } });
// NEW: throttles GET /api/chat (history load), same idea as chatLimiter but for reads.
const chatReadLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Slow down — too many requests.' } });

// ==== Access-key gate for chat routes ====
async function requireAccessKey(req, res, next) {
  const key = String(req.headers['x-access-key'] || '').toUpperCase().trim();
  if (!key) return res.status(401).json({ error: 'Access key required.' });
  const rec = await kvGet(`keys:${key}`);
  if (!rec || !rec.active) return res.status(401).json({ error: 'Invalid or revoked access key.' });

  // paid plans auto-expire after PLAN_DURATION_DAYS — once past that,
  // silently drop back to free rather than leaving them stuck on a
  // plan they haven't renewed
  let plan = rec.plan || 'free';
  if (plan !== 'free' && rec.planExpiresAt && new Date(rec.planExpiresAt) < new Date()) {
    plan = 'free';
    rec.plan = 'free';
    rec.planExpiresAt = null;
    await kvSet(`keys:${key}`, rec);
  }

  // usage counters reset every PLAN_DURATION_DAYS from when they were
  // last reset (not calendar-month based, just a rolling window per key)
  const usageKey = `usage:${key}`;
  let usage = await kvGet(usageKey);
  const cutoff = Date.now() - PLAN_DURATION_DAYS * 24 * 60 * 60 * 1000;
  if (!usage || new Date(usage.periodStart).getTime() < cutoff) {
    usage = { periodStart: new Date().toISOString(), messagesUsed: 0, imagesUsed: 0 };
    await kvSet(usageKey, usage);
  }

  req.accessKey = key;
  req.userPlan = plan;
  req.usage = usage;
  next();
}

// ==== Original 4 hidden-persona endpoints — full CORE persona + conversation history ====
const ENDPOINTS = {
  low:      (q) => `https://llama.adi7ya.workers.dev/?q=${encodeURIComponent(q)}`,
  medium:   (q) => `https://gemini.adi7ya.workers.dev/?q=${encodeURIComponent(q)}`,
  standard: (q) => `https://copilot.adi7ya.workers.dev/?q=${encodeURIComponent(q)}`,
  high:     (q) => `https://gpt5.adi7ya.workers.dev/?q=${encodeURIComponent(q)}`,
};

// ==== New models — these are simple single-turn "q=" style wrapper APIs,
// not built to take a full persona+history prompt like the 4 above. We
// send them the raw user message only (see SIMPLE_MODES + /api/chat below). ====
const SIMPLE_ENDPOINTS = {
  gptlogic:    (q) => `https://r-bots-free-apis.co08.art/api/v1/api/gptlogic?q=${encodeURIComponent(q)}&prompt=${encodeURIComponent('be friendly')}`,
  deepai:      (q) => `https://r-bots-free-apis.co08.art/api/v1/api/deep-ai?query=${encodeURIComponent(q)}`,
  qwen:        (q) => `https://r-bots-free-apis.co08.art/api/v1/api/qwen?q=${encodeURIComponent(q)}`,
  deepseekv3:  (q) => `https://r-bots-free-apis.co08.art/api/v1/api/deepseek-v3?q=${encodeURIComponent(q)}`,
  deepseekr1:  (q) => `https://r-bots-free-apis.co08.art/api/v1/api/deepseek-r1?q=${encodeURIComponent(q)}`,
  gpt3:        (q) => `https://r-bots-free-apis.co08.art/api/v1/api/gpt3?q=${encodeURIComponent(q)}`,
  claudehaiku: (q) => `https://claudehaiku.onrender.com/TG/@SAHILXALONE/ai/claudehaiku?text=${encodeURIComponent(q)}`,
};
const SIMPLE_MODES = new Set(Object.keys(SIMPLE_ENDPOINTS));

// image-generation mode — different output shape entirely (a URL, not
// chat text). Kept separate so /api/chat can branch on it below.
// NOTE: this endpoint timed out during testing, so its response shape
// is unconfirmed — treat as best-effort until verified.
const IMAGE_ENDPOINTS = {
  dalle: (q) => `https://r-bots-free-apis.co08.art/api/v1/api/dalle?q=${encodeURIComponent(q)}`,
};
const IMAGE_MODES = new Set(Object.keys(IMAGE_ENDPOINTS));

Object.assign(ENDPOINTS, SIMPLE_ENDPOINTS, IMAGE_ENDPOINTS);

// ==== Subscription plans — which modes each tier can use ====
// Keys default to 'free' plan when issued unless admin sets otherwise.
const PLAN_MODES = {
  free:     ['low', 'medium'],
  basic:    ['low', 'medium', 'standard', 'gptlogic', 'deepai', 'gpt3'],
  pro:      ['low', 'medium', 'standard', 'high', 'gptlogic', 'deepai', 'gpt3', 'deepseekv3', 'qwen', 'claudehaiku'],
  ultimate: Object.keys(ENDPOINTS),
};
const PLAN_ORDER = ['free', 'basic', 'pro', 'ultimate'];
function planAllows(plan, mode) {
  const allowed = PLAN_MODES[plan] || PLAN_MODES.free;
  return allowed.includes(mode);
}

// ==== Plan pricing + usage limits ====
// messages/images: null means unlimited. Free has no expiry (it never
// runs out); paid plans run for PLAN_DURATION_DAYS from approval, and
// requireAccessKey auto-downgrades a key to 'free' once it's past expiry.
const PLAN_INFO = {
  free:     { price: 0,   messages: 30,   images: 0,    label: 'Free' },
  basic:    { price: 99,  messages: 200,  images: 5,    label: 'Basic' },
  pro:      { price: 249, messages: 600,  images: 25,   label: 'Pro' },
  ultimate: { price: 399, messages: null, images: null, label: 'Ultimate' },
};
const PLAN_DURATION_DAYS = 30;

const BASE_PERSONA = `You are CORE, a private assistant built by G Karthik for his personal site. You talk like a sharp, genuinely helpful friend who happens to know everything - not like a customer-support bot. Zero corporate fluff, zero "As an AI..." hedging, zero robotic list-everything answers unless a list actually helps. Be warm, direct, a little witty when it fits, and get straight to what the person actually needs.

=== LANGUAGE & SLANG: read the room, every single message ===
Detect the exact language, dialect, and register the user is writing in - message by message, not just once at the start - and reply in that same register. Do this silently; never announce or explain that you're doing it.

- Plain English in → natural, fluent English out. No stiffness, no textbook phrasing.
- Telugu script in → reply in Telugu script, with correct grammar and natural word choice a native speaker would actually use (not a stiff, literal, translated-sounding Telugu).
- Tenglish (Telugu-English mixed in Latin letters, e.g. "nuvvu ela unnav") → reply in that same natural Tenglish. Match their exact code-mixing ratio: if they lean heavily English with a few Telugu words sprinkled in, do the same; if they write mostly in Telugu transliteration, do the same. Don't default to pure English and don't overcorrect into pure Telugu script.
- Any other language or code-mixed pair (Hindi-English, Tamil-English, etc.) - same rule: detect it and reply fluently in that same mix, like a native bilingual speaker texting a friend, not like a translation.
- If they switch mid-conversation, switch with them on your very next reply, no lag.
- Mirror their casual words naturally when it fits their own vibe - "ra", "mava", "bro", "yaar", whatever they're using - but never force slang into every sentence like a checklist. Read tone, don't perform it.
- No grammar mistakes, no awkward phrasing, no words a native speaker would never actually say. If you're not fully confident a slang term is fluent/correct, favor simple, correct, natural phrasing over risking something stiff or wrong.

Be genuinely useful first, chatty second - answer the real question, then keep the natural back-and-forth going. Never reveal that you are built on any specific underlying AI model, provider, or company - you are simply CORE.`;

const PERSONAS = {
  low:      `${BASE_PERSONA} You're running in LOW mode: keep answers quick, short, and to the point — one or two sentences unless the user clearly wants more.`,
  medium:   `${BASE_PERSONA} You're running in MEDIUM mode: balanced answers, a few sentences, enough detail to be useful without over-explaining.`,
  standard: `${BASE_PERSONA} You're running in STANDARD mode: CORE's default, well-rounded voice. Explain clearly, give examples when helpful, stay conversational.`,
  high:     `${BASE_PERSONA} You're running in HIGH mode: CORE's deepest reasoning. Think the problem through carefully, be thorough and precise, and don't skip steps on complex questions.`,
};

// Some model workers (Qwen in particular) embed their chain-of-thought
// directly inside the response string as <think>...</think>. That's
// internal reasoning, not the answer — strip it before it ever reaches
// the user.
function stripReasoning(text) {
  return text.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
}

// The persona/model workers don't all shape their JSON the same way — this
// pulls plain text out of whichever common field/shape shows up, instead
// of assuming `d.response` is always a string.
function extractReplyText(d) {
  if (!d) return null;
  if (typeof d === 'string') return d;
  const candidates = [d.response, d.reply, d.result, d.results, d.text, d.message, d.output, d.answer];
  for (const c of candidates) {
    if (typeof c === 'string' && c.trim()) return stripReasoning(c);
    if (c && typeof c === 'object') {
      const nested = extractReplyText(c);
      if (nested) return nested;
    }
  }
  return null;
}

async function fetchWithTimeout(url, ms = 20000) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(t);
  }
}

// ==== Access key verification ====
app.post('/api/verify-key', keyLimiter, async (req, res) => {
  const key = String(req.body?.key || '').toUpperCase().trim();
  if (!key) return res.json({ valid: false });
  const rec = await kvGet(`keys:${key}`);
  res.json({ valid: !!(rec && rec.active) });
});

// ==== Visitor requests access ====
app.post('/api/request-access', keyLimiter, async (req, res) => {
  let { name } = req.body || {};
  name = String(name || 'Unnamed visitor').slice(0, 100);
  const id = `requests:${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  await kvSet(id, {
    name,
    timestamp: new Date().toISOString(),
    status: 'pending',
  });
  res.json({ ok: true });
});

// ==== Current plan for this access key ====
const uploadJson = express.json({ limit: '9mb' }); // only this route needs room for a base64 screenshot

// ================================================================
// Real user accounts (email + password) — signing up or logging in
// hands back an access key exactly like the invite-only flow did, so
// every existing feature (console, dashboard, plans, usage limits)
// keeps working completely unchanged. The account layer just sits
// in front of it.
//   user:{email}  -> { name, passwordHash, accessKey, createdAt }
// The linked keys:{accessKey} record gets an extra `ownerEmail` field
// so profile lookups can go key -> email -> user record.
// ================================================================

app.post('/api/signup', authLimiter, async (req, res) => {
  let { name, email, password } = req.body || {};
  name = String(name || '').trim().slice(0, 60);
  email = String(email || '').trim().toLowerCase();
  password = String(password || '');
  if (!name) return res.status(400).json({ error: 'name required' });
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'invalid email' });
  if (password.length < 8) return res.status(400).json({ error: 'password must be at least 8 characters' });

  const existing = await kvGet(`user:${email}`);
  if (existing) return res.status(409).json({ error: 'an account with that email already exists' });

  const accessKey = genKey();
  await kvSet(`keys:${accessKey}`, {
    issuedTo: name,
    issuedAt: new Date().toISOString(),
    active: true,
    plan: 'free',
    planExpiresAt: null,
    ownerEmail: email,
  });
  await kvSet(`user:${email}`, {
    name,
    passwordHash: hashPassword(password),
    accessKey,
    createdAt: new Date().toISOString(),
  });

  res.json({ accessKey, name });
});

app.post('/api/login', authLimiter, async (req, res) => {
  let { email, password } = req.body || {};
  email = String(email || '').trim().toLowerCase();
  password = String(password || '');
  const user = await kvGet(`user:${email}`);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'invalid email or password' });
  }
  const rec = await kvGet(`keys:${user.accessKey}`);
  if (!rec || !rec.active) return res.status(403).json({ error: 'this account\'s access key was revoked' });
  res.json({ accessKey: user.accessKey, name: user.name });
});

// ==== Account/profile: read the signed-in user's own details ====
app.get('/api/account', keyLimiter, requireAccessKey, async (req, res) => {
  const rec = await kvGet(`keys:${req.accessKey}`);
  if (!rec?.ownerEmail) return res.json({ hasAccount: false });
  const user = await kvGet(`user:${rec.ownerEmail}`);
  if (!user) return res.json({ hasAccount: false });
  res.json({ hasAccount: true, name: user.name, email: rec.ownerEmail, createdAt: user.createdAt });
});

// ==== Account/profile: update display name ====
app.post('/api/account/name', keyLimiter, requireAccessKey, async (req, res) => {
  const name = String(req.body?.name || '').trim().slice(0, 60);
  if (!name) return res.status(400).json({ error: 'name required' });
  const rec = await kvGet(`keys:${req.accessKey}`);
  if (!rec?.ownerEmail) return res.status(400).json({ error: 'no account linked to this key' });
  const user = await kvGet(`user:${rec.ownerEmail}`);
  if (!user) return res.status(404).json({ error: 'account not found' });
  user.name = name;
  await kvSet(`user:${rec.ownerEmail}`, user);
  rec.issuedTo = name;
  await kvSet(`keys:${req.accessKey}`, rec);
  res.json({ ok: true });
});

// ==== Account/profile: change password ====
app.post('/api/account/password', authLimiter, requireAccessKey, async (req, res) => {
  const currentPassword = String(req.body?.currentPassword || '');
  const newPassword = String(req.body?.newPassword || '');
  if (newPassword.length < 8) return res.status(400).json({ error: 'new password must be at least 8 characters' });
  const rec = await kvGet(`keys:${req.accessKey}`);
  if (!rec?.ownerEmail) return res.status(400).json({ error: 'no account linked to this key' });
  const user = await kvGet(`user:${rec.ownerEmail}`);
  if (!user || !verifyPassword(currentPassword, user.passwordHash)) {
    return res.status(401).json({ error: 'current password is incorrect' });
  }
  user.passwordHash = hashPassword(newPassword);
  await kvSet(`user:${rec.ownerEmail}`, user);
  res.json({ ok: true });
});

app.get('/api/my-plan', keyLimiter, requireAccessKey, async (req, res) => {
  const rec = await kvGet(`keys:${req.accessKey}`);
  const info = PLAN_INFO[req.userPlan] || PLAN_INFO.free;
  const justUpgraded = !!rec?.pendingNotification;
  if (justUpgraded) {
    rec.pendingNotification = false;
    await kvSet(`keys:${req.accessKey}`, rec);
  }
  res.json({
    plan: req.userPlan,
    planLabel: info.label,
    expiresAt: rec?.planExpiresAt || null,
    accessKey: req.accessKey,
    justUpgraded,
    limits: { messages: info.messages, images: info.images },
    used: { messages: req.usage.messagesUsed, images: req.usage.imagesUsed },
    remaining: {
      messages: info.messages === null ? null : Math.max(0, info.messages - req.usage.messagesUsed),
      images: info.images === null ? null : Math.max(0, info.images - req.usage.imagesUsed),
    },
  });
});

// ==== Visitor requests a plan upgrade (manual approval — no payment
// gateway wired in; visitor pays via UPI/QR outside the app, then
// submits this with a note, and admin approves it by hand) ====
app.post('/api/request-upgrade', keyLimiter, uploadJson, async (req, res) => {
  let { key, plan, note, screenshot } = req.body || {};
  key = String(key || '').toUpperCase().trim();
  plan = String(plan || '');
  note = String(note || '').slice(0, 300);
  screenshot = String(screenshot || '');
  if (!PLAN_MODES[plan]) return res.status(400).json({ error: 'bad plan' });
  if (!screenshot.startsWith('data:image/')) return res.status(400).json({ error: 'payment screenshot required' });
  if (screenshot.length > 5.5 * 1024 * 1024) return res.status(400).json({ error: 'screenshot too large — try a smaller image' });
  const rec = await kvGet(`keys:${key}`);
  if (!rec || !rec.active) return res.status(400).json({ error: 'unknown or inactive access key' });

  const id = `requests:${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  await kvSet(id, {
    type: 'upgrade',
    key,
    plan,
    note,
    screenshot,
    name: rec.issuedTo || key,
    timestamp: new Date().toISOString(),
    status: 'pending',
  });
  res.json({ ok: true });
});

// ==== Admin login ====
app.post('/api/admin-login', adminLoginLimiter, (req, res) => {
  const password = String(req.body?.password || '');
  res.json({ ok: safeEqual(password, ADMIN_PASSWORD) });
});

// ==== Admin: pending requests + issued keys ====
// FIX: added adminLoginLimiter — this route was previously unthrottled,
// letting someone hammer it with guessed X-Admin-Pass headers with no limit.
app.get('/api/admin-data', adminLoginLimiter, async (req, res) => {
  if (!checkAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
  const statusFilter = String(req.query.status || 'pending'); // pending | approved | rejected | all

  const reqKeys = await kvList('requests:');
  const allRequests = [];
  const counts = { pending: 0, approved: 0, rejected: 0 };
  for (const k of reqKeys) {
    const r = await kvGet(k);
    if (!r) continue;
    if (counts[r.status] !== undefined) counts[r.status]++;
    allRequests.push({ id: k, ...r });
  }
  const pending = allRequests
    .filter((r) => statusFilter === 'all' || r.status === statusFilter)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  const keyKeys = await kvList('keys:');
  const keys = [];
  for (const k of keyKeys) {
    const r = await kvGet(k);
    if (r) keys.push({ id: k.replace('keys:', ''), ...r });
  }
  keys.sort((a, b) => new Date(b.issuedAt) - new Date(a.issuedAt));

  res.json({ pending, keys, requestCounts: counts });
});

// ==== Admin: analytics dashboard ====
// Built entirely from data we actually have — no fake "API cost"/"revenue"
// numbers, since these are our own endpoints, not metered third-party calls.
app.get('/api/admin-analytics', adminLoginLimiter, async (req, res) => {
  if (!checkAdmin(req)) return res.status(401).json({ error: 'unauthorized' });

  // key stats
  const keyKeys = await kvList('keys:');
  let activeKeys = 0, revokedKeys = 0;
  for (const k of keyKeys) {
    const r = await kvGet(k);
    if (r) (r.active ? activeKeys++ : revokedKeys++);
  }

  // request stats
  const reqKeys = await kvList('requests:');
  let pendingRequests = 0;
  for (const k of reqKeys) {
    const r = await kvGet(k);
    if (r && r.status === 'pending') pendingRequests++;
  }

  // conversation + message stats, aggregated across every access key's
  // thread list. Also builds a "who owns this key" lookup so recent
  // activity can show a friendly name instead of the raw key.
  const keyOwner = {};
  for (const k of keyKeys) {
    const r = await kvGet(k);
    if (r) keyOwner[k.replace('keys:', '')] = r.issuedTo || 'Unnamed';
  }

  const threadListKeys = await kvList('threadlist:');
  let totalConversations = 0;
  let totalMessages = 0;
  const modeCounts = {};
  const recentActivity = [];

  for (const tlk of threadListKeys) {
    const ownerKey = tlk.replace('threadlist:', '');
    const list = (await kvGet(tlk)) || [];
    totalConversations += list.length;
    for (const t of list) {
      modeCounts[t.mode] = (modeCounts[t.mode] || 0) + 1;
      recentActivity.push({
        title: t.title,
        mode: t.mode,
        updatedAt: t.updatedAt,
        issuedTo: keyOwner[ownerKey] || 'Unknown',
      });
      const msgs = (await kvGet(`thread:${ownerKey}:${t.id}`)) || [];
      totalMessages += msgs.length;
    }
  }

  const topModels = Object.entries(modeCounts)
    .map(([mode, count]) => ({ mode, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  recentActivity.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));

  res.json({
    keys: { active: activeKeys, revoked: revokedKeys, total: activeKeys + revokedKeys },
    requests: { pending: pendingRequests },
    conversations: { total: totalConversations, messages: totalMessages },
    topModels,
    recentActivity: recentActivity.slice(0, 12),
  });
});

// ==== Admin: issue a key ====
// paid plans run for PLAN_DURATION_DAYS from the moment they're set;
// free has no expiry at all
function planExpiryFor(plan) {
  if (plan === 'free') return null;
  return new Date(Date.now() + PLAN_DURATION_DAYS * 24 * 60 * 60 * 1000).toISOString();
}

app.post('/api/admin-issue-key', adminLoginLimiter, async (req, res) => {
  if (!checkAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
  let { name, requestId, plan } = req.body || {};
  name = String(name || 'Unnamed').slice(0, 100);
  plan = PLAN_MODES[plan] ? plan : 'free';
  const key = genKey();
  await kvSet(`keys:${key}`, {
    issuedTo: name,
    issuedAt: new Date().toISOString(),
    active: true,
    plan,
    planExpiresAt: planExpiryFor(plan),
  });
  if (requestId) {
    const rd = await kvGet(requestId);
    if (rd) {
      rd.status = 'approved';
      await kvSet(requestId, rd);
    }
  }
  res.json({ key });
});

// ==== Admin: revoke a key ====
app.post('/api/admin-revoke-key', adminLoginLimiter, async (req, res) => {
  if (!checkAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
  const key = String(req.body?.key || '');
  const rec = await kvGet(`keys:${key}`);
  if (!rec) return res.status(404).json({ error: 'not found' });
  rec.active = false;
  await kvSet(`keys:${key}`, rec);
  res.json({ ok: true });
});

// ==== Admin: directly set a key's plan ====
app.post('/api/admin-set-plan', adminLoginLimiter, async (req, res) => {
  if (!checkAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
  const key = String(req.body?.key || '');
  const plan = String(req.body?.plan || '');
  if (!PLAN_MODES[plan]) return res.status(400).json({ error: 'bad plan' });
  const rec = await kvGet(`keys:${key}`);
  if (!rec) return res.status(404).json({ error: 'not found' });
  rec.plan = plan;
  rec.planExpiresAt = planExpiryFor(plan);
  await kvSet(`keys:${key}`, rec);
  res.json({ ok: true });
});

// ==== Admin: approve a pending upgrade request (sets the key's plan
// and marks the request approved — the manual "I checked the payment
// myself" step) ====
app.post('/api/admin-approve-upgrade', adminLoginLimiter, async (req, res) => {
  if (!checkAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
  const requestId = String(req.body?.requestId || '');
  const rd = await kvGet(requestId);
  if (!rd || rd.type !== 'upgrade') return res.status(404).json({ error: 'not found' });
  const rec = await kvGet(`keys:${rd.key}`);
  if (!rec) return res.status(404).json({ error: 'key not found' });
  rec.plan = rd.plan;
  rec.planExpiresAt = planExpiryFor(rd.plan);
  rec.pendingNotification = true; // shown once on the dashboard, then cleared
  await kvSet(`keys:${rd.key}`, rec);
  rd.status = 'approved';
  await kvSet(requestId, rd);
  res.json({ ok: true });
});

// ==== Admin: reject a pending request (access-request or upgrade) ====
app.post('/api/admin-reject-request', adminLoginLimiter, async (req, res) => {
  if (!checkAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
  const requestId = String(req.body?.requestId || '');
  const rd = await kvGet(requestId);
  if (!rd) return res.status(404).json({ error: 'not found' });
  rd.status = 'rejected';
  await kvSet(requestId, rd);
  res.json({ ok: true });
});

// ================================================================
// Chat threads — multiple named conversations per access key, the
// way ChatGPT/Claude's sidebar works, instead of one single thread
// per mode. Storage:
//   threadlist:{accessKey}        -> [{id, title, mode, updatedAt}, ...]
//   thread:{accessKey}:{threadId} -> [{role, text, image}, ...]
// A thread isn't locked to one model — `mode` on the list entry is
// just "whichever model most recently replied here", updated on
// every send, so the sidebar can show a colored dot/label per thread.
// ================================================================

function threadTitleFrom(message) {
  const trimmed = message.trim().replace(/\s+/g, ' ');
  return trimmed.length > 42 ? trimmed.slice(0, 42) + '…' : trimmed;
}

// ==== Threads: list all conversations for this key ====
app.get('/api/threads', chatReadLimiter, requireAccessKey, async (req, res) => {
  const list = (await kvGet(`threadlist:${req.accessKey}`)) || [];
  list.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
  res.json({ threads: list });
});

// ==== Threads: start a new conversation ====
app.post('/api/threads', chatReadLimiter, requireAccessKey, async (req, res) => {
  const mode = String(req.body?.mode || 'standard');
  const id = crypto.randomBytes(6).toString('hex');
  const entry = { id, title: 'New chat', mode, updatedAt: new Date().toISOString() };
  const list = (await kvGet(`threadlist:${req.accessKey}`)) || [];
  list.push(entry);
  await kvSet(`threadlist:${req.accessKey}`, list);
  await kvSet(`thread:${req.accessKey}:${id}`, []);
  res.json(entry);
});

// ==== Threads: load one conversation's messages ====
app.get('/api/threads/:id/messages', chatReadLimiter, requireAccessKey, async (req, res) => {
  const list = (await kvGet(`threadlist:${req.accessKey}`)) || [];
  if (!list.some((t) => t.id === req.params.id)) return res.status(404).json({ error: 'not found' });
  const history = (await kvGet(`thread:${req.accessKey}:${req.params.id}`)) || [];
  res.json({ history });
});

// ==== Threads: delete a conversation entirely (used by both the sidebar's
// trash icon and the "clear chat" button on the active thread) ====
app.post('/api/chat-clear', chatReadLimiter, requireAccessKey, async (req, res) => {
  const threadId = String(req.body?.threadId || '');
  const list = (await kvGet(`threadlist:${req.accessKey}`)) || [];
  const next = list.filter((t) => t.id !== threadId);
  await kvSet(`threadlist:${req.accessKey}`, next);
  await kvDelete(`thread:${req.accessKey}:${threadId}`);
  res.json({ ok: true });
});

// ==== Chat: send a message into a specific thread ====
app.post('/api/chat', requireAccessKey, chatLimiter, async (req, res) => {
  const mode = String(req.body?.mode || '');
  const threadId = String(req.body?.threadId || '');
  const message = req.body?.message;
  if (!ENDPOINTS[mode]) return res.status(400).json({ error: 'bad mode' });
  if (!planAllows(req.userPlan, mode)) {
    return res.status(403).json({ error: 'upgrade required', plan: req.userPlan });
  }
  if (typeof message !== 'string' || message.trim().length === 0 || message.length > 2000) {
    return res.status(400).json({ error: 'Message must be 1–2000 characters.' });
  }

  // usage-limit check — null limit means unlimited for that plan
  const isImage = IMAGE_MODES.has(mode);
  const info = PLAN_INFO[req.userPlan] || PLAN_INFO.free;
  const limit = isImage ? info.images : info.messages;
  const used = isImage ? req.usage.imagesUsed : req.usage.messagesUsed;
  if (limit !== null && used >= limit) {
    return res.status(403).json({ error: 'usage limit reached', plan: req.userPlan, kind: isImage ? 'images' : 'messages' });
  }

  const list = (await kvGet(`threadlist:${req.accessKey}`)) || [];
  const threadEntry = list.find((t) => t.id === threadId);
  if (!threadEntry) return res.status(404).json({ error: 'thread not found' });

  const key = `thread:${req.accessKey}:${threadId}`;
  let history = (await kvGet(key)) || [];
  history.push({ role: 'user', text: message });

  // Original 4 modes get the full CORE persona + recent conversation history.
  // The newer simple/image endpoints are single-turn "q=" style APIs not
  // built to parse a big persona+history block, so they just get the
  // user's raw message.
  let requestPrompt = message;
  if (PERSONAS[mode]) {
    const recent = history.slice(-9, -1);
    const convo = recent.map((m) => `${m.role === 'user' ? 'User' : 'CORE'}: ${m.text}`).join('\n');
    requestPrompt = `${PERSONAS[mode]}\n\n${convo ? 'Conversation so far:\n' + convo + '\n\n' : ''}User: ${message}\nCORE:`;
  }

  const timeoutMs = 20000;

  let reply = 'Signal dropped — try again in a moment.';
  if (isImage) {
    // this endpoint returns the image itself (not JSON) — the URL IS the
    // image, so the frontend drops it straight into an <img src>. We don't
    // pre-fetch to check reachability here, since that would hit this
    // (already slow/unverified) endpoint twice per message; the <img> tag
    // will simply fail to load if the endpoint is down.
    reply = ENDPOINTS[mode](requestPrompt);
  } else {
    try {
      const r = await fetchWithTimeout(ENDPOINTS[mode](requestPrompt), timeoutMs);
      const d = await r.json();
      reply = extractReplyText(d) || reply;
    } catch (e) {
      // keep fallback reply — endpoint timed out or errored
    }
  }

  history.push({ role: 'bot', text: reply, image: isImage });
  if (history.length > 60) history = history.slice(-60); // cap stored thread length
  await kvSet(key, history);

  // bump the right usage counter now that the message actually went through
  if (isImage) req.usage.imagesUsed++; else req.usage.messagesUsed++;
  await kvSet(`usage:${req.accessKey}`, req.usage);

  // keep the sidebar entry fresh: title from the first message, mode from
  // whichever model just answered, updatedAt bumped so it sorts to the top
  threadEntry.mode = mode;
  threadEntry.updatedAt = new Date().toISOString();
  if (threadEntry.title === 'New chat') threadEntry.title = threadTitleFrom(message);
  await kvSet(`threadlist:${req.accessKey}`, list);

  res.json({ reply, history });
});

// ==== Error handler — must come after all routes. Catches body-parser
// failures (like a too-large screenshot upload) and anything else that
// throws, and always responds with JSON so the frontend's res.json()
// never breaks on an unexpected HTML error page. ====
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'that file is too large — try a smaller screenshot.' });
  }
  console.error('Unhandled error:', err?.message || err);
  res.status(500).json({ error: 'something went wrong on our end — try again.' });
});

// ==== Start ====
const PORT = process.env.PORT || 3000;
initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`KARTHIK×CORE running on port ${PORT}`));

    // Housekeeping: trim old chat threads and stale access requests so
    // kv_store doesn't grow forever. Runs once at boot, then daily.
    // Never touches the `keys:` prefix.
    const cleanup = async () => {
      try {
        const chatDeleted = await kvCleanup('thread:', 60);
        const reqDeleted = await kvCleanup('requests:', 30);
        if (chatDeleted || reqDeleted) {
          console.log(`Cleanup: removed ${chatDeleted} old chat rows, ${reqDeleted} old request rows`);
        }
      } catch (e) {
        console.error('Cleanup failed:', e.message);
      }
    };
    cleanup();
    setInterval(cleanup, 24 * 60 * 60 * 1000);
  })
  .catch((err) => {
    console.error('Failed to init DB:', err);
    process.exit(1);
  });

