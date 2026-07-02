import express from 'express';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { initDb, kvGet, kvSet, kvList, kvCleanup } from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.set('trust proxy', 1); // needed on Railway/Render so rate-limiting sees the real client IP

app.use(helmet({ contentSecurityPolicy: false })); // CSP off: pages use inline <style>/<script> by design
app.use(express.json({ limit: '32kb' }));
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

function checkAdmin(req) {
  const header = req.headers['x-admin-pass'];
  return typeof header === 'string' && safeEqual(header, ADMIN_PASSWORD);
}

// ==== Rate limiters ====
const keyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again in a bit.' } });
const adminLoginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts. Try again in a bit.' } });
const chatLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Slow down — too many messages at once.' } });
// NEW: throttles GET /api/chat (history load), same idea as chatLimiter but for reads.
const chatReadLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Slow down — too many requests.' } });

// ==== Access-key gate for chat routes ====
async function requireAccessKey(req, res, next) {
  const key = String(req.headers['x-access-key'] || '').toUpperCase().trim();
  if (!key) return res.status(401).json({ error: 'Access key required.' });
  const rec = await kvGet(`keys:${key}`);
  if (!rec || !rec.active) return res.status(401).json({ error: 'Invalid or revoked access key.' });
  req.accessKey = key;
  next();
}

// ==== 4 hidden-persona endpoints, exposed to the frontend only as tiers ====
const ENDPOINTS = {
  low:      (q) => `https://llama.adi7ya.workers.dev/?q=${encodeURIComponent(q)}`,
  medium:   (q) => `https://gemini.adi7ya.workers.dev/?q=${encodeURIComponent(q)}`,
  standard: (q) => `https://copilot.adi7ya.workers.dev/?q=${encodeURIComponent(q)}`,
  high:     (q) => `https://gpt5.adi7ya.workers.dev/?q=${encodeURIComponent(q)}`,
};

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

// The 4 persona workers don't all shape their JSON the same way — this
// pulls plain text out of whichever common field/shape shows up, instead
// of assuming `d.response` is always a string.
function extractReplyText(d) {
  if (!d) return null;
  if (typeof d === 'string') return d;
  const candidates = [d.response, d.reply, d.result, d.text, d.message, d.output, d.answer];
  for (const c of candidates) {
    if (typeof c === 'string' && c.trim()) return c;
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

  const reqKeys = await kvList('requests:');
  const pending = [];
  for (const k of reqKeys) {
    const r = await kvGet(k);
    if (r && r.status === 'pending') pending.push({ id: k, ...r });
  }
  pending.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  const keyKeys = await kvList('keys:');
  const keys = [];
  for (const k of keyKeys) {
    const r = await kvGet(k);
    if (r) keys.push({ id: k.replace('keys:', ''), ...r });
  }
  keys.sort((a, b) => new Date(b.issuedAt) - new Date(a.issuedAt));

  res.json({ pending, keys });
});

// ==== Admin: issue a key ====
app.post('/api/admin-issue-key', adminLoginLimiter, async (req, res) => {
  if (!checkAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
  let { name, requestId } = req.body || {};
  name = String(name || 'Unnamed').slice(0, 100);
  const key = genKey();
  await kvSet(`keys:${key}`, {
    issuedTo: name,
    issuedAt: new Date().toISOString(),
    active: true,
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

// ==== Chat: load history (session = the visitor's own access key) ====
// FIX: added chatReadLimiter — this route was previously unthrottled,
// letting someone hammer it with guessed X-Access-Key headers with no limit.
app.get('/api/chat', chatReadLimiter, requireAccessKey, async (req, res) => {
  const mode = String(req.query.mode || '');
  if (!ENDPOINTS[mode]) return res.status(400).json({ error: 'bad mode' });
  const history = (await kvGet(`chat:${req.accessKey}:${mode}`)) || [];
  res.json({ history });
});

// ==== Chat: send message ====
app.post('/api/chat', requireAccessKey, chatLimiter, async (req, res) => {
  const mode = String(req.body?.mode || '');
  const message = req.body?.message;
  if (!ENDPOINTS[mode]) return res.status(400).json({ error: 'bad mode' });
  if (typeof message !== 'string' || message.trim().length === 0 || message.length > 2000) {
    return res.status(400).json({ error: 'Message must be 1–2000 characters.' });
  }

  const key = `chat:${req.accessKey}:${mode}`;
  let history = (await kvGet(key)) || [];
  history.push({ role: 'user', text: message });

  const recent = history.slice(-9, -1);
  const convo = recent.map((m) => `${m.role === 'user' ? 'User' : 'CORE'}: ${m.text}`).join('\n');
  const fullPrompt = `${PERSONAS[mode]}\n\n${convo ? 'Conversation so far:\n' + convo + '\n\n' : ''}User: ${message}\nCORE:`;

  let reply = 'Signal dropped — try again in a moment.';
  try {
    const r = await fetchWithTimeout(ENDPOINTS[mode](fullPrompt), 20000);
    const d = await r.json();
    reply = extractReplyText(d) || reply;
  } catch (e) {
    // keep fallback reply — persona endpoint timed out or errored
  }

  history.push({ role: 'bot', text: reply });
  if (history.length > 60) history = history.slice(-60); // cap stored thread length
  await kvSet(key, history);
  res.json({ reply, history });
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
        const chatDeleted = await kvCleanup('chat:', 60);
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
