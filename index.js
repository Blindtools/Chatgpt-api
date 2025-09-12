// index.js - Up-to-date production-ready Chat API using g4f (GPT4Free)
// Features:
// - Defensive g4f initialization (supports multiple export shapes)
// - Provider fallback and per-provider model hints
// - 50 requests/min per-IP rate limiter on /api/chat
// - Friendly GET / and GET /api/chat responses (prevents "Cannot GET")
// - Admin JWT login and /admin/test-providers endpoint for debugging providers
// - In-memory session store (swap with DB/Redis for production)
// - Clear JSON 404 handler and access logging to access.log
// NOTE: Install dependencies: express, cors, dotenv, jsonwebtoken, express-rate-limit, g4f

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '256kb' }));

// ----------------------
// Defensive g4f init
// ----------------------
let g4fClient = null;
let G4FProviders = null;
try {
  const g4fModule = require('g4f');
  // Common shapes
  if (g4fModule && typeof g4fModule.G4F === 'function') {
    try { g4fClient = new g4fModule.G4F(); } catch (e) { g4fClient = g4fModule.G4F ? new g4fModule.G4F() : g4fModule; }
    G4FProviders = g4fModule.providers || g4fModule.Provider || g4fModule.providers;
  } else if (g4fModule && typeof g4fModule.default === 'function') {
    try { g4fClient = new g4fModule.default(); } catch (e) { g4fClient = g4fModule.default || g4fModule; }
    G4FProviders = g4fModule.providers || g4fModule.Provider || g4fModule.providers;
  } else if (typeof g4fModule === 'function') {
    try { g4fClient = new g4fModule(); } catch (e) { g4fClient = g4fModule; }
    G4FProviders = g4fModule.providers || g4fModule.Provider || g4fModule.providers;
  } else if (g4fModule && typeof g4fModule.chatCompletion === 'function') {
    g4fClient = g4fModule;
    G4FProviders = g4fModule.providers || g4fModule.Provider || g4fModule.providers;
  } else {
    // fallback attempt: instance may attach providers later
    g4fClient = g4fModule;
    G4FProviders = g4fModule && (g4fModule.providers || g4fModule.Provider);
    console.warn('g4f loaded with unexpected shape. Defensive mode enabled.');
  }
} catch (err) {
  console.warn('g4f not installed or failed to require(); AI calls will fail until "g4f" is installed.');
  g4fClient = null;
  G4FProviders = null;
}

// ----------------------
// Utilities & stores
// ----------------------
const SESSIONS = {}; // sessionId -> [{ role, content, timestamp }]
const LOGS = [];     // { ts, sessionId, ip, message }

function nowISO() { return new Date().toISOString(); }
function newSessionId() { return crypto.randomUUID(); }
function appendAccessLog(obj) {
  try { fs.appendFileSync(path.join(__dirname, 'access.log'), JSON.stringify(obj) + '\n'); } catch (e) { /* ignore */ }
}

// ----------------------
// Rate limiter: 50 req/min per IP
// ----------------------
const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim(),
  handler: (req, res) => {
    res.status(429).json({ error: 'rate_limit_exceeded', message: 'Too many requests — limit is 50 per minute per IP' });
  }
});

// ----------------------
// Provider helpers
// ----------------------
function buildCandidateProviders() {
  const list = [];
  try {
    if (!G4FProviders && g4fClient && g4fClient.providers) G4FProviders = g4fClient.providers;
    if (G4FProviders && typeof G4FProviders === 'object') {
      for (const [k, v] of Object.entries(G4FProviders)) {
        list.push({ name: k, provider: v });
      }
    }
    // Also try to require top-level module providers if nothing found
    if (list.length === 0) {
      try {
        const mod = require('g4f');
        const maybe = mod.providers || mod.Provider || {};
        if (maybe && typeof maybe === 'object') {
          for (const [k, v] of Object.entries(maybe)) list.push({ name: k, provider: v });
        }
      } catch (e) { /* ignore */ }
    }
  } catch (e) {
    // ignore build errors
  }
  return list;
}

function modelForProvider(name, desiredModel) {
  if (!name) return desiredModel;
  const n = String(name).toLowerCase();
  if (n.includes('gpt')) return desiredModel;
  if (n.includes('chatbase')) return 'gpt-3.5';
  if (n.includes('bing')) return desiredModel;
  if (n.includes('openai')) return desiredModel;
  if (n.includes('openassistant')) return 'oasst';
  if (n.includes('forefront')) return desiredModel;
  return desiredModel;
}

// ----------------------
// callAI - provider fallback, no unsupported retry option
// ----------------------
async function callAI(messages, options = {}) {
  // TEMP MOCK: Uncomment this during debugging (DO NOT leave in production)
  // return Promise.resolve('MOCK: g4f disabled — enable provider for live replies');

  if (!g4fClient) throw new Error('g4f client not initialized. Install the "g4f" package.');

  const desiredModel = options.model || process.env.DEFAULT_MODEL || 'gpt-4';
  const baseOpts = { model: desiredModel, debug: true, stream: !!options.stream };
  const tried = [];

  // 1) try direct chatCompletion if callable
  if (typeof g4fClient.chatCompletion === 'function') {
    try {
      const res = await g4fClient.chatCompletion(messages, baseOpts);
      return (typeof res === 'object' && res?.text) ? String(res.text) : String(res);
    } catch (err) {
      tried.push({ provider: 'default', ok: false, error: err && err.message ? err.message : String(err) });
    }
  }

  // 2) try candidate providers
  const candidates = buildCandidateProviders();
  for (const cand of candidates) {
    const provName = cand.name || 'unknown';
    const provObj = cand.provider;
    const modelToUse = modelForProvider(provName, desiredModel);
    try {
      const res = await g4fClient.chatCompletion(messages, { ...baseOpts, provider: provObj, model: modelToUse });
      const text = (typeof res === 'object' && res?.text) ? String(res.text) : String(res);
      return text;
    } catch (err) {
      const message = err && err.message ? err.message : String(err);
      tried.push({ provider: provName, ok: false, error: message });
      console.warn(`[g4f] provider ${provName} failed: ${message}`);
      if (err && err.stack) console.warn(err.stack);
    }
  }

  // 3) if still nothing, try module-level fallback (best-effort)
  try {
    const mod = require('g4f');
    if (mod && typeof mod.chatCompletion === 'function') {
      try {
        const r = await mod.chatCompletion(messages, baseOpts);
        return (typeof r === 'object' && r?.text) ? String(r.text) : String(r);
      } catch (err) {
        tried.push({ provider: 'module-fallback', ok: false, error: err && err.message ? err.message : String(err) });
      }
    }
  } catch (e) { /* ignore */ }

  // All attempts failed: throw aggregated error
  const agg = tried.length ? tried : [{ provider: 'unknown', ok: false, error: 'no providers discovered' }];
  const err = new Error('All g4f providers failed. See details property.');
  err.details = agg;
  throw err;
}

// ----------------------
// Middleware: access log
// ----------------------
app.use((req, res, next) => {
  const entry = { ts: nowISO(), method: req.method, path: req.path, ip: req.ip };
  appendAccessLog(entry);
  next();
});

// ----------------------
// Routes
// ----------------------

// Root friendly
app.get('/', (req, res) => {
  res.json({
    message: 'Shaikh Juned Advanced Chat API (g4f)',
    endpoints: {
      chat: '/api/chat (POST)',
      health: '/healthz (GET)',
      admin_login: '/admin/login (POST)',
      admin_test_providers: '/admin/test-providers (POST, requires admin JWT)'
    }
  });
});

// If someone opens /api/chat in a browser (GET), return helpful JSON instead of "Cannot GET"
app.get('/api/chat', (req, res) => {
  res.status(405).json({ error: 'method_not_allowed', message: 'Use POST /api/chat with JSON body: { "message": "..." }' });
});

// Chat endpoint - POST only, rate limited
app.post('/api/chat', chatLimiter, async (req, res) => {
  try {
    const ip = (req.headers['x-forwarded-for'] || req.ip || 'unknown').split(',')[0].trim();
    const { sessionId, message, systemPrompt, stream } = req.body || {};

    if (!message || typeof message !== 'string' || !message.trim()) {
      return res.status(400).json({ error: 'invalid_request', message: 'Provide JSON { "message": "..." }' });
    }

    const sid = sessionId && typeof sessionId === 'string' ? sessionId : newSessionId();
    if (!SESSIONS[sid]) {
      SESSIONS[sid] = [];
      if (systemPrompt && typeof systemPrompt === 'string') {
        SESSIONS[sid].push({ role: 'system', content: systemPrompt, timestamp: nowISO() });
      }
    }

    SESSIONS[sid].push({ role: 'user', content: message, timestamp: nowISO() });
    LOGS.push({ ts: nowISO(), sessionId: sid, ip, message });

    const messagesForAI = SESSIONS[sid].map(m => ({ role: m.role, content: m.content }));
    let aiReply;
    try {
      aiReply = await callAI(messagesForAI, { model: process.env.DEFAULT_MODEL || 'gpt-4', stream: !!stream });
    } catch (aiErr) {
      console.error('AI call failed:', aiErr && aiErr.message ? aiErr.message : aiErr);
      if (aiErr && aiErr.details) console.error('AI details:', JSON.stringify(aiErr.details, null, 2));
      return res.status(502).json({ error: 'AI provider error', details: aiErr.details || aiErr.message || String(aiErr) });
    }

    SESSIONS[sid].push({ role: 'assistant', content: aiReply, timestamp: nowISO() });
    LOGS.push({ ts: nowISO(), sessionId: sid, ip, message: '[assistant reply]' });

    return res.json({ sessionId: sid, reply: aiReply });
  } catch (err) {
    console.error('Unexpected /api/chat error:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// ----------------------
// Admin auth & endpoints
// ----------------------
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password';
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_production';

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '8h' });
    return res.json({ token });
  }
  return res.status(401).json({ error: 'invalid_credentials' });
});

function verifyAdminToken(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const parts = auth.split(/\s+/);
  const token = parts.length === 2 && parts[0].toLowerCase() === 'bearer' ? parts[1] : parts[0] || '';
  if (!token) return res.status(401).json({ error: 'token_required' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'invalid_or_expired_token' });
    req.admin = decoded;
    next();
  });
}

// Admin: list sessions metadata
app.get('/admin/sessions', verifyAdminToken, (req, res) => {
  const sessionsMeta = Object.entries(SESSIONS).map(([sid, msgs]) => ({
    sessionId: sid,
    messages: msgs.length,
    startedAt: msgs.length > 0 ? msgs[0].timestamp : null,
    lastAt: msgs.length > 0 ? msgs[msgs.length - 1].timestamp : null
  }));
  res.json({ count: sessionsMeta.length, sessions: sessionsMeta });
});

// Admin: inspect a single session
app.get('/admin/session/:id', verifyAdminToken, (req, res) => {
  const sid = req.params.id;
  const session = SESSIONS[sid];
  if (!session) return res.status(404).json({ error: 'session_not_found' });
  res.json({ sessionId: sid, messages: session });
});

// Admin: logs
app.get('/admin/logs', verifyAdminToken, (req, res) => {
  const limit = Math.min(1000, Math.abs(parseInt(req.query.limit || '100')));
  const since = req.query.since ? new Date(req.query.since) : null;
  let items = LOGS.slice().reverse();
  if (since && !isNaN(since.getTime())) items = items.filter(l => new Date(l.ts) >= since);
  res.json({ count: items.length, logs: items.slice(0, limit) });
});

// Admin: clear sessions
app.post('/admin/clear-sessions', verifyAdminToken, (req, res) => {
  const keep = Number(req.body.keep || 0);
  if (keep <= 0) {
    for (const k of Object.keys(SESSIONS)) delete SESSIONS[k];
    return res.json({ cleared: true, remaining: 0 });
  }
  const ordered = Object.entries(SESSIONS)
    .map(([sid, msgs]) => ({ sid, last: msgs.length ? msgs[msgs.length - 1].timestamp : null }))
    .sort((a, b) => (b.last || '').localeCompare(a.last || ''));
  const toKeep = new Set(ordered.slice(0, keep).map(x => x.sid));
  for (const k of Object.keys(SESSIONS)) {
    if (!toKeep.has(k)) delete SESSIONS[k];
  }
  return res.json({ cleared: true, remaining: Object.keys(SESSIONS).length });
});

// Admin: test providers (debugging endpoint)
app.post('/admin/test-providers', verifyAdminToken, async (req, res) => {
  const testMessage = (req.body && req.body.message) ? req.body.message : 'Provider test';
  try {
    const reply = await callAI([{ role: 'user', content: testMessage }], { model: process.env.DEFAULT_MODEL || 'gpt-4' });
    return res.json({ ok: true, reply });
  } catch (err) {
    console.error('Provider test failed:', err && (err.details || err.message) ? (err.details || err.message) : err);
    return res.status(502).json({ ok: false, error: 'all_providers_failed', details: err.details || err.message || String(err) });
  }
});

// ----------------------
// 405/404 handlers & health
// ----------------------
app.use((req, res, next) => {
  // If route allowed but method not allowed, return 405 (handled above for /api/chat explicitly)
  // Default to 404 JSON
  res.status(404).json({ error: 'not_found', path: req.path });
});

app.get('/healthz', (req, res) => res.json({ status: 'ok', ts: nowISO() }));

// ----------------------
// Start server
// ----------------------
app.listen(PORT, () => {
  console.log(`SHAIKH_JUNED_API listening on port ${PORT}`);
});
