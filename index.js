// index.js - Robust production-ready Chat API using GPT4Free (g4f)
// For: Shaikh Juned
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
app.use(express.json());

// ---------------------------
// Robust g4f initialization
// - Support multiple export shapes users encounter in different g4f versions.
// Docs/examples use: const { G4F } = require("g4f"); const g4f = new G4F(); OR client = new G4F(); g4f.chatCompletion(...).
// See g4f docs for chatCompletion usage. :contentReference[oaicite:2]{index=2}
let g4fClient = null;
try {
  const g4fModule = require('g4f');
  // Try common export shapes:
  if (typeof g4fModule === 'function') {
    // module directly exported as constructor / function
    g4fClient = new g4fModule();
  } else if (g4fModule && typeof g4fModule.G4F === 'function') {
    g4fClient = new g4fModule.G4F();
  } else if (g4fModule && typeof g4fModule.default === 'function') {
    g4fClient = new g4fModule.default();
  } else if (g4fModule && typeof g4fModule.G4F === 'object' && typeof g4fModule.G4F === 'object') {
    // weird shapes - attempt to use named export class if present
    try { g4fClient = new g4fModule.G4F(); } catch (e) { /* ignore */ }
  } else if (g4fModule && typeof g4fModule.chatCompletion === 'function') {
    // module itself is a helper object exposing chatCompletion
    g4fClient = g4fModule;
  } else {
    console.warn('g4f loaded but shape unrecognized. You may need to update initialization.');
  }
} catch (e) {
  console.warn('g4f not installed or failed to require(); AI calls will fail until g4f is installed.');
  g4fClient = null;
}

// ---------------------------
// Rate limiter: 50 requests per IP per minute
// ---------------------------
const chatLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({ error: 'rate_limit_exceeded', message: 'Too many requests — limit is 50 per minute per IP' });
  },
  keyGenerator: (req) => {
    return (req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress || '').split(',')[0].trim();
  }
});

// In-memory stores (swap with DB/Redis for real production persistence)
const SESSIONS = {};
const LOGS = [];

// Utilities
function newSessionId() { return crypto.randomUUID(); }
function nowISO() { return new Date().toISOString(); }

// ---------------------------
// callAI: unified wrapper that works with common g4f shapes
// - Attempts g4fClient.chatCompletion(messages, options)
// - If the g4fClient is not installed or fails, throws a helpful error
// - You can temporarily enable the mock return (uncomment) for testing UI without provider.
// ---------------------------
async function callAI(messages, options = {}) {
  // TEMP MOCK (uncomment for debugging front-end flow without g4f):
  // return Promise.resolve("Mock reply (g4f disabled) — uncomment in code only for debugging.");

  if (!g4fClient) throw new Error('g4f client not initialized. Install and configure the "g4f" package.');

  // Some versions expect an instance with chatCompletion, others export a function directly.
  const model = options.model || process.env.DEFAULT_MODEL || 'gpt-4';
  try {
    if (typeof g4fClient.chatCompletion === 'function') {
      // typical JS client usage: client.chatCompletion(messages, opts)
      return String(await g4fClient.chatCompletion(messages, { model }));
    }
    // some shapes export a single function
    if (typeof g4fClient === 'function') {
      return String(await g4fClient.chatCompletion(messages, { model }));
    }
    // last resort: if module has a 'chat' or 'ChatCompletion' namespace
    if (g4fClient.chat && typeof g4fClient.chat === 'object' && typeof g4fClient.chat.completions === 'function') {
      const r = await g4fClient.chat.completions(messages, { model });
      return String(r);
    }

    throw new Error('g4f client loaded but chatCompletion API not found on exported object.');
  } catch (err) {
    const e = new Error('g4f chat error: ' + (err && err.message ? err.message : String(err)));
    e.inner = err;
    throw e;
  }
}

// Middleware: simple request logger (append to access.log)
app.use((req, res, next) => {
  const entry = { ts: nowISO(), method: req.method, path: req.path, ip: req.ip };
  try { fs.appendFileSync(path.join(__dirname, 'access.log'), JSON.stringify(entry) + '\n'); } catch (e) {}
  next();
});

// Friendly root so browsers don't display "Cannot GET /"
app.get('/', (req, res) => {
  res.json({
    message: "Shaikh Juned Advanced AI API is running!",
    endpoints: { chat: "/api/chat (POST)", health: "/healthz (GET)", admin_login: "/admin/login (POST)" }
  });
});

// If someone opens /api/chat with GET in browser, give a helpful message instead of "Cannot GET /api/chat"
app.get('/api/chat', (req, res) => {
  res.status(405).json({ error: 'method_not_allowed', message: 'Use POST /api/chat with JSON body: { \"message\": \"...\" }' });
});

// Public chat endpoint (POST) — apply rate limiter
app.post('/api/chat', chatLimiter, async (req, res) => {
  try {
    const ip = (req.headers['x-forwarded-for'] || req.ip || 'unknown').split(',')[0].trim();
    const { sessionId, message, systemPrompt } = req.body || {};

    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'message is required and must be a non-empty string' });
    }

    const sid = sessionId && typeof sessionId === 'string' ? sessionId : newSessionId();
    if (!SESSIONS[sid]) {
      SESSIONS[sid] = [];
      if (systemPrompt) SESSIONS[sid].push({ role: 'system', content: systemPrompt, timestamp: nowISO() });
    }

    SESSIONS[sid].push({ role: 'user', content: message, timestamp: nowISO() });
    LOGS.push({ timestamp: nowISO(), sessionId: sid, message, ip });

    const messagesForAI = SESSIONS[sid].map(m => ({ role: m.role, content: m.content }));

    let aiReply;
    try {
      aiReply = await callAI(messagesForAI, { model: process.env.DEFAULT_MODEL || 'gpt-4' });
    } catch (aiErr) {
      console.error('AI call failed:', aiErr && aiErr.message ? aiErr.message : aiErr);
      if (aiErr && aiErr.inner) console.error('AI inner:', aiErr.inner.stack || aiErr.inner);
      return res.status(502).json({ error: 'AI provider error', details: String(aiErr && aiErr.message ? aiErr.message : aiErr) });
    }

    SESSIONS[sid].push({ role: 'assistant', content: aiReply, timestamp: nowISO() });
    LOGS.push({ timestamp: nowISO(), sessionId: sid, message: '[assistant reply]', ip });

    res.json({ sessionId: sid, reply: aiReply });
  } catch (err) {
    console.error('Unexpected /api/chat error:', err);
    res.status(500).json({ error: 'internal_server_error' });
  }
});

// Admin setup (same as before)
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
  const auth = req.headers['authorization'];
  if (!auth || typeof auth !== 'string') return res.status(401).json({ error: 'authorization header required' });
  const parts = auth.split(/\s+/);
  const token = parts.length === 2 && parts[0].toLowerCase() === 'bearer' ? parts[1] : parts[0];
  if (!token) return res.status(401).json({ error: 'token required' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'invalid_or_expired_token' });
    req.admin = decoded;
    next();
  });
}

app.get('/admin/sessions', verifyAdminToken, (req, res) => {
  const sessionsMeta = Object.entries(SESSIONS).map(([sid, msgs]) => ({
    sessionId: sid,
    messages: msgs.length,
    startedAt: msgs.length > 0 ? msgs[0].timestamp : null,
    lastAt: msgs.length > 0 ? msgs[msgs.length - 1].timestamp : null
  }));
  res.json({ count: sessionsMeta.length, sessions: sessionsMeta });
});

app.get('/admin/logs', verifyAdminToken, (req, res) => {
  const since = req.query.since ? new Date(req.query.since) : null;
  const limit = Math.min(1000, Math.abs(parseInt(req.query.limit || '100')));
  let items = LOGS.slice().reverse();
  if (since && !isNaN(since.getTime())) items = items.filter(l => new Date(l.timestamp) >= since);
  res.json({ count: items.length, logs: items.slice(0, limit) });
});

// 404 JSON for all other requests (prevents "Cannot GET /something" plain text)
app.use((req, res) => {
  res.status(404).json({ error: 'not_found', path: req.path });
});

// Health
app.get('/healthz', (req, res) => res.json({ status: 'ok', ts: nowISO() }));

// Start
app.listen(PORT, () => console.log(`SHAIKH_JUNED_API listening on port ${PORT}`));
