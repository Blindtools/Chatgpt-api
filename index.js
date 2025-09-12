// index.js - Advanced public Chat API using GPT4Free (g4f)
// Created for: Shaikh Juned
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');

let g4f;
try {
  g4f = require('g4f');
} catch (e) {
  console.warn('g4f not installed. AI calls will fail until g4f is installed as a dependency.');
}

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ---------------------------
// Rate limiter: 50 requests per IP per minute
// ---------------------------
const chatLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 50, // limit each IP to 50 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res) => {
    res.status(429).json({ error: 'rate_limit_exceeded', message: 'Too many requests — limit is 50 per minute per IP' });
  },
  keyGenerator: (req /*, res*/) => {
    // use forwarded IP if present (Render/Proxies)
    return (req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress || '').split(',')[0].trim();
  }
});

// In-memory stores (replace with DB/Redis for production)
const SESSIONS = {};     // sessionId -> [{ role, content, timestamp }]
const LOGS = [];         // array of { timestamp, sessionId, message, ip }

// Utilities
function newSessionId() {
  return crypto.randomUUID();
}
function nowISO() {
  return new Date().toISOString();
}

// ---------------------------
// AI call wrapper
// ---------------------------
async function callAI(messages, options = {}) {
  // For debugging without g4f, you can temporarily enable this mock line:
  // return Promise.resolve("Mock reply: GPT4Free unavailable. This confirms API flow works.");

  if (!g4f) throw new Error('g4f library not available. Install dependency "g4f".');

  try {
    const provider = (g4f && g4f.providers && g4f.providers.GPT) ? g4f.providers.GPT : undefined;
    const model = options.model || 'gpt-4';
    const response = await g4f.chatCompletion(messages, { provider, model });
    return String(response);
  } catch (err) {
    const e = new Error('g4f chatCompletion error: ' + (err && err.message ? err.message : String(err)));
    e.inner = err;
    throw e;
  }
}

// Middleware: simple request logger (write to access.log)
app.use((req, res, next) => {
  const entry = { ts: nowISO(), method: req.method, path: req.path, ip: req.ip };
  const logLine = JSON.stringify(entry) + '\n';
  try {
    fs.appendFileSync(path.join(__dirname, 'access.log'), logLine);
  } catch (e) {
    // ignore file write errors
  }
  next();
});

// Root route so browsers don't show "could not get /"
app.get('/', (req, res) => {
  res.json({
    message: "Shaikh Juned Advanced AI API is running!",
    endpoints: {
      chat: "/api/chat (POST)",
      health: "/healthz (GET)",
      admin_login: "/admin/login (POST)"
    }
  });
});

// Public chat endpoint (no auth) - apply rate limiter to this route only
app.post('/api/chat', chatLimiter, async (req, res) => {
  try {
    const ip = (req.headers['x-forwarded-for'] || req.ip || 'unknown').split(',')[0].trim();
    const { sessionId, message, systemPrompt } = req.body || {};

    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'message is required and must be a non-empty string' });
    }

    // create or reuse session
    const sid = sessionId && typeof sessionId === 'string' ? sessionId : newSessionId();
    if (!SESSIONS[sid]) {
      SESSIONS[sid] = [];
      if (systemPrompt && typeof systemPrompt === 'string' && systemPrompt.trim().length) {
        SESSIONS[sid].push({ role: 'system', content: systemPrompt, timestamp: nowISO() });
      }
    }

    // Append user message
    const userMsg = { role: 'user', content: message, timestamp: nowISO() };
    SESSIONS[sid].push(userMsg);

    // Log the incoming request
    LOGS.push({ timestamp: nowISO(), sessionId: sid, message: message, ip });

    // Build messages array for AI
    const messagesForAI = SESSIONS[sid].map(m => ({ role: m.role, content: m.content }));

    // Call AI provider
    let aiReply;
    try {
      aiReply = await callAI(messagesForAI, { model: process.env.DEFAULT_MODEL || 'gpt-4' });
    } catch (aiErr) {
      console.error('AI call failed:', aiErr && aiErr.message ? aiErr.message : aiErr);
      if (aiErr && aiErr.inner) console.error('AI inner error stack:', aiErr.inner.stack || aiErr.inner);
      return res.status(502).json({ error: 'AI provider error', details: String(aiErr && aiErr.message ? aiErr.message : aiErr) });
    }

    // Store assistant reply
    const assistantMsg = { role: 'assistant', content: aiReply, timestamp: nowISO() };
    SESSIONS[sid].push(assistantMsg);
    LOGS.push({ timestamp: nowISO(), sessionId: sid, message: '[assistant reply]', ip });

    // Return reply and sessionId
    return res.json({ sessionId: sid, reply: aiReply });
  } catch (err) {
    console.error('Unexpected error in /api/chat:', err);
    return res.status(500).json({ error: 'internal_server_error' });
  }
});

// Admin auth and routes
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password';
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_production';

// Admin login - returns JWT token
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '8h' });
    return res.json({ token });
  }
  return res.status(401).json({ error: 'invalid_credentials' });
});

// Admin token verification middleware
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

// Admin endpoints (protected)
app.get('/admin/sessions', verifyAdminToken, (req, res) => {
  const sessionsMeta = Object.entries(SESSIONS).map(([sid, msgs]) => ({
    sessionId: sid,
    messages: msgs.length,
    startedAt: msgs.length > 0 ? msgs[0].timestamp : null,
    lastAt: msgs.length > 0 ? msgs[msgs.length - 1].timestamp : null
  }));
  res.json({ count: sessionsMeta.length, sessions: sessionsMeta });
});

app.get('/admin/session/:id', verifyAdminToken, (req, res) => {
  const sid = req.params.id;
  const session = SESSIONS[sid];
  if (!session) return res.status(404).json({ error: 'session_not_found' });
  res.json({ sessionId: sid, messages: session });
});

app.get('/admin/logs', verifyAdminToken, (req, res) => {
  const limit = Math.min(1000, Math.abs(parseInt(req.query.limit || '100')));
  const since = req.query.since ? new Date(req.query.since) : null;
  let items = LOGS.slice().reverse();
  if (since && !isNaN(since.getTime())) {
    items = items.filter(l => new Date(l.timestamp) >= since);
  }
  res.json({ count: items.length, logs: items.slice(0, limit) });
});

app.post('/admin/clear-sessions', verifyAdminToken, (req, res) => {
  const keep = req.body.keep || 0;
  if (keep <= 0) {
    for (const k of Object.keys(SESSIONS)) delete SESSIONS[k];
    return res.json({ cleared: true, remaining: 0 });
  }
  const ordered = Object.entries(SESSIONS)
    .map(([sid, msgs]) => ({ sid, last: msgs.length ? msgs[msgs.length - 1].timestamp : null }))
    .sort((a,b) => (b.last || '').localeCompare(a.last || ''));
  const toKeep = new Set(ordered.slice(0, keep).map(x => x.sid));
  for (const k of Object.keys(SESSIONS)) {
    if (!toKeep.has(k)) delete SESSIONS[k];
  }
  return res.json({ cleared: true, remaining: Object.keys(SESSIONS).length });
});

// Health check
app.get('/healthz', (req, res) => res.json({ status: 'ok', ts: nowISO() }));

// Start server
app.listen(PORT, () => {
  console.log(`SHAIKH_JUNED_API listening on port ${PORT}`);
});
