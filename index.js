// index.js - Production-grade Chat API using g4f (GPT4Free)
// 2025 setup: defensive g4f init, provider fallback, retry, streaming option,
// rate limiter (50 req/min per IP), admin endpoints for provider testing.

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

// ---------- defensive g4f initialization ----------
let g4fClient = null;
let G4FProviders = null;
try {
  const g4fModule = require('g4f'); // preferred module
  // common shapes:
  if (g4fModule && typeof g4fModule.G4F === 'function') {
    g4fClient = new g4fModule.G4F();
    G4FProviders = g4fModule.Provider || g4fModule.providers || g4fModule.providers;
  } else if (g4fModule && typeof g4fModule.default === 'function') {
    g4fClient = new g4fModule.default();
    G4FProviders = g4fModule.providers || g4fModule.Provider;
  } else if (typeof g4fModule === 'function') {
    // module itself might be a constructor
    try { g4fClient = new g4fModule(); } catch(e) { g4fClient = g4fModule; }
    G4FProviders = g4fModule.providers || g4fModule.Provider;
  } else if (g4fModule && typeof g4fModule.chatCompletion === 'function') {
    // module exports helper directly
    g4fClient = g4fModule;
    G4FProviders = g4fModule.providers || g4fModule.Provider;
  } else {
    console.warn('g4f installed but export shape was unexpected - please check g4f version');
    g4fClient = g4fModule; // fallback
    G4FProviders = g4fModule && (g4fModule.providers || g4fModule.Provider);
  }
} catch (e) {
  console.warn('g4f not installed or failed to require(); AI calls will fail until "g4f" is installed.');
  g4fClient = null;
}

// ---------- utils ----------
const SESSIONS = {}; // sessionId -> messages
const LOGS = [];     // usage logs

function nowISO(){ return new Date().toISOString(); }
function newSessionId(){ return crypto.randomUUID(); }
function appendAccessLog(obj){
  try { fs.appendFileSync(path.join(__dirname,'access.log'), JSON.stringify(obj)+'\n'); } catch(e){}
}

// ---------- rate limit: 50 req / minute per IP ----------
const chatLimiter = rateLimit({
  windowMs: 60*1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req,res) => res.status(429).json({ error:'rate_limit_exceeded', message: '50 requests per minute per IP' }),
  keyGenerator: (req) => (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim()
});

// ---------- friendly root & health ----------
app.get('/', (req,res) => {
  res.json({ message: 'Shaikh Juned Chat API (g4f)', endpoints: { chat: '/api/chat (POST)', health: '/healthz', admin_test: '/admin/test-providers (POST)' }});
});
app.get('/healthz', (req,res) => res.json({ status:'ok', ts: nowISO() }));

// ---------- helper: build candidate providers list if available ----------
function buildCandidateProviders(){
  const list = [];
  try {
    if (!G4FProviders) {
      // try to read providers off instance
      if (g4fClient && g4fClient.providers) G4FProviders = g4fClient.providers;
    }
    if (G4FProviders) {
      // common names that appear in g4f exports
      ['GPT','Forefront','Bing','ChatBase','OpenAssistant','OpenAI','Ails','Bard'].forEach(name=>{
        if (G4FProviders[name]) list.push({name, provider: G4FProviders[name]});
      });
    }
  } catch(e){}
  return list;
}

// ---------- callAI: tries default then provider fallback with retries ----------
async function callAI(messages, opts = {}){
  // opts: { model: 'gpt-4', stream: false }
  // TEMP MOCK: uncomment for UI testing without providers:
  // return Promise.resolve('MOCK: g4f disabled — enable real provider to get live replies');

  if (!g4fClient) throw new Error('g4f client not initialized. Install "g4f" package.');

  const model = opts.model || process.env.DEFAULT_MODEL || 'gpt-4';
  const baseOpts = { model, stream: !!opts.stream, debug: true, retry: { times: 2 } };

  const tried = [];

  // 1) try direct chatCompletion if available (without provider)
  if (typeof g4fClient.chatCompletion === 'function'){
    try {
      const r = await g4fClient.chatCompletion(messages, baseOpts);
      return (typeof r === 'object' && r?.text) ? String(r.text) : String(r);
    } catch(err){
      tried.push({provider:'default', ok:false, error: err && err.message ? err.message : String(err)});
    }
  }

  // 2) candidate provider loop
  const providers = buildCandidateProviders();
  for (const p of providers){
    try {
      const res = await g4fClient.chatCompletion(messages, { ...baseOpts, provider: p.provider });
      const text = (typeof res === 'object' && res?.text) ? String(res.text) : String(res);
      return text;
    } catch(err){
      const message = err && err.message ? err.message : String(err);
      tried.push({ provider: p.name, ok:false, error: message });
      console.warn(`[g4f] provider ${p.name} failed: ${message}`);
    }
  }

  // 3) if nothing worked, throw aggregated error
  const details = tried.length ? tried : [{ provider:'unknown', ok:false, error:'no providers detected' }];
  const e = new Error('All providers failed: ' + JSON.stringify(details.map(d => `${d.provider}:${d.error}`)));
  e.details = details;
  throw e;
}

// ---------- simple request logger ----------
app.use((req,res,next)=>{
  const entry = { ts: nowISO(), method: req.method, path: req.path, ip: req.ip };
  appendAccessLog(entry);
  next();
});

// ---------- helpful GET for /api/chat (prevent "Cannot GET /api/chat") ----------
app.get('/api/chat', (req,res) => {
  res.status(405).json({ error:'method_not_allowed', message:'Use POST /api/chat with JSON body {\"message\":\"...\"}'});
});

// ---------- chat endpoint ----------
app.post('/api/chat', chatLimiter, async (req,res) => {
  const ip = (req.headers['x-forwarded-for'] || req.ip || 'unknown').split(',')[0].trim();
  const { sessionId, message, systemPrompt, stream } = req.body || {};
  if (!message || typeof message !== 'string') return res.status(400).json({ error:'invalid_request', message:'Provide JSON body: {\"message\":\"...\"}'});

  const sid = sessionId && typeof sessionId === 'string' ? sessionId : newSessionId();
  if (!SESSIONS[sid]) {
    SESSIONS[sid] = [];
    if (systemPrompt && typeof systemPrompt === 'string') SESSIONS[sid].push({ role:'system', content: systemPrompt, timestamp: nowISO() });
  }
  SESSIONS[sid].push({ role:'user', content: message, timestamp: nowISO() });
  LOGS.push({ ts: nowISO(), sessionId: sid, ip, message });

  try {
    const messagesForAI = SESSIONS[sid].map(m => ({ role: m.role, content: m.content }));
    const aiReply = await callAI(messagesForAI, { model: process.env.DEFAULT_MODEL || 'gpt-4', stream: !!stream });
    SESSIONS[sid].push({ role:'assistant', content: aiReply, timestamp: nowISO() });
    LOGS.push({ ts: nowISO(), sessionId: sid, ip, message: '[assistant reply]' });
    return res.json({ sessionId: sid, reply: aiReply });
  } catch(err){
    console.error('AI call failed:', err && (err.details || err.message) ? (err.details || err.message) : err);
    return res.status(502).json({ error:'AI provider error', details: err.details || err.message || String(err) });
  }
});

// ---------- admin: basic JWT auth ----------
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password';
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

app.post('/admin/login', (req,res)=>{
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error:'username_password_required' });
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = jwt.sign({ user: username }, JWT_SECRET, { expiresIn: '8h' });
    return res.json({ token });
  }
  return res.status(401).json({ error:'invalid_credentials' });
});

function verifyAdminToken(req,res,next){
  const auth = req.headers.authorization || '';
  const token = auth.split(' ')[1] || auth;
  if (!token) return res.status(401).json({ error:'token_required' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error:'invalid_token' });
    req.admin = decoded;
    next();
  });
}

// ---------- admin provider test endpoint ----------
app.post('/admin/test-providers', verifyAdminToken, async (req,res) => {
  const msg = (req.body && req.body.message) ? req.body.message : 'Provider test';
  try {
    const reply = await callAI([{ role:'user', content: msg }], { model: process.env.DEFAULT_MODEL || 'gpt-4' });
    return res.json({ ok:true, reply });
  } catch(err) {
    return res.status(502).json({ ok:false, error:'all_providers_failed', details: err.details || err.message || String(err) });
  }
});

// ---------- 404 JSON handler ----------
app.use((req,res) => res.status(404).json({ error:'not_found', path: req.path }));

// ---------- start server ----------
app.listen(PORT, () => console.log(`SHAIKH_JUNED_API listening on port ${PORT}`));
