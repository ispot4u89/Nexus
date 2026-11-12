
'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const WebSocket = require('ws');

const app = express();
const PORT = Number(process.env.PORT || process.env.SERVER_PORT || 8080);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'nexus-data.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

function initialData() {
  return {
    users: [],
    configs: [],
    settings: {
      panelName: 'NEXUS',
      wsPath: '/ws',
      host: process.env.PROXY_HOST || '',
      address: process.env.PROXY_ADDRESS || process.env.PROXY_HOST || '',
      port: Number(process.env.PROXY_PORT || 443),
      tls: true
    },
    usage: {
      note: 'WebSocket VLESS traffic is counted by this Node.js backend.',
      totalBytes: 0
    },
    security: null
  };
}

function writeData(data) {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE);
  try {
    fs.chmodSync(DB_FILE, 0o600);
  } catch {}
}

function readData() {
  try {
    const d = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    const base = initialData();
    const out = {
      ...base,
      ...d,
      users: Array.isArray(d.users) ? d.users : [],
      configs: Array.isArray(d.configs) ? d.configs : [],
      settings: { ...base.settings, ...(d.settings || {}) },
      usage: { ...base.usage, ...(d.usage || {}) }
    };

    if (out.security) {
      if (!Array.isArray(out.security.admins) || !out.security.admins.length) {
        out.security.admins = [{
          id: 'super-admin-legacy',
          username: 'admin',
          role: 'superadmin',
          passwordSalt: out.security.passwordSalt,
          passwordHash: out.security.passwordHash,
          createdAt: out.security.createdAt || new Date().toISOString()
        }];
      }

      const ownerId =
        out.security.admins.find(a => a.role === 'superadmin')?.id ||
        out.security.admins[0].id;

      let changed = false;

      out.users = out.users.map(u => {
        if (u.ownerId) return u;
        changed = true;
        return { ...u, ownerId };
      });

      out.configs = out.configs.map(c => {
        if (c.ownerId) return c;
        changed = true;
        return { ...c, ownerId };
      });

      if (changed) writeData(out);
    }

    return out;
  } catch {
    return initialData();
  }
}

if (!fs.existsSync(DB_FILE)) writeData(initialData());

app.disable('x-powered-by');
app.set('trust proxy', true);
app.use(express.json({ limit: '10mb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

const sessions = new Map();

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function cookieValue(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) {
      try {
        return decodeURIComponent(part.slice(i + 1).trim());
      } catch {
        return '';
      }
    }
  }
  return '';
}

function makeSecretPath() {
  return '/' + crypto.randomBytes(24).toString('base64url');
}

function getSecurity() {
  return readData().security;
}

function isSecureRequest(req) {
  return req.secure || req.headers['x-forwarded-proto'] === 'https';
}

function setSessionCookie(req, res, token, clear = false) {
  const security = getSecurity();
  const cookiePath = security?.adminPath ? security.adminPath + '/' : '/';
  const parts = [
    `nexus_session=${clear ? '' : token}`,
    'HttpOnly',
    'SameSite=Strict',
    `Path=${cookiePath}`
  ];

  if (clear) parts.push('Max-Age=0');
  if (isSecureRequest(req)) parts.push('Secure');

  res.setHeader('Set-Cookie', parts.join('; '));
}

function auth(req, res, next) {
  const token = cookieValue(req, 'nexus_session');
  const session = token && sessions.get(token);

  if (session) {
    const d = readData();
    const admin = d.security?.admins?.find(a => a.id === session.adminId);

    if (admin) {
      req.admin = {
        id: admin.id,
        username: admin.username,
        role: admin.role
      };
      return next();
    }

    sessions.delete(token);
  }

  return res.status(401).json({ error: 'Authentication required' });
}

function requireSuperAdmin(req, res, next) {
  if (req.admin?.role !== 'superadmin') {
    return res.status(403).json({ error: 'Super administrator permission required.' });
  }
  next();
}

function getPanelHostname(req) {
  const raw = String(req.hostname || req.get('host') || '')
    .trim()
    .toLowerCase();

  const hostname = raw
    .replace(/:\d+$/, '')
    .replace(/[^a-z0-9.-]/g, '');

  return hostname && hostname.length <= 253 ? hostname : '';
}

function makeLink(user, settings, panelHostname = '') {
  const domain = panelHostname || settings.host || '';
  const query = new URLSearchParams();

  query.set('encryption', 'none');
  query.set('security', settings.tls ? 'tls' : 'none');

  if (settings.tls) {
    query.set('sni', domain);
    query.set('insecure', '0');
    query.set('allowInsecure', '0');
  }

  query.set('type', 'ws');
  query.set('host', domain);
  query.set('path', settings.wsPath || '/ws');

  return `vless://${user.uuid}@${domain}:${settings.port}?${query.toString()}#${encodeURIComponent('NEXUS-' + user.name + '-WS')}`;
}

const setupHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NEXUS Setup</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:#080b14;color:#eef2ff;font:15px/1.6 system-ui}.card{width:min(480px,100%);padding:28px;background:#101626;border:1px solid #27334a;border-radius:18px}input,button{width:100%;padding:12px;margin-top:9px;border-radius:9px;border:1px solid #2a354c;background:#080e1b;color:#eef2ff}button{background:#8b5cf6;color:white;font-weight:bold;cursor:pointer}.muted{color:#8b98b7}.error{color:#fda4af}.result{overflow-wrap:anywhere}
</style>
</head>
<body>
<main class="card">
<h1>NEXUS</h1>
<p class="muted">First-run administrator setup</p>
<form id="form">
<label>Administrator username</label>
<input id="username" value="admin" minlength="3" maxlength="32" required>
<label>Administrator password</label>
<input id="password" type="password" minlength="12" autocomplete="new-password" required>
<label>Confirm password</label>
<input id="confirm" type="password" minlength="12" autocomplete="new-password" required>
<button>Initialize NEXUS</button>
</form>
<p id="message" class="error"></p>
<p id="result" class="result"></p>
</main>
<script>
const $=id=>document.getElementById(id);
fetch('/__nexus_setup/status',{cache:'no-store'}).then(r=>r.json()).then(d=>{
 if(d.initialized){$('form').hidden=true;$('message').textContent='Setup is already complete. Use your saved private URL.'}
}).catch(()=>{});
$('form').addEventListener('submit',async e=>{
 e.preventDefault();$('message').textContent='';
 const username=$('username').value.trim();
 const password=$('password').value;
 if(password!==$('confirm').value){$('message').textContent='Passwords do not match.';return}
 try{
  const r=await fetch('/__nexus_setup/initialize',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
  const d=await r.json();if(!r.ok)throw Error(d.error||'Setup failed');
  $('form').hidden=true;$('message').textContent='Setup complete. Save this private URL:';
  $('result').textContent=d.url;
  const a=document.createElement('a');a.href=d.url;a.textContent='Open NEXUS';a.style.color='#22d3ee';$('result').appendChild(document.createElement('br'));$('result').appendChild(a);
 }catch(err){$('message').textContent=err.message}
});
</script>
</body>
</html>`;

app.get('/__nexus_setup/status', (req, res) => {
  res.json({ initialized: !!getSecurity() });
});

app.post('/__nexus_setup/initialize', (req, res) => {
  const d = readData();

  if (d.security) {
    return res.status(409).json({ error: 'NEXUS has already been initialized.' });
  }

  const username = String(req.body.username || 'admin').trim();
  const password = String(req.body.password || '');

  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
    return res.status(400).json({ error: 'Username must be 3-32 characters and use letters, numbers, dot, underscore or hyphen.' });
  }

  if (password.length < 12 || password.length > 256) {
    return res.status(400).json({ error: 'Password must be 12-256 characters.' });
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const adminPath = makeSecretPath();
  const firstAdmin = {
    id: crypto.randomUUID(),
    username,
    role: 'superadmin',
    passwordSalt: salt,
    passwordHash: hashPassword(password, salt),
    createdAt: new Date().toISOString()
  };

  d.security = {
    passwordSalt: salt,
    passwordHash: hashPassword(password, salt),
    adminPath,
    admins: [firstAdmin],
    createdAt: new Date().toISOString()
  };

  d.users = d.users.map(u => ({ ...u, ownerId: u.ownerId || firstAdmin.id }));
  d.configs = d.configs.map(c => ({ ...c, ownerId: c.ownerId || firstAdmin.id }));
  writeData(d);

  const proto = isSecureRequest(req) ? 'https' : 'http';
  res.status(201).json({
    ok: true,
    url: `${proto}://${req.get('host')}${adminPath}/`
  });
});

app.get('/', (req, res) => {
  if (getSecurity()) return res.status(404).type('text').send('Not found');
  res.type('html').send(setupHtml);
});

app.get('/index.html', (req, res) => {
  if (getSecurity()) return res.status(404).type('text').send('Not found');
  res.type('html').send(setupHtml);
});

const panel = express.Router();
panel.use(express.json({ limit: '10mb' }));

panel.post('/api/login', (req, res) => {
  const d = readData();
  const security = d.security;

  if (!security) {
    return res.status(503).json({ error: 'First-run setup is required at the main subdomain.' });
  }

  const username = String(req.body.username || '').trim().toLowerCase();
  const supplied = String(req.body.password || '');
  const admin = (security.admins || []).find(a => String(a.username).toLowerCase() === username);

  if (!admin || !safeEqual(hashPassword(supplied, admin.passwordSalt), admin.passwordHash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { adminId: admin.id, createdAt: Date.now() });
  setSessionCookie(req, res, token);

  res.json({
    ok: true,
    admin: { id: admin.id, username: admin.username, role: admin.role }
  });
});

panel.post('/api/logout', auth, (req, res) => {
  sessions.delete(cookieValue(req, 'nexus_session'));
  setSessionCookie(req, res, '', true);
  res.json({ ok: true });
});

panel.get('/api/state', auth, (req, res) => {
  const d = readData();
  const panelHost = getPanelHostname(req);
  const effectiveSettings = { ...d.settings, host: panelHost, address: panelHost };
  const adminNames = new Map((d.security?.admins || []).map(a => [a.id, a.username]));

  const visibleUsers = req.admin.role === 'superadmin'
    ? d.users
    : d.users.filter(u => u.ownerId === req.admin.id);

  const users = visibleUsers.map(u => ({
    ...u,
    ownerAdminId: u.ownerId || '',
    ownerAdminUsername: adminNames.get(u.ownerId) || 'Unknown admin',
    wsLink: makeLink(u, effectiveSettings, panelHost)
  }));

  res.json({
    panelName: 'NEXUS',
    users,
    currentAdmin: req.admin,
    admins: req.admin.role === 'superadmin'
      ? (d.security.admins || []).map(a => ({
          id: a.id,
          username: a.username,
          role: a.role,
          createdAt: a.createdAt
        }))
      : [],
    settings: effectiveSettings,
    usage: d.usage,
    backend: {
      connected: true,
      label: 'NEXUS WS backend enabled',
      message: 'WebSocket backend is enabled. External reachability depends on hosting WebSocket support.'
    }
  });
});

panel.post('/api/users', auth, (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  const quotaGB = Number(req.body.quotaGB);
  const days = Number(req.body.days);
  const customUuid = String(req.body.uuid || '').trim();

  if (!name) return res.status(400).json({ error: 'Enter a user name.' });
  if (!Number.isFinite(quotaGB) || quotaGB < 0.1 || quotaGB > 100000) {
    return res.status(400).json({ error: 'Quota must be between 0.1 and 100000 GB.' });
  }
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    return res.status(400).json({ error: 'Validity must be 1–3650 days.' });
  }
  if (customUuid && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(customUuid)) {
    return res.status(400).json({ error: 'UUID must be a valid canonical UUID.' });
  }

  const d = readData();
  const requestedOwnerId = req.admin.role === 'superadmin' && req.body.ownerAdminId
    ? String(req.body.ownerAdminId)
    : req.admin.id;

  const validOwner = (d.security?.admins || []).some(a => a.id === requestedOwnerId);
  if (!validOwner) return res.status(400).json({ error: 'Invalid user owner administrator.' });
  if (customUuid && d.users.some(u => String(u.uuid).toLowerCase() === customUuid.toLowerCase())) {
    return res.status(409).json({ error: 'This UUID is already in use.' });
  }

  const now = new Date();
  const user = {
    id: crypto.randomUUID(),
    name,
    uuid: customUuid || crypto.randomUUID(),
    quotaGB,
    usedBytes: 0,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + days * 86400000).toISOString(),
    enabled: true,
    ownerId: requestedOwnerId
  };

  d.users.unshift(user);
  writeData(d);

  const panelHost = getPanelHostname(req);
  res.status(201).json({
    ...user,
    wsLink: makeLink(user, { ...d.settings, host: panelHost, address: panelHost }, panelHost)
  });
});

panel.patch('/api/users/:id', auth, (req, res) => {
  const d = readData();
  const user = d.users.find(u => u.id === req.params.id);

  if (!user || (req.admin.role !== 'superadmin' && user.ownerId !== req.admin.id)) {
    return res.status(404).json({ error: 'User not found.' });
  }

  if (typeof req.body.enabled === 'boolean') user.enabled = req.body.enabled;
  if (req.body.name !== undefined) user.name = String(req.body.name).trim().slice(0, 60) || user.name;

  if (req.body.quotaGB !== undefined) {
    const quota = Number(req.body.quotaGB);
    if (!Number.isFinite(quota) || quota < 0.1 || quota > 100000) {
      return res.status(400).json({ error: 'Invalid quota.' });
    }
    user.quotaGB = quota;
  }

  if (req.body.resetUsage === true) user.usedBytes = 0;

  writeData(d);
  res.json({ ok: true });
});

panel.delete('/api/users/:id', auth, (req, res) => {
  const d = readData();
  const user = d.users.find(u => u.id === req.params.id);

  if (!user || (req.admin.role !== 'superadmin' && user.ownerId !== req.admin.id)) {
    return res.status(404).json({ error: 'User not found.' });
  }

  d.users = d.users.filter(u => u.id !== req.params.id);
  writeData(d);
  res.json({ ok: true });
});

panel.patch('/api/settings', auth, (req, res) => {
  const d = readData();

  if (req.body.port !== undefined) {
    const port = Number(req.body.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return res.status(400).json({ error: 'Invalid port.' });
    }
    d.settings.port = port;
  }

  writeData(d);
  res.json({ ok: true });
});

panel.get('/api/backup', auth, (req, res) => {
  const d = readData();
  let exportData = d;

  if (req.admin.role !== 'superadmin') {
    exportData = {
      ...initialData(),
      users: d.users.filter(u => u.ownerId === req.admin.id),
      configs: d.configs.filter(c => c.ownerId === req.admin.id),
      settings: d.settings,
      usage: { note: 'Personal backup.', totalBytes: 0 },
      security: null
    };
  }

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="nexus-backup-${new Date().toISOString().slice(0, 10)}.json"`
  );

  res.send(JSON.stringify({
    format: 'nexus-backup',
    version: 2,
    exportedAt: new Date().toISOString(),
    data: exportData
  }, null, 2));
});

panel.post('/api/restore', auth, requireSuperAdmin, (req, res) => {
  const body = req.body || {};
  const incoming = body.data && typeof body.data === 'object' ? body.data : body;

  if (!incoming || !Array.isArray(incoming.users) ||
      !incoming.settings || typeof incoming.settings !== 'object') {
    return res.status(400).json({ error: 'Invalid backup file. Expected a NEXUS JSON backup.' });
  }

  if (incoming.users.length > 10000 ||
      incoming.users.some(u => !u || typeof u.uuid !== 'string' || !u.id)) {
    return res.status(400).json({ error: 'Backup user data is invalid or exceeds limits.' });
  }

  const current = readData();
  const admins = current.security?.admins || [];
  const validIds = new Set(admins.map(a => a.id));
  const superAdminId = admins.find(a => a.role === 'superadmin')?.id || req.admin.id;

  const restored = {
    ...initialData(),
    ...incoming,
    settings: { ...initialData().settings, ...incoming.settings },
    users: incoming.users,
    configs: Array.isArray(incoming.configs) ? incoming.configs.slice(0, 2000) : [],
    security: current.security
  };

  restored.users = restored.users.map(u => ({
    ...u,
    ownerId: validIds.has(u.ownerId) ? u.ownerId : superAdminId,
    usedBytes: Math.max(0, Number(u.usedBytes) || 0)
  }));

  restored.configs = restored.configs.map(c => ({
    ...c,
    ownerId: validIds.has(c.ownerId) ? c.ownerId : req.admin.id
  }));

  restored.usage = {
    ...initialData().usage,
    ...(incoming.usage || {}),
    totalBytes: restored.users.reduce((sum, u) => sum + u.usedBytes, 0)
  };

  writeData(restored);
  res.json({
    ok: true,
    users: restored.users.length,
    configs: restored.configs.length,
    note: 'Current administrator credentials were preserved.'
  });
});

panel.post('/api/admins', auth, requireSuperAdmin, (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');

  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
    return res.status(400).json({ error: 'Username must be 3-32 characters and use letters, numbers, dot, underscore or hyphen.' });
  }
  if (password.length < 12 || password.length > 256) {
    return res.status(400).json({ error: 'Password must be 12-256 characters.' });
  }

  const d = readData();
  if ((d.security.admins || []).some(a => a.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: 'That administrator username already exists.' });
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const admin = {
    id: crypto.randomUUID(),
    username,
    role: 'admin',
    passwordSalt: salt,
    passwordHash: hashPassword(password, salt),
    createdAt: new Date().toISOString()
  };

  d.security.admins.push(admin);
  writeData(d);

  res.status(201).json({
    ok: true,
    admin: {
      id: admin.id,
      username: admin.username,
      role: admin.role,
      createdAt: admin.createdAt
    }
  });
});

panel.delete('/api/admins/:id', auth, requireSuperAdmin, (req, res) => {
  const d = readData();
  const target = (d.security.admins || []).find(a => a.id === req.params.id);

  if (!target) return res.status(404).json({ error: 'Administrator not found.' });
  if (target.role === 'superadmin') {
    return res.status(400).json({ error: 'The super administrator cannot be deleted.' });
  }

  const superAdminId = d.security.admins.find(a => a.role === 'superadmin')?.id;
  d.security.admins = d.security.admins.filter(a => a.id !== target.id);

  d.configs = d.configs.filter(c => c.ownerId !== target.id);
  if (superAdminId) {
    d.users = d.users.map(u =>
      u.ownerId === target.id ? { ...u, ownerId: superAdminId } : u
    );
  }

  writeData(d);
  for (const [token, session] of sessions) {
    if (session.adminId === target.id) sessions.delete(token);
  }

  res.json({ ok: true });
});

panel.get('/health', (req, res) => {
  res.json({ ok: true, app: 'NEXUS', mode: 'prototype' });
});

panel.use((req, res, next) => {
  if (req.method !== 'GET') return next();

  fs.readFile(path.join(PUBLIC_DIR, 'index.html'), 'utf8', (err, html) => {
    if (err) return res.status(500).send('Unable to load NEXUS interface.');
    res.type('html').send(html.replaceAll('__NEXUS_BASE__', req.nexusBase || ''));
  });
});

app.use((req, res, next) => {
  const security = getSecurity();

  if (!security) return next();

  const base = security.adminPath;

  if (req.path === base) return res.redirect(308, base + '/');

  if (req.path === base + '/' || req.path.startsWith(base + '/')) {
    req.nexusBase = base;
    req.url = req.url.slice(base.length) || '/';
    return panel(req, res, next);
  }

  if (req.path.startsWith('/__nexus_setup/')) return next();
  return res.status(404).type('text').send('Not found');
});

app.use((req, res) => {
  if (!getSecurity() && (req.path === '/' || req.path === '/index.html')) {
    return res.type('html').send(setupHtml);
  }
  res.status(404).type('text').send('Not found');
});

/* Keep unexpected application errors from being printed by Express. */
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Internal server error.' });
});

/* VLESS over WebSocket. TLS terminates at the hosting provider. */
const server = http.createServer(app);
const wss = new WebSocket.Server({
  noServer: true,
  maxPayload: 2 * 1024 * 1024
});

const pendingUsage = new Map();
let flushBusy = false;

function addUsage(userId, bytes) {
  if (!bytes || bytes < 0) return;
  pendingUsage.set(userId, (pendingUsage.get(userId) || 0) + bytes);
}

function flushUsage() {
  if (flushBusy || pendingUsage.size === 0) return;

  flushBusy = true;
  try {
    const d = readData();

    for (const [id, amount] of pendingUsage.entries()) {
      const user = d.users.find(u => u.id === id);
      if (user) user.usedBytes = Number(user.usedBytes || 0) + amount;
    }

    d.usage.totalBytes = d.users.reduce(
      (sum, u) => sum + Number(u.usedBytes || 0),
      0
    );

    pendingUsage.clear();
    writeData(d);
  } catch {
    /* Intentionally do not write usage errors to stderr. */
  } finally {
    flushBusy = false;
  }
}

const usageTimer = setInterval(flushUsage, 1500);
if (usageTimer.unref) usageTimer.unref();

function accountAllowed(user) {
  return !!user &&
    user.enabled &&
    Date.parse(user.expiresAt) > Date.now() &&
    Number(user.usedBytes || 0) < Number(user.quotaGB) * 1024 ** 3;
}

function parseVlessHeader(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 24) {
    throw new Error('Invalid request');
  }

  const version = buf[0];
  const uuid = [...buf.subarray(1, 17)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  const addonLen = buf[17];
  let i = 18 + addonLen;
  if (buf.length < i + 4) throw new Error('Incomplete request');

  const command = buf[i++];
  if (command !== 1) throw new Error('Unsupported command');

  const port = buf.readUInt16BE(i);
  i += 2;
  const atyp = buf[i++];
  let host;

  if (atyp === 1) {
    if (buf.length < i + 4) throw new Error('Invalid address');
    host = [...buf.subarray(i, i + 4)].join('.');
    i += 4;
  } else if (atyp === 2) {
    if (buf.length < i + 1) throw new Error('Invalid address');
    const len = buf[i++];
    if (buf.length < i + len) throw new Error('Invalid address');
    host = buf.subarray(i, i + len).toString('utf8');
    i += len;
  } else if (atyp === 3) {
    if (buf.length < i + 16) throw new Error('Invalid address');
    const parts = [];
    for (let j = 0; j < 16; j += 2) {
      parts.push(buf.readUInt16BE(i + j).toString(16));
    }
    host = parts.join(':');
    i += 16;
  } else {
    throw new Error('Invalid address type');
  }

  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Invalid destination');
  }

  return { version, uuid, host, port, payload: buf.subarray(i) };
}

server.on('upgrade', (req, socket, head) => {
  let pathname;

  try {
    pathname = new URL(req.url, 'http://localhost').pathname;
  } catch {
    socket.destroy();
    return;
  }

  const d = readData();
  if (pathname !== (d.settings.wsPath || '/ws')) {
    socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    return;
  }

  wss.handleUpgrade(req, socket, head, ws => {
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', ws => {
  let stream = null;
  let dest = null;
  let finished = false;
  let user = null;

  const closeAll = () => {
    if (finished) return;
    finished = true;

    try { if (stream) stream.destroy(); } catch {}
    try { if (dest) dest.destroy(); } catch {}
    try {
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close();
      }
    } catch {}
  };

  ws.once('message', raw => {
    try {
      const request = parseVlessHeader(Buffer.from(raw));
      const d = readData();

      user = d.users.find(u =>
        String(u.uuid).replace(/-/g, '').toLowerCase() === request.uuid.toLowerCase()
      );

      if (!accountAllowed(user)) {
        try {
          if (ws.readyState === WebSocket.OPEN) ws.close(1008, 'Account unavailable');
        } catch {}
        return;
      }

      stream = WebSocket.createWebSocketStream(ws, { encoding: null });
      dest = net.connect({ host: request.host, port: request.port });

      const enforceQuota = chunk => {
        if (finished || !user) return false;

        const current = readData().users.find(u => u.id === user.id);
        const used = Number(current?.usedBytes || 0) + (pendingUsage.get(user.id) || 0);
        const max = Number(current?.quotaGB || 0) * 1024 ** 3;

        if (!accountAllowed(current) || used + chunk.length > max) {
          if (max > used) addUsage(user.id, max - used);
          closeAll();
          return false;
        }

        addUsage(user.id, chunk.length);
        return true;
      };

      dest.once('connect', () => {
        if (finished || ws.readyState !== WebSocket.OPEN) {
          closeAll();
          return;
        }

        ws.send(Buffer.from([request.version, 0]), error => {
          if (error || finished) {
            closeAll();
            return;
          }

          if (request.payload.length) {
            if (!enforceQuota(request.payload)) return;
            dest.write(request.payload);
          }

          stream.pipe(dest);
          dest.pipe(stream);
        });
      });

      stream.on('data', chunk => {
        if (!enforceQuota(chunk)) return;
      });

      dest.on('data', chunk => {
        if (!enforceQuota(chunk)) return;
      });

      /* Connection errors are handled silently to avoid log-file growth. */
      dest.on('error', closeAll);
      dest.on('close', closeAll);
      stream.on('error', closeAll);
      ws.on('close', closeAll);
      ws.on('error', closeAll);
    } catch {
      closeAll();
    }
  });

  ws.on('error', closeAll);
});

server.listen(PORT, '0.0.0.0');

function shutdown() {
  clearInterval(usageTimer);
  flushUsage();
  for (const client of wss.clients) {
    try { client.terminate(); } catch {}
  }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
