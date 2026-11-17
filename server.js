'use strict';

const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || 'alericfyock1@gmail.com').toLowerCase();
const JWT_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-me';
const NOTIFY_TOKEN = process.env.NOTIFY_TOKEN || '';
const DATABASE_URL = process.env.DATABASE_URL || '';

const pool = DATABASE_URL
  ? new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : null;
let dbReady = false;
let dbError = '';
let dbHost = '';
try {
  if (DATABASE_URL) dbHost = new URL(DATABASE_URL).hostname;
} catch (err) {
  dbHost = 'invalid-url';
}

async function initDb() {
  if (!pool) {
    console.error('DATABASE_URL is not set; user accounts are unavailable');
    return;
  }
  try {
    await pool.query(
      `CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    dbReady = true;
    console.log('Database ready');
  } catch (err) {
    dbError = err.message || String(err);
    console.error('Database init failed:', err.message);
  }
}

const app = express();
app.use(express.json());
app.use(cookieParser());

function publicUser(row) {
  return { id: row.id, name: row.name, email: row.email, status: row.status, role: row.role, created_at: row.created_at };
}

function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}

function setAuthCookie(res, token) {
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  });
}

async function authUser(req, res, next) {
  const token = req.cookies && req.cookies.token;
  if (!token) {
    req.user = null;
    return next();
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT id, name, email, status, role, created_at FROM users WHERE id = $1', [payload.id]);
    req.user = result.rows.length ? result.rows[0] : null;
  } catch (err) {
    req.user = null;
  }
  return next();
}

function requireDb(req, res) {
  if (!dbReady || !pool) {
    res.status(503).json({ error: 'Database is not ready yet. Please try again in a moment.' });
    return false;
  }
  return true;
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Please log in.' });
  return next();
}

function requireApproved(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Please log in.' });
  if (req.user.status !== 'approved') {
    return res.status(403).json({ error: 'Your account is waiting for approval.' });
  }
  return next();
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Please log in.' });
  if (req.user.role !== 'admin' || req.user.status !== 'approved') {
    return res.status(403).json({ error: 'Admin access only.' });
  }
  return next();
}

app.use(authUser);

app.get('/api/health', (req, res) => {
  res.json({ ok: true, db: dbReady, dbHost: dbHost, dbError: dbError || undefined });
});

app.post('/api/signup', async (req, res) => {
  if (!requireDb(req, res)) return;
  const name = String(req.body && req.body.name ? req.body.name : '').trim();
  const email = String(req.body && req.body.email ? req.body.email : '').trim().toLowerCase();
  const password = String(req.body && req.body.password ? req.body.password : '');
  if (!name || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Please enter your name and a valid email address.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  const isAdmin = email === ADMIN_EMAIL;
  const status = isAdmin ? 'approved' : 'pending';
  const role = isAdmin ? 'admin' : 'user';
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash, status, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, status, role, created_at',
      [name, email, hash, status, role]
    );
    const user = publicUser(result.rows[0]);
    if (isAdmin) {
      setAuthCookie(res, signToken(user));
      return res.status(201).json({ ok: true, user, message: 'Admin account created and approved.' });
    }
    return res.status(201).json({ ok: true, user, message: 'Account created. It is waiting for approval before you can log in.' });
  } catch (err) {
    if (err && err.code === '23505') {
      return res.status(409).json({ error: 'An account with that email already exists. Try logging in instead.' });
    }
    console.error('Signup failed:', err.message);
    return res.status(500).json({ error: 'Could not create the account. Please try again.' });
  }
});

app.post('/api/login', async (req, res) => {
  if (!requireDb(req, res)) return;
  const email = String(req.body && req.body.email ? req.body.email : '').trim().toLowerCase();
  const password = String(req.body && req.body.password ? req.body.password : '');
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Email or password is incorrect.' });
    }
    if (user.status === 'pending') {
      return res.status(403).json({ error: 'Your account is waiting for approval.' });
    }
    if (user.status === 'denied') {
      return res.status(403).json({ error: 'Access denied.' });
    }
    setAuthCookie(res, signToken(user));
    return res.json({ ok: true, user: publicUser(user) });
  } catch (err) {
    console.error('Login failed:', err.message);
    return res.status(500).json({ error: 'Could not log in. Please try again.' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { path: '/' });
  return res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ ok: true, user: publicUser(req.user) });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  if (!requireDb(req, res)) return;
  const current = String(req.body && req.body.currentPassword ? req.body.currentPassword : '');
  const next = String(req.body && req.body.newPassword ? req.body.newPassword : '');
  if (next.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(current, user.password_hash))) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }
    const hash = await bcrypt.hash(next, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.id]);
    return res.json({ ok: true, message: 'Password changed.' });
  } catch (err) {
    console.error('Change password failed:', err.message);
    return res.status(500).json({ error: 'Could not change the password. Please try again.' });
  }
});

app.get('/api/admin/pending', requireAdmin, async (req, res) => {
  if (!requireDb(req, res)) return;
  try {
    const result = await pool.query(
      "SELECT id, name, email, created_at FROM users WHERE status = 'pending' ORDER BY created_at ASC"
    );
    return res.json({ ok: true, pending: result.rows });
  } catch (err) {
    console.error('List pending failed:', err.message);
    return res.status(500).json({ error: 'Could not load pending accounts.' });
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  if (!requireDb(req, res)) return;
  try {
    const result = await pool.query(
      'SELECT id, name, email, status, role, created_at FROM users ORDER BY created_at ASC'
    );
    return res.json({ ok: true, users: result.rows });
  } catch (err) {
    console.error('List users failed:', err.message);
    return res.status(500).json({ error: 'Could not load accounts.' });
  }
});

app.post('/api/admin/approve', requireAdmin, async (req, res) => {
  if (!requireDb(req, res)) return;
  const id = Number(req.body && req.body.id);
  if (!id) return res.status(400).json({ error: 'Account id is required.' });
  try {
    const result = await pool.query(
      "UPDATE users SET status = 'approved' WHERE id = $1 RETURNING id, name, email, status, role, created_at",
      [id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Account not found.' });
    return res.json({ ok: true, user: publicUser(result.rows[0]) });
  } catch (err) {
    console.error('Approve failed:', err.message);
    return res.status(500).json({ error: 'Could not approve the account.' });
  }
});

app.post('/api/admin/deny', requireAdmin, async (req, res) => {
  if (!requireDb(req, res)) return;
  const id = Number(req.body && req.body.id);
  if (!id) return res.status(400).json({ error: 'Account id is required.' });
  try {
    const result = await pool.query(
      "UPDATE users SET status = 'denied' WHERE id = $1 RETURNING id, name, email, status, role, created_at",
      [id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Account not found.' });
    return res.json({ ok: true, user: publicUser(result.rows[0]) });
  } catch (err) {
    console.error('Deny failed:', err.message);
    return res.status(500).json({ error: 'Could not deny the account.' });
  }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  if (!requireDb(req, res)) return;
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: 'Account id is required.' });
  if (id === req.user.id) return res.status(400).json({ error: 'You cannot delete your own account.' });
  try {
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id', [id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Account not found.' });
    return res.json({ ok: true });
  } catch (err) {
    console.error('Delete user failed:', err.message);
    return res.status(500).json({ error: 'Could not delete the account.' });
  }
});

app.get('/api/notify/pending', async (req, res) => {
  if (!requireDb(req, res)) return;
  if (!NOTIFY_TOKEN || req.headers['x-notify-token'] !== NOTIFY_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  try {
    const result = await pool.query(
      "SELECT id, name, email, created_at FROM users WHERE status = 'pending' ORDER BY created_at ASC"
    );
    return res.json({ ok: true, pending: result.rows });
  } catch (err) {
    console.error('Notify pending failed:', err.message);
    return res.status(500).json({ error: 'Could not load pending accounts.' });
  }
});

const APP_FILE = path.join(__dirname, 'public', 'index.html');
const LOGIN_FILE = path.join(__dirname, 'login.html');
const ADMIN_FILE = path.join(__dirname, 'admin.html');

function serveApp(req, res) {
  if (!req.user) return res.redirect('/login');
  if (req.user.status !== 'approved') {
    return res.redirect('/login?notice=waiting');
  }
  let html = fs.readFileSync(APP_FILE, 'utf8');
  if (req.user.role === 'admin') {
    const banner = '<a href="/admin" style="position:fixed;right:16px;bottom:16px;z-index:9999;background:#a6192e;color:#fff;padding:10px 16px;border-radius:999px;text-decoration:none;font-family:system-ui,sans-serif;font-weight:700;box-shadow:0 2px 8px rgba(0,0,0,.25)">Approvals</a>';
    html = html.replace('</body>', banner + '</body>');
  }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.send(html);
}

app.get('/', serveApp);
app.get('/app', serveApp);

app.get('/login', (req, res) => {
  if (req.user && req.user.status === 'approved') return res.redirect('/');
  return res.sendFile(LOGIN_FILE);
});

app.get('/admin', (req, res) => {
  if (!req.user) return res.redirect('/login');
  if (req.user.role !== 'admin' || req.user.status !== 'approved') return res.redirect('/');
  return res.sendFile(ADMIN_FILE);
});

app.listen(PORT, async () => {
  console.log('Listening on port ' + PORT);
  await initDb();
});
