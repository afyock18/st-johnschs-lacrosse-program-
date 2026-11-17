'use strict';

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || 'alericfyock1@gmail.com').toLowerCase();
const JWT_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-me';
const NOTIFY_TOKEN = process.env.NOTIFY_TOKEN || '';
const DATABASE_URL = process.env.DATABASE_URL || '';
const SMTP_USER = process.env.SMTP_USER || 'alericfyock1@gmail.com';
const SMTP_PASS = process.env.SMTP_PASS || '';

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
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ');
    // Single-use password reset tokens (only the SHA-256 hash is stored).
    await pool.query(
      `CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    // One shared program state for every approved account (last-write-wins).
    await pool.query(
      `CREATE TABLE IF NOT EXISTS shared_state (
        id INTEGER PRIMARY KEY DEFAULT 1,
        data JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT single_row CHECK (id = 1)
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
app.use(express.json({ limit: '6mb' }));
app.use(cookieParser());

// Password reset mailer (Gmail SMTP). Configured from env only; SMTP_PASS is a
// Gmail app password. Until it is set, reset emails are skipped (logged) and
// the forgot-password endpoint still answers with its generic success.
let mailTransporter = null;
let mailTransporterTried = false;
function getMailer() {
  if (mailTransporterTried) return mailTransporter;
  mailTransporterTried = true;
  if (!SMTP_PASS) {
    console.error('SMTP_PASS is not set; password reset emails are disabled');
    return null;
  }
  try {
    mailTransporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
  } catch (err) {
    console.error('Could not set up the mailer:', err.message);
    mailTransporter = null;
  }
  return mailTransporter;
}

// Password recovery: emailed reset links, one use, 1 hour.
const RESET_TOKEN_TTL_MS = 60 * 60 * 1000;
const FORGOT_RATE_LIMIT = 5;
const FORGOT_RATE_WINDOW_MS = 60 * 60 * 1000;
const forgotAttempts = new Map(); // email -> [request timestamps]

function forgotRateLimited(email) {
  const now = Date.now();
  const recent = (forgotAttempts.get(email) || []).filter(function (t) { return now - t < FORGOT_RATE_WINDOW_MS; });
  if (recent.length >= FORGOT_RATE_LIMIT) {
    forgotAttempts.set(email, recent);
    return true;
  }
  recent.push(now);
  forgotAttempts.set(email, recent);
  return false;
}

function hashResetToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function resetLinkBase(req) {
  const external = process.env.RENDER_EXTERNAL_URL;
  if (external) return String(external).replace(/\/$/, '');
  return req.protocol + '://' + req.get('host');
}

async function sendResetEmail(email, resetLink) {
  const transporter = getMailer();
  if (!transporter) {
    console.error('Password reset email not sent: mail is not configured');
    return false;
  }
  try {
    await transporter.sendMail({
      from: SMTP_USER,
      to: email,
      subject: "Reset your St. John's Lacrosse password",
      text: [
        "You asked to reset the password for your St. John's Lacrosse account.",
        '',
        'Reset your password here (this link works once and expires in 1 hour):',
        resetLink,
        '',
        'If you did not ask for this, you can ignore this email — your password will not change.',
      ].join('\n'),
    });
    return true;
  } catch (err) {
    console.error('Password reset email failed:', err.message);
    return false;
  }
}
function publicUser(row) {
  return { id: row.id, name: row.name, email: row.email, status: row.status, role: row.role, created_at: row.created_at };
}

function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}

// Idle auto-logout: a session ends after 1 hour without activity.
// The 7-day JWT stays the absolute cap; this is the idle cap only.
const IDLE_TIMEOUT_MS = 60 * 60 * 1000;
const ACTIVITY_WRITE_MIN_MS = 60 * 1000;
const SKIP_ACTIVITY_PATHS = ['/api/health', '/login', '/api/login', '/api/signup', '/api/logout'];
const lastActivityWrite = new Map();
function touchActivity(userId, force, reqPath) {
  if (!pool || !userId) return;
  if (reqPath && SKIP_ACTIVITY_PATHS.indexOf(reqPath) !== -1) return;
  var now = Date.now();
  var prev = lastActivityWrite.get(userId) || 0;
  if (!force && now - prev < ACTIVITY_WRITE_MIN_MS) return;
  lastActivityWrite.set(userId, now);
  pool.query('UPDATE users SET last_active_at = now() WHERE id = $1', [userId]).catch(function () {});
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
    const result = await pool.query('SELECT id, name, email, status, role, created_at, last_active_at, password_changed_at FROM users WHERE id = $1', [payload.id]);
    req.user = result.rows.length ? result.rows[0] : null;
    if (req.user) {
      var changedAt = req.user.password_changed_at ? new Date(req.user.password_changed_at).getTime() : 0;
      if (changedAt && payload.iat < Math.floor(changedAt / 1000)) {
        // Password was reset after this session started: end the session.
        req.user = null;
        res.clearCookie('token', { path: '/' });
        return next();
      }
      var lastActive = req.user.last_active_at ? new Date(req.user.last_active_at).getTime() : 0;
      if (lastActive && Date.now() - lastActive > IDLE_TIMEOUT_MS) {
        // Idle for over an hour: end the session even though the JWT is still valid.
        req.user = null;
        req.sessionExpired = true;
        res.clearCookie('token', { path: '/' });
      } else {
        // No last_active_at yet (users from before this change): seed it now and stay logged in.
        touchActivity(req.user.id, !lastActive, req.path);
      }
    }
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
  if (req.sessionExpired) return res.status(401).json({ error: 'Your session ended after an hour without activity. Please log in again.' });
  if (!req.user) return res.status(401).json({ error: 'Please log in.' });
  return next();
}

function requireApproved(req, res, next) {
  if (req.sessionExpired) return res.status(401).json({ error: 'Your session ended after an hour without activity. Please log in again.' });
  if (!req.user) return res.status(401).json({ error: 'Please log in.' });
  if (req.user.status !== 'approved') {
    return res.status(403).json({ error: 'Your account is waiting for approval.' });
  }
  return next();
}

function requireAdmin(req, res, next) {
  if (req.sessionExpired) return res.status(401).json({ error: 'Your session ended after an hour without activity. Please log in again.' });
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
      touchActivity(user.id, true);
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
    touchActivity(user.id, true);
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

// Forgot password: always the same generic answer, whether or not the email
// has an approved account, so account existence is never revealed.
app.post('/api/forgot-password', async (req, res) => {
  if (!requireDb(req, res)) return;
  const email = String(req.body && req.body.email ? req.body.email : '').trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.json({ ok: true });
  }
  if (forgotRateLimited(email)) return res.json({ ok: true });
  try {
    const result = await pool.query('SELECT id, email, status FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || user.status !== 'approved') return res.json({ ok: true });
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashResetToken(rawToken);
    // One active token per user: a new request replaces any earlier one.
    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [user.id]);
    await pool.query(
      'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
      [user.id, tokenHash, new Date(Date.now() + RESET_TOKEN_TTL_MS)]
    );
    const link = resetLinkBase(req) + '/reset?token=' + rawToken;
    await sendResetEmail(user.email, link);
    return res.json({ ok: true });
  } catch (err) {
    console.error('Forgot password failed:', err.message);
    return res.json({ ok: true });
  }
});

// Check whether a reset token is still usable (drives the reset page's state).
app.get('/api/reset-token', async (req, res) => {
  if (!requireDb(req, res)) return;
  const token = String(req.query && req.query.token ? req.query.token : '');
  const badLink = 'This reset link is invalid or has expired.';
  if (!token) return res.status(400).json({ error: badLink });
  try {
    const result = await pool.query(
      'SELECT id FROM password_reset_tokens WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()',
      [hashResetToken(token)]
    );
    if (!result.rows.length) return res.status(400).json({ error: badLink });
    return res.json({ ok: true });
  } catch (err) {
    console.error('Reset token check failed:', err.message);
    return res.status(500).json({ error: 'Could not check the reset link. Please try again.' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  if (!requireDb(req, res)) return;
  const token = String(req.body && req.body.token ? req.body.token : '');
  const password = String(req.body && req.body.password ? req.body.password : '');
  const badLink = 'This reset link is invalid or has expired.';
  if (!token) return res.status(400).json({ error: badLink });
  try {
    const result = await pool.query(
      'SELECT id, user_id FROM password_reset_tokens WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()',
      [hashResetToken(token)]
    );
    const row = result.rows[0];
    if (!row) return res.status(400).json({ error: badLink });
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    const hash = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password_hash = $1, password_changed_at = now() WHERE id = $2', [hash, row.user_id]);
    await pool.query('UPDATE password_reset_tokens SET used_at = now() WHERE id = $1', [row.id]);
    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1 AND id <> $2', [row.user_id, row.id]);
    return res.json({ ok: true, message: 'Your password was updated.' });
  } catch (err) {
    console.error('Reset password failed:', err.message);
    return res.status(500).json({ error: 'Could not reset the password. Please try again.' });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ ok: true, user: publicUser(req.user) });
});

// Shared program state: one state for every approved account (last-write-wins).
app.get('/api/data', requireApproved, async (req, res) => {
  if (!requireDb(req, res)) return;
  try {
    const result = await pool.query('SELECT data, updated_at FROM shared_state WHERE id = 1');
    if (!result.rows.length) return res.json({ ok: true, data: null, updated_at: null });
    return res.json({ ok: true, data: result.rows[0].data, updated_at: result.rows[0].updated_at });
  } catch (err) {
    console.error('Load shared state failed:', err.message);
    return res.status(500).json({ error: 'Could not load the saved program.' });
  }
});

app.put('/api/data', requireApproved, async (req, res) => {
  if (!requireDb(req, res)) return;
  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'Saved data must be an object.' });
  }
  let size = 0;
  try {
    size = JSON.stringify(body).length;
  } catch (err) {
    return res.status(400).json({ error: 'Saved data could not be read.' });
  }
  if (size > 5 * 1024 * 1024) {
    return res.status(413).json({ error: 'Saved data is too large (over 5 MB).' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO shared_state (id, data, updated_at) VALUES (1, $1::jsonb, now())
       ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()
       RETURNING updated_at`,
      [JSON.stringify(body)]
    );
    return res.json({ ok: true, updated_at: result.rows[0].updated_at });
  } catch (err) {
    console.error('Save shared state failed:', err.message);
    return res.status(500).json({ error: 'Could not save the program.' });
  }
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
    await pool.query('UPDATE users SET password_hash = $1, password_changed_at = now() WHERE id = $2', [hash, req.user.id]);
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
const RESET_FILE = path.join(__dirname, 'reset.html');
const ADMIN_FILE = path.join(__dirname, 'admin.html');

function serveApp(req, res) {
  if (req.sessionExpired) return res.redirect('/login?notice=idle');
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

app.get('/reset', (req, res) => {
  return res.sendFile(RESET_FILE);
});

app.get('/admin', (req, res) => {
  if (req.sessionExpired) return res.redirect('/login?notice=idle');
  if (!req.user) return res.redirect('/login');
  if (req.user.role !== 'admin' || req.user.status !== 'approved') return res.redirect('/');
  return res.sendFile(ADMIN_FILE);
});

app.listen(PORT, async () => {
  console.log('Listening on port ' + PORT);
  await initDb();
});
