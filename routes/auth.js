const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { OAuth2Client } = require('google-auth-library');
const { dbGet, dbRun } = require('../db/database');
const { generateToken } = require('../middleware/auth');

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const JWT_SECRET   = process.env.JWT_SECRET || 'tradevault-secret-change-in-production';

// ── HELPERS ───────────────────────────────────────────────
function authUser(req) {
  const h = req.headers.authorization;
  if (!h) throw new Error('Not authenticated');
  return jwt.verify(h.split(' ')[1], JWT_SECRET);
}

// ── POST /api/auth/signup ─────────────────────────────────
router.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ success: false, error: 'Name, email and password are required' });
    if (password.length < 6)
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });

    const existing = dbGet('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (existing)
      return res.status(409).json({ success: false, error: 'An account with this email already exists' });

    const id     = uuidv4();
    const hashed = await bcrypt.hash(password, 12);
    dbRun('INSERT INTO users (id, name, email, password, created_at) VALUES (?, ?, ?, ?, datetime("now"))',
      [id, name.trim(), email.toLowerCase(), hashed]);

    const user  = dbGet('SELECT id, name, email, avatar, created_at FROM users WHERE id = ?', [id]);
    const token = generateToken(user);
    res.status(201).json({ success: true, token, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── POST /api/auth/login ──────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, error: 'Email and password are required' });

    const user = dbGet('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    if (!user)
      return res.status(401).json({ success: false, error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.password || '');
    if (!valid)
      return res.status(401).json({ success: false, error: 'Invalid email or password' });

    const { password: _pw, ...safeUser } = user;
    const token = generateToken(safeUser);
    res.json({ success: true, token, user: safeUser });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── POST /api/auth/google ─────────────────────────────────
router.post('/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential)
      return res.status(400).json({ success: false, error: 'Google credential required' });

    const ticket  = await googleClient.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    let user = dbGet('SELECT * FROM users WHERE google_id = ? OR email = ?', [googleId, email.toLowerCase()]);
    if (!user) {
      const id = uuidv4();
      dbRun('INSERT INTO users (id, name, email, google_id, avatar, created_at) VALUES (?, ?, ?, ?, ?, datetime("now"))',
        [id, name, email.toLowerCase(), googleId, picture || null]);
      user = dbGet('SELECT id, name, email, avatar, created_at FROM users WHERE id = ?', [id]);
    } else {
      dbRun('UPDATE users SET google_id = ?, avatar = ? WHERE id = ?', [googleId, picture || user.avatar, user.id]);
      user = dbGet('SELECT id, name, email, avatar, created_at FROM users WHERE id = ?', [user.id]);
    }

    const token = generateToken(user);
    res.json({ success: true, token, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── GET /api/auth/me ──────────────────────────────────────
router.get('/me', (req, res) => {
  try {
    const decoded = authUser(req);
    const user    = dbGet('SELECT id, name, email, avatar, created_at FROM users WHERE id = ?', [decoded.id]);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });
    res.json({ success: true, user });
  } catch (err) {
    res.status(401).json({ success: false, error: err.message });
  }
});

// ── POST /api/auth/reset-password-request ────────────────
router.post('/reset-password-request', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, error: 'Email is required' });

    const user = dbGet('SELECT id, name FROM users WHERE email = ?', [email.toLowerCase()]);
    // Always return success to prevent email enumeration
    if (!user) return res.json({ success: true, message: 'If that email exists, a reset link has been sent.' });

    const resetToken = jwt.sign(
      { id: user.id, purpose: 'reset' },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    // In production: send email with reset link containing this token
    // For now (no email service configured): return token directly in dev mode
    res.json({
      success: true,
      message: 'Reset token generated.',
      resetToken,
      dev_note: 'No email service is configured yet. Copy the resetToken above and paste it into the Reset Password form.'
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── POST /api/auth/reset-password ────────────────────────
router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword)
      return res.status(400).json({ success: false, error: 'Token and new password required' });
    if (newPassword.length < 6)
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });

    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(400).json({ success: false, error: 'Reset link is invalid or has expired (15 min limit)' });
    }
    if (decoded.purpose !== 'reset')
      return res.status(400).json({ success: false, error: 'Invalid reset token' });

    const hashed = await bcrypt.hash(newPassword, 12);
    dbRun('UPDATE users SET password = ? WHERE id = ?', [hashed, decoded.id]);
    res.json({ success: true, message: 'Password updated successfully. Please log in.' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── PUT /api/auth/profile — update name or password ──────
router.put('/profile', async (req, res) => {
  try {
    const decoded = authUser(req);
    const { name, currentPassword, newPassword } = req.body;
    const user = dbGet('SELECT * FROM users WHERE id = ?', [decoded.id]);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    if (name && name.trim()) {
      dbRun('UPDATE users SET name = ? WHERE id = ?', [name.trim(), decoded.id]);
    }

    if (newPassword) {
      if (!currentPassword)
        return res.status(400).json({ success: false, error: 'Current password required' });
      if (!user.password)
        return res.status(400).json({ success: false, error: 'Google accounts cannot set a password here' });
      const valid = await bcrypt.compare(currentPassword, user.password);
      if (!valid)
        return res.status(400).json({ success: false, error: 'Current password is incorrect' });
      if (newPassword.length < 6)
        return res.status(400).json({ success: false, error: 'New password must be at least 6 characters' });
      const hashed = await bcrypt.hash(newPassword, 12);
      dbRun('UPDATE users SET password = ? WHERE id = ?', [hashed, decoded.id]);
    }

    const updated  = dbGet('SELECT id, name, email, avatar, created_at FROM users WHERE id = ?', [decoded.id]);
    const newToken = jwt.sign({ id: updated.id, email: updated.email, name: updated.name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, user: updated, token: newToken });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── DELETE /api/auth/account ──────────────────────────────
router.delete('/account', async (req, res) => {
  try {
    const decoded = authUser(req);
    const { password, confirmText } = req.body;
    if (confirmText !== 'DELETE')
      return res.status(400).json({ success: false, error: 'Please type DELETE to confirm' });

    const user = dbGet('SELECT * FROM users WHERE id = ?', [decoded.id]);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    if (user.password) {
      if (!password)
        return res.status(400).json({ success: false, error: 'Password required to delete account' });
      const valid = await bcrypt.compare(password, user.password);
      if (!valid)
        return res.status(400).json({ success: false, error: 'Incorrect password' });
    }

    dbRun('DELETE FROM trades           WHERE user_id = ?', [decoded.id]);
    dbRun('DELETE FROM journal_entries  WHERE user_id = ?', [decoded.id]);
    dbRun('DELETE FROM broker_connections WHERE user_id = ?', [decoded.id]);
    dbRun('DELETE FROM users            WHERE id = ?',      [decoded.id]);
    res.json({ success: true, message: 'Account deleted' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
