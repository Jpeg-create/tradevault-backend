const express    = require('express');
const router     = express.Router();
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { OAuth2Client } = require('google-auth-library');
const { dbGet, dbRun } = require('../db/database');
const { generateToken } = require('../middleware/auth');

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  if (process.env.NODE_ENV === 'production') {
    console.error('FATAL: JWT_SECRET not set'); process.exit(1);
  }
  return 'dev-only-secret-not-for-production';
})();


// Sanitize errors for client — never expose internal details in production
function safeError(err) {
  if (process.env.NODE_ENV !== 'production') return err.message;
  return 'An error occurred. Please try again.';
}

// ── EMAIL SETUP ───────────────────────────────────────────
// Configure these in Render Environment Variables:
//   SMTP_HOST     e.g. smtp.gmail.com
//   SMTP_PORT     e.g. 587
//   SMTP_USER     your Gmail address
//   SMTP_PASS     your Gmail App Password (not your real password)
//   SMTP_FROM     e.g. TradeVault <you@gmail.com>

function createMailer() {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
  return nodemailer.createTransport({
    host:   process.env.SMTP_HOST || 'smtp.gmail.com',
    port:   parseInt(process.env.SMTP_PORT || '587'),
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

async function sendResetEmail(toEmail, toName, resetToken) {
  const mailer = createMailer();
  const frontendUrl = process.env.FRONTEND_URL || 'https://tradevault-frontend.vercel.app';
  const resetLink   = `${frontendUrl}/auth.html?reset=${resetToken}`;

  if (!mailer) {
    // No SMTP configured — return token so dev can still test
    console.log(`[DEV] Reset token for ${toEmail}: ${resetToken}`);
    return { devToken: resetToken };
  }

  await mailer.sendMail({
    from:    process.env.SMTP_FROM || `TradeVault <${process.env.SMTP_USER}>`,
    to:      `${toName} <${toEmail}>`,
    subject: 'Reset your TradeVault password',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#0a0e14;color:#e8ecf1;border-radius:12px">
        <h1 style="font-size:24px;margin-bottom:8px;color:#00ff88">TradeVault</h1>
        <p style="color:#8a94a6;margin-bottom:24px">Password Reset Request</p>
        <p>Hi ${toName},</p>
        <p>Someone requested a password reset for your account. Click the button below to set a new password. This link expires in <strong>15 minutes</strong>.</p>
        <div style="text-align:center;margin:32px 0">
          <a href="${resetLink}"
             style="background:#00ff88;color:#0a0e14;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px;display:inline-block">
            Reset Password
          </a>
        </div>
        <p style="font-size:13px;color:#8a94a6">Or paste this link in your browser:<br>
          <a href="${resetLink}" style="color:#3498ff;word-break:break-all">${resetLink}</a>
        </p>
        <hr style="border:none;border-top:1px solid #2a3140;margin:24px 0">
        <p style="font-size:12px;color:#8a94a6">If you didn't request this, you can safely ignore this email. Your password won't change.</p>
      </div>`,
  });
  return { sent: true };
}

// ── HELPER ────────────────────────────────────────────────
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
    if (name.trim().length > 100)
      return res.status(400).json({ success: false, error: 'Name must be 100 characters or less' });
    if (email.length > 254)
      return res.status(400).json({ success: false, error: 'Email address is too long' });
    // Basic email format check
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ success: false, error: 'Please enter a valid email address' });
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
    res.status(500).json({ success: false, error: safeError(err) });
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
    res.status(500).json({ success: false, error: safeError(err) });
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
    res.status(500).json({ success: false, error: safeError(err) });
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
    // Always return 200 to prevent email enumeration
    if (!user) return res.json({ success: true, message: 'If that email exists, a reset link has been sent.' });

    const resetToken = jwt.sign({ id: user.id, purpose: 'reset' }, JWT_SECRET, { expiresIn: '15m' });
    const result     = await sendResetEmail(email.toLowerCase(), user.name, resetToken);

    if (result.devToken) {
      // No email configured — return token so user can still reset
      return res.json({
        success: true,
        message: 'No email service configured. Copy the token below and paste it in the Reset Password form.',
        devToken: result.devToken,
      });
    }

    res.json({ success: true, message: 'Password reset email sent! Check your inbox (and spam folder).' });
  } catch (err) {
    console.error('Reset email error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to send reset email: ' + err.message });
  }
});

// ── POST /api/auth/reset-password ────────────────────────
router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword)
      return res.status(400).json({ success: false, error: 'Token and new password are required' });
    if (newPassword.length < 6)
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });

    let decoded;
    try { decoded = jwt.verify(token, JWT_SECRET); }
    catch { return res.status(400).json({ success: false, error: 'Reset link is invalid or has expired (15 min limit)' }); }

    if (decoded.purpose !== 'reset')
      return res.status(400).json({ success: false, error: 'Invalid reset token' });

    const hashed = await bcrypt.hash(newPassword, 12);
    dbRun('UPDATE users SET password = ? WHERE id = ?', [hashed, decoded.id]);
    res.json({ success: true, message: 'Password updated! You can now log in.' });
  } catch (err) {
    res.status(500).json({ success: false, error: safeError(err) });
  }
});

// ── PUT /api/auth/profile ─────────────────────────────────
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
        return res.status(400).json({ success: false, error: 'Google accounts cannot change password here' });
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
    res.status(500).json({ success: false, error: safeError(err) });
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

    dbRun('DELETE FROM trades              WHERE user_id = ?', [decoded.id]);
    dbRun('DELETE FROM journal_entries     WHERE user_id = ?', [decoded.id]);
    dbRun('DELETE FROM broker_connections  WHERE user_id = ?', [decoded.id]);
    dbRun('DELETE FROM users               WHERE id = ?',      [decoded.id]);
    res.json({ success: true, message: 'Account deleted' });
  } catch (err) {
    res.status(500).json({ success: false, error: safeError(err) });
  }
});

module.exports = router;
