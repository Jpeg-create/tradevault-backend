const express    = require('express');
const router     = express.Router();
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { OAuth2Client } = require('google-auth-library');
const { dbGet, dbRun } = require('../db/database');
const { generateToken, requireAuth, JWT_SECRET } = require('../middleware/auth');

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);


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
//   SMTP_FROM     e.g. Quantario <you@gmail.com>

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

// Verify SMTP connection on startup so misconfiguration fails loudly
(async () => {
  const mailer = createMailer();
  if (!mailer) {
    console.log('[EMAIL] No SMTP credentials set — email sending disabled. Password reset tokens will be returned in API responses (dev mode).');
    return;
  }
  try {
    await mailer.verify();
    console.log(`[EMAIL] SMTP ready — sending from ${process.env.SMTP_FROM || process.env.SMTP_USER}`);
  } catch (err) {
    console.error('[EMAIL] SMTP connection failed:', err.message);
    console.error('[EMAIL] Check SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS in your environment.');
  }
})();

async function sendWelcomeEmail(toEmail, toName) {
  const mailer = createMailer();
  if (!mailer) return; // silent — no SMTP configured

  const frontendUrl = process.env.FRONTEND_URL || 'https://quantario-frontend.vercel.app';
  try {
    await mailer.sendMail({
      from:    process.env.SMTP_FROM || `Quantario <${process.env.SMTP_USER}>`,
      to:      `${toName} <${toEmail}>`,
      subject: 'Welcome to Quantario 🚀',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#0a0e14;color:#e8ecf1;border-radius:12px">
          <h1 style="font-size:24px;margin-bottom:8px;color:#00d4ff">Trade<span style="color:#a3e635">Vault</span></h1>
          <p style="color:#8a94a6;margin-bottom:24px">Your professional trading journal</p>
          <p>Hi ${toName},</p>
          <p>Welcome aboard! Your Quantario account is ready. Start logging your trades, track your performance, and build better trading habits.</p>
          <div style="background:#111827;border-radius:8px;padding:20px;margin:24px 0;border-left:3px solid #00d4ff">
            <p style="margin:0 0 8px;font-size:13px;color:#8a94a6;text-transform:uppercase;letter-spacing:.05em">A few things you can do:</p>
            <ul style="margin:0;padding-left:18px;color:#e8ecf1;line-height:2">
              <li>Log your first trade</li>
              <li>Connect a broker for auto-sync</li>
              <li>Import a CSV of past trades</li>
              <li>Write your first journal entry</li>
            </ul>
          </div>
          <div style="text-align:center;margin:32px 0">
            <a href="${frontendUrl}/app"
               style="background:#00d4ff;color:#0a0e14;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px;display:inline-block">
              Open Quantario
            </a>
          </div>
          <hr style="border:none;border-top:1px solid #2a3140;margin:24px 0">
          <p style="font-size:12px;color:#8a94a6">You're receiving this because you created an account at Quantario. If this wasn't you, you can safely ignore this email.</p>
        </div>`,
    });
  } catch (err) {
    // Welcome email is best-effort — never block signup
    console.error('[EMAIL] Failed to send welcome email to', toEmail, ':', err.message);
  }
}

async function sendResetEmail(toEmail, toName, resetToken) {
  const mailer = createMailer();
  const frontendUrl = process.env.FRONTEND_URL || 'https://quantario-frontend.vercel.app';
  const resetLink   = `${frontendUrl}/auth.html?reset=${resetToken}`;

  if (!mailer) {
    // No SMTP configured — return token so dev can still test
    console.log(`[DEV] Reset token for ${toEmail}: ${resetToken}`);
    return { devToken: resetToken };
  }

  await mailer.sendMail({
    from:    process.env.SMTP_FROM || `Quantario <${process.env.SMTP_USER}>`,
    to:      `${toName} <${toEmail}>`,
    subject: 'Reset your Quantario password',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#0a0e14;color:#e8ecf1;border-radius:12px">
        <h1 style="font-size:24px;margin-bottom:8px;color:#00ff88">Quantario</h1>
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

    const user  = dbGet('SELECT id, name, email, avatar, plan, created_at FROM users WHERE id = ?', [id]);
    const token = generateToken(user);

    // Send welcome email — fire-and-forget, never block the signup response
    sendWelcomeEmail(user.email, user.name);

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
      user = dbGet('SELECT id, name, email, avatar, plan, created_at FROM users WHERE id = ?', [id]);
    } else {
      dbRun('UPDATE users SET google_id = ?, avatar = ? WHERE id = ?', [googleId, picture || user.avatar, user.id]);
      user = dbGet('SELECT id, name, email, avatar, plan, created_at FROM users WHERE id = ?', [user.id]);
    }

    const token = generateToken(user);
    res.json({ success: true, token, user });
  } catch (err) {
    res.status(500).json({ success: false, error: safeError(err) });
  }
});

// ── GET /api/auth/me ──────────────────────────────────────
router.get('/me', requireAuth, (req, res) => {
  try {
    const user = dbGet('SELECT id, name, email, avatar, plan, created_at FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: safeError(err) });
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
    const result = await sendResetEmail(email.toLowerCase(), user.name, resetToken);

    if (result?.devToken) {
      // No email configured AND not in production — return token for local dev/testing
      if (process.env.NODE_ENV === 'production') {
        // In production without SMTP, fail explicitly rather than leaking a token
        return res.status(500).json({
          success: false,
          error: 'Email service is not configured. Please contact support to reset your password.',
        });
      }
      return res.json({
        success: true,
        message: 'No email service configured. Copy the token below and paste it in the Reset Password form.',
        devToken: result.devToken,
      });
    }

    res.json({ success: true, message: 'Password reset email sent! Check your inbox (and spam folder).' });
  } catch (err) {
    console.error('Reset email error:', err.message);
    const isProduction = process.env.NODE_ENV === 'production';
    res.status(500).json({
      success: false,
      error: isProduction ? 'Failed to send reset email. Please try again.' : 'Failed to send reset email: ' + err.message,
    });
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

    // Enforce single-use: hash the token and check if it's already been used
    const crypto = require('crypto');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const alreadyUsed = dbGet('SELECT token_hash FROM used_reset_tokens WHERE token_hash = ?', [tokenHash]);
    if (alreadyUsed)
      return res.status(400).json({ success: false, error: 'Reset link has already been used. Please request a new one.' });

    // Mark token as used before updating password
    dbRun('INSERT INTO used_reset_tokens (token_hash) VALUES (?)', [tokenHash]);

    const hashed = await bcrypt.hash(newPassword, 12);
    dbRun('UPDATE users SET password = ? WHERE id = ?', [hashed, decoded.id]);

    // Clean up expired used tokens (older than 15 min) to prevent table bloat
    dbRun("DELETE FROM used_reset_tokens WHERE used_at < datetime('now', '-15 minutes')");

    res.json({ success: true, message: 'Password updated! You can now log in.' });
  } catch (err) {
    res.status(500).json({ success: false, error: safeError(err) });
  }
});

// ── PUT /api/auth/profile ─────────────────────────────────
router.put('/profile', requireAuth, async (req, res) => {
  try {
    const { name, currentPassword, newPassword } = req.body;
    const user = dbGet('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    if (name && name.trim()) {
      dbRun('UPDATE users SET name = ? WHERE id = ?', [name.trim(), req.user.id]);
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
      dbRun('UPDATE users SET password = ? WHERE id = ?', [hashed, req.user.id]);
    }

    const updated  = dbGet('SELECT id, name, email, avatar, plan, created_at FROM users WHERE id = ?', [req.user.id]);
    const newToken = generateToken(updated);
    res.json({ success: true, user: updated, token: newToken });
  } catch (err) {
    res.status(500).json({ success: false, error: safeError(err) });
  }
});

// ── DELETE /api/auth/account ──────────────────────────────
router.delete('/account', requireAuth, async (req, res) => {
  try {
    const { password, confirmText } = req.body;
    if (confirmText !== 'DELETE')
      return res.status(400).json({ success: false, error: 'Please type DELETE to confirm' });

    const user = dbGet('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    if (user.password) {
      if (!password)
        return res.status(400).json({ success: false, error: 'Password required to delete account' });
      const valid = await bcrypt.compare(password, user.password);
      if (!valid)
        return res.status(400).json({ success: false, error: 'Incorrect password' });
    }

    dbRun('DELETE FROM trades              WHERE user_id = ?', [req.user.id]);
    dbRun('DELETE FROM journal_entries     WHERE user_id = ?', [req.user.id]);
    dbRun('DELETE FROM broker_connections  WHERE user_id = ?', [req.user.id]);
    dbRun('DELETE FROM users               WHERE id = ?',      [req.user.id]);
    res.json({ success: true, message: 'Account deleted' });
  } catch (err) {
    res.status(500).json({ success: false, error: safeError(err) });
  }
});

module.exports = router;
