const express  = require('express');
const router   = express.Router();
const nodemailer = require('nodemailer');
const { dbAll } = require('../db/database');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

const safeErr = err =>
  process.env.NODE_ENV !== 'production' ? err.message : 'Server error';

function createMailer() {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
  return nodemailer.createTransport({
    host:   process.env.SMTP_HOST || 'smtp.gmail.com',
    port:   parseInt(process.env.SMTP_PORT || '587'),
    secure: false,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

// ── POST /api/email/weekly-summary ───────────────────────
// Calculates the current week's stats and emails them to the logged-in user.
router.post('/weekly-summary', async (req, res) => {
  try {
    const mailer = createMailer();
    if (!mailer) {
      return res.status(503).json({ success: false, error: 'Email is not configured on this server.' });
    }

    // Get user record for name + email
    const { dbGet } = require('../db/database');
    const user = await dbGet('SELECT id, name, email FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    // Week boundaries (Mon 00:00 → Sun 23:59 local-ish, using UTC for simplicity)
    const now   = new Date();
    const day   = now.getDay(); // 0 = Sunday
    const diffToMon = (day === 0 ? -6 : 1 - day);
    const weekStart = new Date(now);
    weekStart.setDate(now.getDate() + diffToMon);
    weekStart.setHours(0, 0, 0, 0);

    const allTrades  = await dbAll('SELECT * FROM trades WHERE user_id = ?', [req.user.id]);
    const weekTrades = allTrades.filter(t => {
      if (!t.exit_date) return false;
      return new Date(t.exit_date) >= weekStart;
    });

    // Compute stats
    const wins     = weekTrades.filter(t => t.pnl > 0);
    const losses   = weekTrades.filter(t => t.pnl < 0);
    const totalPnL = weekTrades.reduce((s, t) => s + Number(t.pnl), 0);
    const winRate  = weekTrades.length ? ((wins.length / weekTrades.length) * 100).toFixed(1) : '0.0';
    const bestTrade  = weekTrades.reduce((b, t) => (!b || Number(t.pnl) > Number(b.pnl) ? t : b), null);
    const worstTrade = weekTrades.reduce((b, t) => (!b || Number(t.pnl) < Number(b.pnl) ? t : b), null);

    // Build strategy breakdown
    const byStrategy = {};
    weekTrades.forEach(t => {
      const k = t.strategy || 'No Strategy';
      if (!byStrategy[k]) byStrategy[k] = { pnl: 0, count: 0 };
      byStrategy[k].pnl   += Number(t.pnl);
      byStrategy[k].count += 1;
    });
    const stratRows = Object.entries(byStrategy)
      .sort((a, b) => b[1].pnl - a[1].pnl)
      .slice(0, 5)
      .map(([name, d]) =>
        `<tr>
          <td style="padding:8px 12px;border-bottom:1px solid #1e2a3a">${name}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #1e2a3a;text-align:center">${d.count}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #1e2a3a;text-align:right;color:${d.pnl >= 0 ? '#00d4ff' : '#ef4444'};font-weight:700">
            ${d.pnl >= 0 ? '+' : ''}$${d.pnl.toFixed(2)}
          </td>
        </tr>`
      ).join('');

    const pnlColour  = totalPnL >= 0 ? '#00d4ff' : '#ef4444';
    const pnlSign    = totalPnL >= 0 ? '+' : '';
    const weekLabel  = weekStart.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    const frontendUrl = process.env.FRONTEND_URL || 'https://quantario-frontend.vercel.app';

    const html = `
      <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;background:#06080d;color:#e8ecf1;border-radius:16px;overflow:hidden">
        <!-- Header -->
        <div style="background:linear-gradient(135deg,rgba(0,212,255,0.12),rgba(163,230,53,0.08));padding:32px;border-bottom:1px solid rgba(255,255,255,0.06)">
          <div style="font-size:22px;font-weight:800;letter-spacing:-0.5px">
            Quan<span style="color:#a3e635">tario</span>
          </div>
          <div style="color:#8a94a6;font-size:13px;margin-top:4px">Weekly Performance Summary</div>
          <div style="color:#8a94a6;font-size:12px;margin-top:2px">Week of ${weekLabel}</div>
        </div>

        <!-- Big P&L number -->
        <div style="padding:32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.06)">
          <div style="font-size:11px;color:#8a94a6;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px">Weekly P&amp;L</div>
          <div style="font-size:48px;font-weight:800;color:${pnlColour};letter-spacing:-2px">${pnlSign}$${Math.abs(totalPnL).toFixed(2)}</div>
          <div style="color:#8a94a6;margin-top:8px;font-size:14px">${weekTrades.length} trades · ${winRate}% win rate</div>
        </div>

        <!-- Stats row -->
        <div style="display:flex;border-bottom:1px solid rgba(255,255,255,0.06)">
          <div style="flex:1;padding:20px;text-align:center;border-right:1px solid rgba(255,255,255,0.06)">
            <div style="font-size:10px;color:#8a94a6;letter-spacing:1.5px;text-transform:uppercase">Wins</div>
            <div style="font-size:24px;font-weight:700;color:#22c55e;margin-top:4px">${wins.length}</div>
          </div>
          <div style="flex:1;padding:20px;text-align:center;border-right:1px solid rgba(255,255,255,0.06)">
            <div style="font-size:10px;color:#8a94a6;letter-spacing:1.5px;text-transform:uppercase">Losses</div>
            <div style="font-size:24px;font-weight:700;color:#ef4444;margin-top:4px">${losses.length}</div>
          </div>
          <div style="flex:1;padding:20px;text-align:center">
            <div style="font-size:10px;color:#8a94a6;letter-spacing:1.5px;text-transform:uppercase">Win Rate</div>
            <div style="font-size:24px;font-weight:700;color:#e8ecf1;margin-top:4px">${winRate}%</div>
          </div>
        </div>

        ${bestTrade ? `
        <!-- Best / Worst -->
        <div style="display:flex;border-bottom:1px solid rgba(255,255,255,0.06)">
          <div style="flex:1;padding:20px;border-right:1px solid rgba(255,255,255,0.06)">
            <div style="font-size:10px;color:#8a94a6;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:8px">Best Trade</div>
            <div style="font-weight:700;font-size:15px">${bestTrade.symbol}</div>
            <div style="color:#00d4ff;font-weight:700;font-size:14px">+$${Number(bestTrade.pnl).toFixed(2)}</div>
          </div>
          <div style="flex:1;padding:20px">
            <div style="font-size:10px;color:#8a94a6;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:8px">Worst Trade</div>
            <div style="font-weight:700;font-size:15px">${worstTrade.symbol}</div>
            <div style="color:#ef4444;font-weight:700;font-size:14px">$${Number(worstTrade.pnl).toFixed(2)}</div>
          </div>
        </div>` : ''}

        ${stratRows ? `
        <!-- Strategy breakdown -->
        <div style="padding:24px;border-bottom:1px solid rgba(255,255,255,0.06)">
          <div style="font-size:11px;color:#8a94a6;letter-spacing:2px;text-transform:uppercase;margin-bottom:16px">Strategy Breakdown</div>
          <table style="width:100%;border-collapse:collapse;font-size:13px">
            <thead>
              <tr style="color:#8a94a6;font-size:11px;text-transform:uppercase;letter-spacing:1px">
                <th style="padding:8px 12px;text-align:left;border-bottom:1px solid #1e2a3a">Strategy</th>
                <th style="padding:8px 12px;text-align:center;border-bottom:1px solid #1e2a3a">Trades</th>
                <th style="padding:8px 12px;text-align:right;border-bottom:1px solid #1e2a3a">P&amp;L</th>
              </tr>
            </thead>
            <tbody>${stratRows}</tbody>
          </table>
        </div>` : ''}

        <!-- CTA -->
        <div style="padding:32px;text-align:center">
          <a href="${frontendUrl}/app" style="background:#00d4ff;color:#06080d;padding:14px 36px;border-radius:10px;text-decoration:none;font-weight:800;font-size:14px;display:inline-block;letter-spacing:-0.3px">
            Open Quantario
          </a>
          <div style="font-size:11px;color:#8a94a6;margin-top:20px">
            You're receiving this because you clicked "Send Weekly Summary" in Quantario.<br>
            <a href="${frontendUrl}" style="color:#8a94a6">Quantario Trading Journal</a>
          </div>
        </div>
      </div>`;

    await mailer.sendMail({
      from:    process.env.SMTP_FROM || `Quantario <${process.env.SMTP_USER}>`,
      to:      `${user.name} <${user.email}>`,
      subject: `📊 Your week: ${pnlSign}$${Math.abs(totalPnL).toFixed(2)} · ${winRate}% win rate`,
      html,
    });

    res.json({ success: true, message: 'Weekly summary sent to your email!' });
  } catch (err) {
    console.error('[EMAIL] Weekly summary failed:', err);
    res.status(500).json({ success: false, error: safeErr(err) });
  }
});

module.exports = router;
