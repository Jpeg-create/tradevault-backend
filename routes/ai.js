const express = require('express');
const router  = express.Router();
const { requireAuth, requirePremium } = require('../middleware/auth');
const { dbAll } = require('../db/database');

router.use(requireAuth);
router.use(requirePremium);

// ── ANTHROPIC STREAMING HELPER ────────────────────────────
async function streamClaude(system, userPrompt, res) {
  const apiKey = process.env.ANTHROPIC_API_KEY;

  if (!apiKey) {
    res.write(`data: ${JSON.stringify({ error: 'AI not configured — set ANTHROPIC_API_KEY in environment.' })}\n\n`);
    res.write('data: [DONE]\n\n');
    res.end();
    return;
  }

  let anthropicRes;
  try {
    anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':    'application/json',
        'x-api-key':       apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      'claude-sonnet-4-20250514',
        max_tokens: 1024,
        stream:     true,
        system,
        messages: [{ role: 'user', content: userPrompt }],
      }),
    });
  } catch (err) {
    res.write(`data: ${JSON.stringify({ error: 'Could not reach AI service.' })}\n\n`);
    res.write('data: [DONE]\n\n');
    res.end();
    return;
  }

  if (!anthropicRes.ok) {
    const body = await anthropicRes.text().catch(() => '');
    console.error('[AI] Anthropic error:', anthropicRes.status, body);
    res.write(`data: ${JSON.stringify({ error: 'AI service error. Please try again.' })}\n\n`);
    res.write('data: [DONE]\n\n');
    res.end();
    return;
  }

  const reader  = anthropicRes.body.getReader();
  const decoder = new TextDecoder();
  let   buffer  = '';

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop(); // hold incomplete line

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const raw = line.slice(6).trim();
        if (!raw) continue;
        try {
          const event = JSON.parse(raw);
          if (event.type === 'content_block_delta' && event.delta?.type === 'text_delta' && event.delta.text) {
            res.write(`data: ${JSON.stringify({ text: event.delta.text })}\n\n`);
          }
        } catch { /* ignore malformed SSE lines */ }
      }
    }
  } catch (err) {
    console.error('[AI] Stream read error:', err.message);
  }

  res.write('data: [DONE]\n\n');
  res.end();
}

function sseHeaders(res) {
  res.writeHead(200, {
    'Content-Type':  'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection':    'keep-alive',
    'X-Accel-Buffering': 'no', // disable Nginx buffering on Render
  });
}

// ── HELPER: build trade stats summary ────────────────────
function buildTradeStats(trades) {
  if (!trades.length) return null;

  const wins   = trades.filter(t => Number(t.pnl) > 0);
  const losses = trades.filter(t => Number(t.pnl) < 0);
  const winRate = ((wins.length / trades.length) * 100).toFixed(1);
  const avgWin  = wins.length   ? (wins.reduce((s,t)   => s + Number(t.pnl), 0) / wins.length).toFixed(2)   : '0';
  const avgLoss = losses.length ? Math.abs(losses.reduce((s,t) => s + Number(t.pnl), 0) / losses.length).toFixed(2) : '0';

  // Win rate by strategy
  const byStrategy = {};
  trades.forEach(t => {
    const k = t.strategy || 'Untagged';
    if (!byStrategy[k]) byStrategy[k] = { wins: 0, total: 0, pnl: 0 };
    byStrategy[k].total++;
    byStrategy[k].pnl += Number(t.pnl);
    if (Number(t.pnl) > 0) byStrategy[k].wins++;
  });

  // Win rate by day of week
  const byDay = { Mon:[], Tue:[], Wed:[], Thu:[], Fri:[], Sat:[], Sun:[] };
  const dayNames = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  trades.forEach(t => {
    if (!t.exit_date) return;
    const day = dayNames[new Date(t.exit_date).getDay()];
    byDay[day].push(Number(t.pnl));
  });

  // Win rate by asset
  const byAsset = {};
  trades.forEach(t => {
    if (!byAsset[t.asset_type]) byAsset[t.asset_type] = { wins: 0, total: 0 };
    byAsset[t.asset_type].total++;
    if (Number(t.pnl) > 0) byAsset[t.asset_type].wins++;
  });

  // Consecutive loss streaks
  let maxConsecLosses = 0, cur = 0;
  [...trades].reverse().forEach(t => {
    if (Number(t.pnl) < 0) { cur++; maxConsecLosses = Math.max(maxConsecLosses, cur); }
    else cur = 0;
  });

  return { winRate, avgWin, avgLoss, byStrategy, byDay, byAsset, maxConsecLosses };
}

// ── POST /api/ai/debrief ──────────────────────────────────
router.post('/debrief', async (req, res) => {
  try {
    const { trade } = req.body;
    if (!trade) return res.status(400).json({ success: false, error: 'trade object required' });

    const allTrades = dbAll('SELECT * FROM trades WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
    const stats     = buildTradeStats(allTrades);
    const pnl       = Number(trade.pnl);

    const stratLine = trade.strategy && stats?.byStrategy[trade.strategy]
      ? `My "${trade.strategy}" strategy: ${((stats.byStrategy[trade.strategy].wins / stats.byStrategy[trade.strategy].total) * 100).toFixed(0)}% win rate across ${stats.byStrategy[trade.strategy].total} trade(s).`
      : '';

    const userPrompt = `
Here is a trade I just completed:
• Symbol: ${trade.symbol} | Direction: ${trade.direction} | Asset: ${trade.asset_type}
• Entry: $${trade.entry_price}  →  Exit: $${trade.exit_price}  |  Qty: ${trade.quantity}
• P&L: ${pnl >= 0 ? '+' : ''}$${pnl.toFixed(2)}
• Strategy: ${trade.strategy || 'Not tagged'}
• Market conditions: ${trade.market_conditions || 'Not noted'}
• My notes: ${trade.notes || 'None'}

My overall stats across ${allTrades.length} trade(s):
• Win Rate: ${stats?.winRate ?? '—'}%  |  Avg Win: $${stats?.avgWin ?? '0'}  |  Avg Loss: $${stats?.avgLoss ?? '0'}
${stratLine}

Please give me a trade debrief. Be specific to my numbers. Keep it to 3–4 sentences.
`.trim();

    const system = `You are a supportive trading mentor. You give honest, constructive feedback that helps traders improve. Always reference the trader's actual numbers. Be warm but direct. End every debrief with one clear, actionable takeaway prefixed with "💡 Takeaway:".`;

    sseHeaders(res);
    await streamClaude(system, userPrompt, res);
  } catch (err) {
    console.error('[AI /debrief]', err.message);
    if (!res.headersSent) res.status(500).json({ success: false, error: 'AI service unavailable' });
  }
});

// ── POST /api/ai/patterns ─────────────────────────────────
router.post('/patterns', async (req, res) => {
  try {
    const allTrades = dbAll('SELECT * FROM trades WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);

    if (allTrades.length < 3) {
      return res.status(400).json({ success: false, error: 'Log at least 3 trades to unlock pattern analysis.' });
    }

    const stats = buildTradeStats(allTrades);

    // Format day stats
    const dayStats = Object.entries(stats.byDay)
      .filter(([, arr]) => arr.length > 0)
      .map(([day, pnls]) => {
        const w = pnls.filter(p => p > 0).length;
        return `${day}: ${w}/${pnls.length} wins (${((w/pnls.length)*100).toFixed(0)}% WR), net $${pnls.reduce((a,b)=>a+b,0).toFixed(2)}`;
      }).join('\n');

    // Format strategy stats
    const stratStats = Object.entries(stats.byStrategy)
      .sort((a,b) => b[1].pnl - a[1].pnl)
      .map(([k, v]) => `"${k}": ${v.total} trades, ${((v.wins/v.total)*100).toFixed(0)}% WR, net $${v.pnl.toFixed(2)}`)
      .join('\n');

    // Format asset stats
    const assetStats = Object.entries(stats.byAsset)
      .map(([k, v]) => `${k}: ${v.total} trades, ${((v.wins/v.total)*100).toFixed(0)}% WR`)
      .join('\n');

    const userPrompt = `
Here is my complete trading data summary (${allTrades.length} trades):

Overall: Win Rate ${stats.winRate}%  |  Avg Win $${stats.avgWin}  |  Avg Loss $${stats.avgLoss}  |  Max consecutive losses: ${stats.maxConsecLosses}

Performance by day of week:
${dayStats || 'Not enough data'}

Performance by strategy:
${stratStats || 'Trades not tagged with strategies'}

Performance by asset class:
${assetStats || 'Not enough data'}

Find me 4 meaningful patterns — both strengths and weaknesses. Be specific with the numbers.
`.trim();

    const system = `You are a quantitative trading analyst and supportive mentor. Analyse the trader's data and surface 4 specific, actionable insights. Format each insight as:
[emoji] **Title** — one sentence explanation with specific numbers.

Use ✅ for clear strengths, ⚠️ for weaknesses or risks, 💡 for opportunities, and 🔄 for behavioral patterns. Reference exact percentages and dollar amounts from the data. Be concise and specific — no generic trading advice.`;

    sseHeaders(res);
    await streamClaude(system, userPrompt, res);
  } catch (err) {
    console.error('[AI /patterns]', err.message);
    if (!res.headersSent) res.status(500).json({ success: false, error: 'AI service unavailable' });
  }
});

// ── POST /api/ai/journal-draft ────────────────────────────
router.post('/journal-draft', async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];

    // Get today's trades
    const todayTrades = dbAll(
      `SELECT * FROM trades WHERE user_id = ? AND date(exit_date) = ? ORDER BY exit_date ASC`,
      [req.user.id, today]
    );

    if (!todayTrades.length) {
      return res.status(400).json({ success: false, error: "No trades found for today yet." });
    }

    const totalPnL  = todayTrades.reduce((s,t) => s + Number(t.pnl), 0);
    const wins      = todayTrades.filter(t => Number(t.pnl) > 0).length;
    const losses    = todayTrades.filter(t => Number(t.pnl) < 0).length;
    const tradeList = todayTrades.map(t =>
      `• ${t.symbol} ${t.direction} — Entry $${t.entry_price} → Exit $${t.exit_price} — P&L: ${Number(t.pnl) >= 0 ? '+' : ''}$${Number(t.pnl).toFixed(2)}${t.strategy ? ` — Strategy: ${t.strategy}` : ''}${t.notes ? ` — Notes: "${t.notes}"` : ''}`
    ).join('\n');

    const existing = req.body.existingText || '';

    const userPrompt = `
Today's trading session (${today}):
Total P&L: ${totalPnL >= 0 ? '+' : ''}$${totalPnL.toFixed(2)}  |  ${wins} win(s), ${losses} loss(es)

Trades:
${tradeList}

${existing ? `I've already started writing: "${existing}"\n\nPlease continue or expand on what I've written.` : 'Please draft a journal entry for me.'}
`.trim();

    const system = `You are helping a trader write their daily trading journal entry. Write in first person, past tense. Be specific about each trade — mention symbols, direction, and P&L. Reflect on what went well, what could improve, and the emotional side of the session. Keep it between 100–180 words. End with one introspective question to prompt deeper reflection. Do not use bullet points — write in natural paragraphs.`;

    sseHeaders(res);
    await streamClaude(system, userPrompt, res);
  } catch (err) {
    console.error('[AI /journal-draft]', err.message);
    if (!res.headersSent) res.status(500).json({ success: false, error: 'AI service unavailable' });
  }
});

module.exports = router;
