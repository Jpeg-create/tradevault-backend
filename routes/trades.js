const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { dbAll, dbRun, dbGet } = require('../db/database');
const { requireAuth } = require('../middleware/auth');

// All trade routes require auth
router.use(requireAuth);

router.get('/', (req, res) => {
  try {
    const { asset_type, direction } = req.query;
    let query = 'SELECT * FROM trades WHERE user_id = ?';
    const params = [req.user.id];
    if (asset_type && asset_type !== 'all') { query += ' AND asset_type = ?'; params.push(asset_type); }
    if (direction  && direction  !== 'all') { query += ' AND direction = ?';  params.push(direction); }
    query += ' ORDER BY created_at DESC';
    const trades = dbAll(query, params);
    res.json({ success: true, data: trades, count: trades.length });
  } catch (err) { res.status(500).json({ success: false, error: process.env.NODE_ENV !== 'production' ? err.message : 'Server error' }); }
});

router.get('/stats/summary', (req, res) => {
  try {
    const trades = dbAll('SELECT * FROM trades WHERE user_id = ?', [req.user.id]);
    const winning = trades.filter(t => t.pnl > 0);
    const losing  = trades.filter(t => t.pnl < 0);
    const totalPnL    = trades.reduce((s, t) => s + Number(t.pnl), 0);
    const totalWins   = winning.reduce((s, t) => s + Number(t.pnl), 0);
    const totalLosses = Math.abs(losing.reduce((s, t) => s + Number(t.pnl), 0));
    const avgWin  = winning.length ? totalWins / winning.length : 0;
    const avgLoss = losing.length  ? totalLosses / losing.length : 0;
    res.json({ success: true, data: {
      totalTrades: trades.length, totalPnL: parseFloat(totalPnL.toFixed(2)),
      winningTrades: winning.length, losingTrades: losing.length,
      winRate: trades.length ? parseFloat(((winning.length/trades.length)*100).toFixed(1)) : 0,
      avgWin: parseFloat(avgWin.toFixed(2)), avgLoss: parseFloat(avgLoss.toFixed(2)),
      profitFactor: totalLosses > 0 ? parseFloat((totalWins/totalLosses).toFixed(2)) : null,
      rMultiple: avgLoss > 0 ? parseFloat((avgWin/avgLoss).toFixed(2)) : null
    }});
  } catch (err) { res.status(500).json({ success: false, error: process.env.NODE_ENV !== 'production' ? err.message : 'Server error' }); }
});

router.get('/:id', (req, res) => {
  try {
    const trade = dbGet('SELECT * FROM trades WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!trade) return res.status(404).json({ success: false, error: 'Trade not found' });
    res.json({ success: true, data: trade });
  } catch (err) { res.status(500).json({ success: false, error: process.env.NODE_ENV !== 'production' ? err.message : 'Server error' }); }
});

router.post('/', (req, res) => {
  try {
    const { symbol, asset_type='stock', direction='long', entry_price, exit_price, quantity,
      entry_date, exit_date, stop_loss, take_profit, strategy, notes,
      commission=0, market_conditions, broker='manual', broker_trade_id } = req.body;
    if (!symbol || entry_price==null || exit_price==null || quantity==null)
      return res.status(400).json({ success: false, error: 'symbol, entry_price, exit_price, quantity required' });
    if (symbol.length > 20)
      return res.status(400).json({ success: false, error: 'Symbol must be 20 characters or less' });
    if (strategy && strategy.length > 200)
      return res.status(400).json({ success: false, error: 'Strategy name must be 200 characters or less' });
    if (notes && notes.length > 5000)
      return res.status(400).json({ success: false, error: 'Notes must be 5000 characters or less' });
    if (isNaN(parseFloat(entry_price)) || isNaN(parseFloat(exit_price)) || isNaN(parseFloat(quantity)))
      return res.status(400).json({ success: false, error: 'Prices and quantity must be valid numbers' });
    if (parseFloat(quantity) <= 0)
      return res.status(400).json({ success: false, error: 'Quantity must be greater than zero' });
    const pnl = (parseFloat(exit_price)-parseFloat(entry_price))*parseFloat(quantity)*(direction==='short'?-1:1)-parseFloat(commission||0);
    const id = uuidv4();
    dbRun(`INSERT INTO trades (id,user_id,symbol,asset_type,direction,entry_price,exit_price,quantity,entry_date,exit_date,stop_loss,take_profit,strategy,notes,commission,market_conditions,pnl,broker,broker_trade_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [id,req.user.id,symbol.toUpperCase(),asset_type,direction,entry_price,exit_price,quantity,entry_date||null,exit_date||null,stop_loss||null,take_profit||null,strategy||null,notes||null,commission,market_conditions||null,parseFloat(pnl.toFixed(8)),broker,broker_trade_id||null]);
    res.status(201).json({ success: true, data: dbGet('SELECT * FROM trades WHERE id = ?', [id]) });
  } catch (err) { res.status(500).json({ success: false, error: process.env.NODE_ENV !== 'production' ? err.message : 'Server error' }); }
});

router.post('/bulk', (req, res) => {
  try {
    const { trades } = req.body;
    if (!Array.isArray(trades) || !trades.length)
      return res.status(400).json({ success: false, error: 'trades array required' });
    if (trades.length > 500)
      return res.status(400).json({ success: false, error: 'Bulk import is limited to 500 trades per request' });
    trades.forEach(t => {
      const pnl = t.pnl!=null ? t.pnl : (parseFloat(t.exit_price)-parseFloat(t.entry_price))*parseFloat(t.quantity)*(t.direction==='short'?-1:1)-parseFloat(t.commission||0);
      dbRun(`INSERT OR IGNORE INTO trades (id,user_id,symbol,asset_type,direction,entry_price,exit_price,quantity,entry_date,exit_date,stop_loss,take_profit,strategy,notes,commission,market_conditions,pnl,broker,broker_trade_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [t.id||uuidv4(),req.user.id,(t.symbol||'').toUpperCase(),t.asset_type||'stock',t.direction||'long',t.entry_price,t.exit_price,t.quantity,t.entry_date||null,t.exit_date||null,t.stop_loss||null,t.take_profit||null,t.strategy||null,t.notes||null,t.commission||0,t.market_conditions||null,parseFloat(parseFloat(pnl).toFixed(8)),t.broker||'manual',t.broker_trade_id||null]);
    });
    res.status(201).json({ success: true, inserted: trades.length });
  } catch (err) { res.status(500).json({ success: false, error: process.env.NODE_ENV !== 'production' ? err.message : 'Server error' }); }
});

router.put('/:id', (req, res) => {
  try {
    const existing = dbGet('SELECT * FROM trades WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!existing) return res.status(404).json({ success: false, error: 'Trade not found' });

    // Whitelist: only allow these fields to be updated — never accept id, user_id, pnl, broker_trade_id from client
    const ALLOWED_FIELDS = [
      'symbol', 'asset_type', 'direction', 'entry_price', 'exit_price', 'quantity',
      'entry_date', 'exit_date', 'stop_loss', 'take_profit', 'strategy', 'notes',
      'commission', 'market_conditions', 'broker',
    ];
    const patch = {};
    for (const key of ALLOWED_FIELDS) {
      if (req.body[key] !== undefined) patch[key] = req.body[key];
    }
    const f = { ...existing, ...patch };

    if (isNaN(parseFloat(f.entry_price)) || isNaN(parseFloat(f.exit_price)) || isNaN(parseFloat(f.quantity)))
      return res.status(400).json({ success: false, error: 'Prices and quantity must be valid numbers' });
    if (parseFloat(f.quantity) <= 0)
      return res.status(400).json({ success: false, error: 'Quantity must be greater than zero' });

    const pnl = (parseFloat(f.exit_price) - parseFloat(f.entry_price)) * parseFloat(f.quantity) * (f.direction === 'short' ? -1 : 1) - parseFloat(f.commission || 0);
    dbRun(
      `UPDATE trades SET symbol=?,asset_type=?,direction=?,entry_price=?,exit_price=?,quantity=?,entry_date=?,exit_date=?,stop_loss=?,take_profit=?,strategy=?,notes=?,commission=?,market_conditions=?,pnl=? WHERE id=? AND user_id=?`,
      [f.symbol, f.asset_type, f.direction, f.entry_price, f.exit_price, f.quantity, f.entry_date, f.exit_date, f.stop_loss, f.take_profit, f.strategy, f.notes, f.commission, f.market_conditions, parseFloat(pnl.toFixed(8)), req.params.id, req.user.id]
    );
    res.json({ success: true, data: dbGet('SELECT * FROM trades WHERE id = ?', [req.params.id]) });
  } catch (err) { res.status(500).json({ success: false, error: process.env.NODE_ENV !== 'production' ? err.message : 'Server error' }); }
});

router.delete('/:id', (req, res) => {
  try {
    const existing = dbGet('SELECT id FROM trades WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!existing) return res.status(404).json({ success: false, error: 'Trade not found' });
    dbRun('DELETE FROM trades WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.json({ success: true, message: 'Trade deleted' });
  } catch (err) { res.status(500).json({ success: false, error: process.env.NODE_ENV !== 'production' ? err.message : 'Server error' }); }
});

module.exports = router;
