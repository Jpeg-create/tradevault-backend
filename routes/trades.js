const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { dbAll, dbRun, dbGet } = require('../db/database');

router.get('/', (req, res) => {
  try {
    const { asset_type, direction } = req.query;
    let query = 'SELECT * FROM trades WHERE 1=1';
    const params = [];
    if (asset_type && asset_type !== 'all') { query += ' AND asset_type = ?'; params.push(asset_type); }
    if (direction  && direction  !== 'all') { query += ' AND direction = ?';  params.push(direction); }
    query += ' ORDER BY created_at DESC';
    const trades = dbAll(query, params);
    res.json({ success: true, data: trades, count: trades.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/stats/summary', (req, res) => {
  try {
    const trades = dbAll('SELECT * FROM trades');
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
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/:id', (req, res) => {
  try {
    const trade = dbGet('SELECT * FROM trades WHERE id = ?', [req.params.id]);
    if (!trade) return res.status(404).json({ success: false, error: 'Trade not found' });
    res.json({ success: true, data: trade });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/', (req, res) => {
  try {
    const { symbol, asset_type='stock', direction='long', entry_price, exit_price, quantity,
      entry_date, exit_date, stop_loss, take_profit, strategy, notes,
      commission=0, market_conditions, broker='manual', broker_trade_id } = req.body;
    if (!symbol || entry_price==null || exit_price==null || quantity==null)
      return res.status(400).json({ success: false, error: 'symbol, entry_price, exit_price, quantity required' });
    const pnl = (parseFloat(exit_price)-parseFloat(entry_price))*parseFloat(quantity)*(direction==='short'?-1:1)-parseFloat(commission||0);
    const id = uuidv4();
    dbRun(`INSERT INTO trades (id,symbol,asset_type,direction,entry_price,exit_price,quantity,entry_date,exit_date,stop_loss,take_profit,strategy,notes,commission,market_conditions,pnl,broker,broker_trade_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [id,symbol.toUpperCase(),asset_type,direction,entry_price,exit_price,quantity,entry_date||null,exit_date||null,stop_loss||null,take_profit||null,strategy||null,notes||null,commission,market_conditions||null,parseFloat(pnl.toFixed(8)),broker,broker_trade_id||null]);
    const trade = dbGet('SELECT * FROM trades WHERE id = ?', [id]);
    res.status(201).json({ success: true, data: trade });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/bulk', (req, res) => {
  try {
    const { trades } = req.body;
    if (!Array.isArray(trades)||!trades.length) return res.status(400).json({ success: false, error: 'trades array required' });
    trades.forEach(t => {
      const pnl = t.pnl!=null ? t.pnl : (parseFloat(t.exit_price)-parseFloat(t.entry_price))*parseFloat(t.quantity)*(t.direction==='short'?-1:1)-parseFloat(t.commission||0);
      dbRun(`INSERT OR IGNORE INTO trades (id,symbol,asset_type,direction,entry_price,exit_price,quantity,entry_date,exit_date,stop_loss,take_profit,strategy,notes,commission,market_conditions,pnl,broker,broker_trade_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [t.id||uuidv4(),(t.symbol||'').toUpperCase(),t.asset_type||'stock',t.direction||'long',t.entry_price,t.exit_price,t.quantity,t.entry_date||null,t.exit_date||null,t.stop_loss||null,t.take_profit||null,t.strategy||null,t.notes||null,t.commission||0,t.market_conditions||null,parseFloat(parseFloat(pnl).toFixed(8)),t.broker||'manual',t.broker_trade_id||null]);
    });
    res.status(201).json({ success: true, inserted: trades.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.put('/:id', (req, res) => {
  try {
    const existing = dbGet('SELECT * FROM trades WHERE id = ?', [req.params.id]);
    if (!existing) return res.status(404).json({ success: false, error: 'Trade not found' });
    const f = { ...existing, ...req.body };
    const pnl = (parseFloat(f.exit_price)-parseFloat(f.entry_price))*parseFloat(f.quantity)*(f.direction==='short'?-1:1)-parseFloat(f.commission||0);
    dbRun(`UPDATE trades SET symbol=?,asset_type=?,direction=?,entry_price=?,exit_price=?,quantity=?,entry_date=?,exit_date=?,stop_loss=?,take_profit=?,strategy=?,notes=?,commission=?,market_conditions=?,pnl=? WHERE id=?`,
      [f.symbol,f.asset_type,f.direction,f.entry_price,f.exit_price,f.quantity,f.entry_date,f.exit_date,f.stop_loss,f.take_profit,f.strategy,f.notes,f.commission,f.market_conditions,parseFloat(pnl.toFixed(8)),req.params.id]);
    res.json({ success: true, data: dbGet('SELECT * FROM trades WHERE id = ?', [req.params.id]) });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.delete('/:id', (req, res) => {
  try {
    const existing = dbGet('SELECT id FROM trades WHERE id = ?', [req.params.id]);
    if (!existing) return res.status(404).json({ success: false, error: 'Trade not found' });
    dbRun('DELETE FROM trades WHERE id = ?', [req.params.id]);
    res.json({ success: true, message: 'Trade deleted' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

module.exports = router;
