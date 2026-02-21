const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { dbAll, dbRun, dbGet } = require('../db/database');
const { fetchTradesFromBroker } = require('../services/brokerService');

router.get('/', (req, res) => {
  try { res.json({ success: true, data: dbAll('SELECT id, broker_name, account_id, is_active, last_sync, created_at FROM broker_connections') }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/', (req, res) => {
  try {
    const { broker_name, api_key, api_secret, account_id } = req.body;
    if (!broker_name || !api_key) return res.status(400).json({ success: false, error: 'broker_name and api_key required' });
    const id = uuidv4();
    dbRun('INSERT INTO broker_connections (id, broker_name, api_key, api_secret, account_id) VALUES (?, ?, ?, ?, ?)', [id, broker_name, api_key, api_secret||null, account_id||null]);
    res.status(201).json({ success: true, data: { id, broker_name, account_id } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.delete('/:id', (req, res) => {
  try { dbRun('DELETE FROM broker_connections WHERE id = ?', [req.params.id]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/:id/sync', async (req, res) => {
  try {
    const conn = dbGet('SELECT * FROM broker_connections WHERE id = ?', [req.params.id]);
    if (!conn) return res.status(404).json({ success: false, error: 'Broker not found' });
    const rawTrades = await fetchTradesFromBroker(conn.broker_name, { api_key: conn.api_key, api_secret: conn.api_secret, account_id: conn.account_id, paper: req.body.paper||false });
    rawTrades.forEach(t => {
      const pnl = t.pnl || ((t.exit_price-t.entry_price)*t.quantity*(t.direction==='short'?-1:1)-(t.commission||0));
      dbRun(`INSERT OR IGNORE INTO trades (id,symbol,asset_type,direction,entry_price,exit_price,quantity,entry_date,exit_date,commission,broker,broker_trade_id,strategy,notes,pnl) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [uuidv4(),t.symbol,t.asset_type,t.direction,t.entry_price,t.exit_price,t.quantity,t.entry_date,t.exit_date,t.commission||0,t.broker,t.broker_trade_id,t.strategy||null,t.notes||null,parseFloat(pnl.toFixed(8))]);
    });
    dbRun("UPDATE broker_connections SET last_sync = datetime('now') WHERE id = ?", [req.params.id]);
    res.json({ success: true, imported: rawTrades.length, broker: conn.broker_name });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/test', async (req, res) => {
  try {
    const trades = await fetchTradesFromBroker(req.body.broker_name, req.body);
    res.json({ success: true, message: `Connected. Found ${trades.length} trades.` });
  } catch (err) { res.status(400).json({ success: false, error: err.message }); }
});

module.exports = router;
