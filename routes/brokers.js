const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { dbAll, dbRun, dbGet } = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const { fetchTradesFromBroker } = require('../services/brokerService');

const safeErr = err =>
  process.env.NODE_ENV !== 'production' ? err.message : 'Server error';

router.use(requireAuth);

router.get('/', async (req, res) => {
  try {
    const brokers = await dbAll(
      'SELECT id, broker_name, account_id, is_active, last_sync, created_at FROM broker_connections WHERE user_id = ?',
      [req.user.id]
    );
    res.json({ success: true, data: brokers });
  } catch (err) { res.status(500).json({ success: false, error: safeErr(err) }); }
});

router.post('/', async (req, res) => {
  try {
    const { broker_name, api_key, api_secret, account_id } = req.body;
    if (!broker_name || !api_key)
      return res.status(400).json({ success: false, error: 'broker_name and api_key required' });
    const ALLOWED_BROKERS = ['alpaca', 'binance', 'metatrader'];
    if (!ALLOWED_BROKERS.includes(broker_name.toLowerCase()))
      return res.status(400).json({ success: false, error: 'Unsupported broker' });
    if (api_key.length > 256)
      return res.status(400).json({ success: false, error: 'API key too long' });
    const id = uuidv4();
    await dbRun(
      'INSERT INTO broker_connections (id, user_id, broker_name, api_key, api_secret, account_id) VALUES (?, ?, ?, ?, ?, ?)',
      [id, req.user.id, broker_name, api_key, api_secret||null, account_id||null]
    );
    res.status(201).json({ success: true, data: { id, broker_name, account_id } });
  } catch (err) { res.status(500).json({ success: false, error: safeErr(err) }); }
});

router.delete('/:id', async (req, res) => {
  try {
    const existing = await dbGet(
      'SELECT id FROM broker_connections WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (!existing) return res.status(404).json({ success: false, error: 'Broker connection not found' });
    await dbRun('DELETE FROM broker_connections WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: safeErr(err) }); }
});

router.post('/:id/sync', async (req, res) => {
  try {
    const broker = await dbGet(
      'SELECT * FROM broker_connections WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (!broker) return res.status(404).json({ success: false, error: 'Broker connection not found' });

    const trades = await fetchTradesFromBroker(broker);
    let inserted = 0;
    for (const t of trades) {
      const changes = await dbRun(
        `INSERT INTO trades (id,user_id,symbol,asset_type,direction,entry_price,exit_price,quantity,entry_date,exit_date,pnl,broker,broker_trade_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING`,
        [t.id||uuidv4(), req.user.id, t.symbol, t.asset_type||'stock', t.direction||'long',
         t.entry_price, t.exit_price, t.quantity, t.entry_date||null, t.exit_date||null,
         t.pnl, broker.broker_name, t.broker_trade_id||null]
      );
      if (changes > 0) inserted++;
    }

    await dbRun(
      `UPDATE broker_connections SET last_sync = ? WHERE id = ?`,
      [new Date().toISOString(), req.params.id]
    );

    res.json({ success: true, imported: inserted, message: `Synced ${inserted} new trade(s)` });
  } catch (err) { res.status(500).json({ success: false, error: safeErr(err) }); }
});

module.exports = router;
