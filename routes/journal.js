const express = require('express');
const router  = express.Router();
const { v4: uuidv4 } = require('uuid');
const { dbAll, dbRun, dbGet } = require('../db/database');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

const safeErr = err =>
  process.env.NODE_ENV !== 'production' ? err.message : 'Server error';

router.get('/', async (req, res) => {
  try {
    const entries = await dbAll(
      'SELECT * FROM journal_entries WHERE user_id = ? ORDER BY entry_date DESC',
      [req.user.id]
    );
    res.json({ success: true, data: entries });
  } catch (err) { res.status(500).json({ success: false, error: safeErr(err) }); }
});

router.post('/', async (req, res) => {
  try {
    const { entry_date, content } = req.body;
    if (!entry_date || !content)
      return res.status(400).json({ success: false, error: 'entry_date and content required' });
    if (content.length > 10000)
      return res.status(400).json({ success: false, error: 'Journal entry must be 10,000 characters or less' });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(entry_date))
      return res.status(400).json({ success: false, error: 'entry_date must be YYYY-MM-DD format' });

    const id = uuidv4();
    await dbRun('INSERT INTO journal_entries (id, user_id, entry_date, content) VALUES (?, ?, ?, ?)',
      [id, req.user.id, entry_date, content]);
    const entry = await dbGet('SELECT * FROM journal_entries WHERE id = ?', [id]);
    res.status(201).json({ success: true, data: entry });
  } catch (err) { res.status(500).json({ success: false, error: safeErr(err) }); }
});

router.delete('/:id', async (req, res) => {
  try {
    const existing = await dbGet('SELECT id FROM journal_entries WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]);
    if (!existing) return res.status(404).json({ success: false, error: 'Entry not found' });
    await dbRun('DELETE FROM journal_entries WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.json({ success: true, message: 'Entry deleted' });
  } catch (err) { res.status(500).json({ success: false, error: safeErr(err) }); }
});

module.exports = router;
