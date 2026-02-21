const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { dbAll, dbRun, dbGet } = require('../db/database');

router.get('/', (req, res) => {
  try { res.json({ success: true, data: dbAll('SELECT * FROM journal_entries ORDER BY entry_date DESC') }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/', (req, res) => {
  try {
    const { entry_date, content } = req.body;
    if (!entry_date || !content) return res.status(400).json({ success: false, error: 'entry_date and content required' });
    const id = uuidv4();
    dbRun('INSERT INTO journal_entries (id, entry_date, content) VALUES (?, ?, ?)', [id, entry_date, content]);
    res.status(201).json({ success: true, data: dbGet('SELECT * FROM journal_entries WHERE id = ?', [id]) });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.put('/:id', (req, res) => {
  try {
    const { entry_date, content } = req.body;
    const existing = dbGet('SELECT id FROM journal_entries WHERE id = ?', [req.params.id]);
    if (!existing) return res.status(404).json({ success: false, error: 'Entry not found' });
    dbRun('UPDATE journal_entries SET entry_date=?, content=? WHERE id=?', [entry_date, content, req.params.id]);
    res.json({ success: true, data: dbGet('SELECT * FROM journal_entries WHERE id = ?', [req.params.id]) });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.delete('/:id', (req, res) => {
  try {
    const existing = dbGet('SELECT id FROM journal_entries WHERE id = ?', [req.params.id]);
    if (!existing) return res.status(404).json({ success: false, error: 'Entry not found' });
    dbRun('DELETE FROM journal_entries WHERE id = ?', [req.params.id]);
    res.json({ success: true, message: 'Entry deleted' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

module.exports = router;
