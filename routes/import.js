const express = require('express');
const router  = express.Router();
const multer  = require('multer');
const { v4: uuidv4 } = require('uuid');
const { dbRun, dbGet } = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const path = require('path');
const fs   = require('fs');

router.use(requireAuth);

const safeErr = err =>
  process.env.NODE_ENV !== 'production' ? err.message : 'Server error';

const uploadDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
  fileFilter: (req, file, cb) => {
    // Check both extension AND MIME type
    const validExt  = file.originalname.toLowerCase().endsWith('.csv');
    const validMime = ['text/csv', 'text/plain', 'application/csv', 'application/vnd.ms-excel'].includes(file.mimetype);
    if (!validExt || !validMime) {
      const err = new Error('Only CSV files are allowed');
      err.status = 400;
      return cb(err);
    }
    cb(null, true);
  },
});

const MAX_ROWS = 5000; // cap per import

// ── CSV COLUMN ALIASES ────────────────────────────────────
const ALIASES = {
  ticker:'symbol', name:'symbol', instrument:'symbol',
  type:'asset_type', class:'asset_type',
  side:'direction', action:'direction',
  entry:'entry_price', open:'entry_price', open_price:'entry_price',
  exit:'exit_price',  close:'exit_price', close_price:'exit_price',
  qty:'quantity', size:'quantity', units:'quantity', shares:'quantity', lots:'quantity',
  entry_time:'entry_date', open_date:'entry_date',
  exit_time:'exit_date',   close_date:'exit_date',
  sl:'stop_loss', stoploss:'stop_loss',
  tp:'take_profit', takeprofit:'take_profit',
  fee:'commission', fees:'commission',
  note:'notes', comment:'notes',
};
const DIR_MAP   = { buy:'long', sell:'short', b:'long', s:'short', long:'long', short:'short' };
const ASSET_MAP = { equities:'stock', equity:'stock', shares:'stock', fx:'forex', currency:'forex',
                    coin:'crypto', cryptocurrency:'crypto', future:'futures', option:'options' };

function parseCSVLine(line) {
  const r = []; let c = '', q = false;
  for (const ch of line) {
    if (ch === '"') q = !q;
    else if (ch === ',' && !q) { r.push(c); c = ''; }
    else c += ch;
  }
  r.push(c);
  return r;
}

function parseCSVText(text) {
  const lines = text.trim().split('\n').filter(l => l.trim());
  if (lines.length < 2) throw new Error('CSV needs a header row plus at least one data row');
  if (lines.length > MAX_ROWS + 1)
    throw new Error(`CSV has too many rows (max ${MAX_ROWS}). Split into smaller files.`);

  // Use parseCSVLine for headers too — handles quoted headers with commas
  const headers = parseCSVLine(lines[0]).map(h => {
    const k = h.trim().toLowerCase().replace(/\s+/g, '_').replace(/[^a-z_]/g, '');
    return ALIASES[k] || k;
  });

  return lines.slice(1).map(line => {
    const vals = parseCSVLine(line);
    const row  = {};
    headers.forEach((h, i) => row[h] = (vals[i] || '').trim());
    row.direction  = DIR_MAP[row.direction?.toLowerCase()]   || 'long';
    row.asset_type = ASSET_MAP[row.asset_type?.toLowerCase()] || row.asset_type?.toLowerCase() || 'stock';
    const clean = v => parseFloat((v || '').replace(/[$,]/g, ''));
    row.entry_price = clean(row.entry_price);
    row.exit_price  = clean(row.exit_price);
    row.quantity    = clean(row.quantity);
    row.commission  = clean(row.commission) || 0;
    const errors = [];
    if (!row.symbol)               errors.push('missing symbol');
    if (isNaN(row.entry_price))    errors.push('invalid entry_price');
    if (isNaN(row.exit_price))     errors.push('invalid exit_price');
    if (isNaN(row.quantity))       errors.push('invalid quantity');
    if (row.quantity <= 0 && !errors.includes('invalid quantity')) errors.push('quantity must be > 0');
    if (!errors.length) {
      row.pnl = parseFloat(((row.exit_price - row.entry_price) *
        row.quantity * (row.direction === 'short' ? -1 : 1) - row.commission).toFixed(8));
    } else {
      row._error = errors.join(', ');
    }
    return row;
  });
}

// ── POST /preview ─────────────────────────────────────────
router.post('/preview', upload.single('file'), (req, res) => {
  const filePath = req.file?.path;
  try {
    if (!filePath) return res.status(400).json({ success: false, error: 'No file uploaded' });
    const text = fs.readFileSync(filePath, 'utf8');
    const rows = parseCSVText(text);
    res.json({ success: true, data: {
      total:  rows.length,
      valid:  rows.filter(r => !r._error).length,
      errors: rows.filter(r => r._error).length,
      rows,
    }});
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  } finally {
    // Always clean up temp file — whether success or error
    if (filePath && fs.existsSync(filePath)) {
      try { fs.unlinkSync(filePath); } catch {}
    }
  }
});

// ── POST /confirm ─────────────────────────────────────────
router.post('/confirm', async (req, res) => {
  try {
    const rawRows  = Array.isArray(req.body.rows) ? req.body.rows : [];
    const validRows = rawRows.filter(r => !r._error).slice(0, MAX_ROWS);
    if (!validRows.length)
      return res.status(400).json({ success: false, error: 'No valid rows to import' });

    let imported = 0;
    for (const t of validRows) {
      const sym = String(t.symbol || '').toUpperCase().slice(0, 20);
      if (!sym) continue;
      const direction  = t.direction || 'long';
      const entryPrice = parseFloat(t.entry_price) || 0;
      const exitPrice  = parseFloat(t.exit_price) || 0;
      const quantity   = parseFloat(t.quantity) || 0;
      const entryDate  = t.entry_date || null;
      const exitDate   = t.exit_date || null;

      const existing = await dbGet(
        `SELECT id FROM trades
         WHERE user_id = ?
           AND broker = 'csv_import'
           AND symbol = ?
           AND direction = ?
           AND entry_price = ?
           AND exit_price = ?
           AND quantity = ?
           AND COALESCE(entry_date, '') = COALESCE(?, '')
           AND COALESCE(exit_date, '') = COALESCE(?, '')
         LIMIT 1`,
        [req.user.id, sym, direction, entryPrice, exitPrice, quantity, entryDate, exitDate]
      );
      if (existing) continue;

      const pnl = parseFloat(t.pnl) || 0;
      const changes = await dbRun(
        `INSERT INTO trades
          (id,user_id,symbol,asset_type,direction,entry_price,exit_price,quantity,
           entry_date,exit_date,stop_loss,take_profit,strategy,notes,commission,
           market_conditions,pnl,broker)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT (id) DO NOTHING`,
        [uuidv4(), req.user.id, sym,
         t.asset_type || 'stock', direction,
         entryPrice, exitPrice, quantity,
         entryDate, exitDate,
         parseFloat(t.stop_loss)  || null, parseFloat(t.take_profit) || null,
         t.strategy    ? String(t.strategy).slice(0, 200)  : null,
         t.notes       ? String(t.notes).slice(0, 5000)    : null,
         parseFloat(t.commission) || 0,
         t.market_conditions ? String(t.market_conditions).slice(0, 500) : null,
         parseFloat(pnl.toFixed(8)), 'csv_import']
      );
      if (changes > 0) imported += 1;
    }
    res.json({ success: true, imported });
  } catch (err) { res.status(500).json({ success: false, error: safeErr(err) }); }
});

// ── GET /sample ───────────────────────────────────────────
router.get('/sample', (req, res) => {
  const csv = [
    'symbol,asset_type,direction,entry_price,exit_price,quantity,entry_date,exit_date,strategy,commission',
    'AAPL,stock,long,178.50,182.30,100,2025-01-10,2025-01-10,Breakout,2.00',
    'EUR/USD,forex,short,1.0850,1.0790,10000,2025-01-11,2025-01-11,Trend,0.00',
  ].join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="quantario-sample.csv"');
  res.send(csv);
});

module.exports = router;
