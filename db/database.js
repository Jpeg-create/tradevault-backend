const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const dbPath = path.join(dataDir, 'tradevault.db');

let db;

async function initDB() {
  const SQL = await initSqlJs();

  if (fs.existsSync(dbPath)) {
    const fileBuffer = fs.readFileSync(dbPath);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.save = () => {
    const data = db.export();
    fs.writeFileSync(dbPath, Buffer.from(data));
  };

  db.run(`
    CREATE TABLE IF NOT EXISTS trades (
      id TEXT PRIMARY KEY, symbol TEXT NOT NULL,
      asset_type TEXT NOT NULL DEFAULT 'stock',
      direction TEXT NOT NULL DEFAULT 'long',
      entry_price REAL NOT NULL, exit_price REAL NOT NULL,
      quantity REAL NOT NULL, entry_date TEXT, exit_date TEXT,
      stop_loss REAL, take_profit REAL, strategy TEXT, notes TEXT,
      commission REAL DEFAULT 0, market_conditions TEXT,
      pnl REAL NOT NULL, broker TEXT DEFAULT 'manual',
      broker_trade_id TEXT, created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS journal_entries (
      id TEXT PRIMARY KEY, entry_date TEXT NOT NULL,
      content TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS broker_connections (
      id TEXT PRIMARY KEY, broker_name TEXT NOT NULL,
      api_key TEXT, api_secret TEXT, account_id TEXT,
      is_active INTEGER DEFAULT 1, last_sync TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);

  db.save();
  console.log('✅ Database ready:', dbPath);
  return db;
}

function dbAll(query, params = []) {
  const stmt = db.prepare(query);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function dbRun(query, params = []) {
  db.run(query, params);
  db.save();
}

function dbGet(query, params = []) {
  return dbAll(query, params)[0] || null;
}

module.exports = { initDB, dbAll, dbRun, dbGet };
