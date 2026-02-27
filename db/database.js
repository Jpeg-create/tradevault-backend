const { Pool } = require('pg');

// ── CONNECTION POOL ───────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on('error', (err) => {
  console.error('[DB] Unexpected pool error:', err.message);
});

// ── SCHEMA ────────────────────────────────────────────────
const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    email      TEXT UNIQUE NOT NULL,
    password   TEXT,
    google_id  TEXT UNIQUE,
    avatar     TEXT,
    plan       TEXT DEFAULT 'free',
    created_at TEXT DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
  );

  CREATE TABLE IF NOT EXISTS trades (
    id                TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL,
    symbol            TEXT NOT NULL,
    asset_type        TEXT NOT NULL DEFAULT 'stock',
    direction         TEXT NOT NULL DEFAULT 'long',
    entry_price       REAL NOT NULL,
    exit_price        REAL NOT NULL,
    quantity          REAL NOT NULL,
    entry_date        TEXT,
    exit_date         TEXT,
    stop_loss         REAL,
    take_profit       REAL,
    strategy          TEXT,
    notes             TEXT,
    commission        REAL DEFAULT 0,
    market_conditions TEXT,
    pnl               REAL NOT NULL,
    broker            TEXT DEFAULT 'manual',
    broker_trade_id   TEXT,
    created_at        TEXT DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS journal_entries (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    entry_date TEXT NOT NULL,
    content    TEXT NOT NULL,
    created_at TEXT DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS broker_connections (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    broker_name TEXT NOT NULL,
    api_key     TEXT,
    api_secret  TEXT,
    account_id  TEXT,
    is_active   INTEGER DEFAULT 1,
    last_sync   TEXT,
    created_at  TEXT DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS used_reset_tokens (
    token_hash TEXT PRIMARY KEY,
    used_at    TEXT DEFAULT (to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
  );
`;

// ── INIT ──────────────────────────────────────────────────
async function initDB() {
  try {
    await pool.query(SCHEMA);
    console.log('✅ Neon database ready');
  } catch (err) {
    console.error('❌ Database init failed:', err.message);
    throw err;
  }
}

// ── HELPERS ───────────────────────────────────────────────
// Convert SQLite-style ? placeholders to PostgreSQL $1 $2 $3...
function toPostgres(query) {
  let i = 0;
  return query.replace(/\?/g, () => `$${++i}`);
}

function normaliseRow(row) {
  if (!row) return null;
  const out = {};
  for (const [k, v] of Object.entries(row)) {
    out[k] = v;
  }
  return out;
}

async function dbAll(query, params = []) {
  const { rows } = await pool.query(toPostgres(query), params);
  return rows.map(normaliseRow);
}

async function dbGet(query, params = []) {
  const rows = await dbAll(query, params);
  return rows[0] || null;
}

async function dbRun(query, params = []) {
  const result = await pool.query(toPostgres(query), params);
  return result.rowCount || 0;
}

module.exports = { initDB, dbAll, dbRun, dbGet };
