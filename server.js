require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const rateLimit = require('express-rate-limit');
const { initDB } = require('./db/database');

// ── GUARD: crash loudly in production if secret is still default ──
if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set. Refusing to start.');
  process.exit(1);
}

const app  = express();
const PORT = process.env.PORT || 3000;

// ── CORS ──────────────────────────────────────────────────
const allowedOrigins = [
  process.env.FRONTEND_URL,
  'http://localhost:5500',
  'http://localhost:3000',
  'http://127.0.0.1:5500',
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: origin ${origin} not allowed`));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// ── RATE LIMITING ──────────────────────────────────────────
// Strict limit on auth endpoints — prevents brute force
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,                   // 20 attempts per 15 min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests. Please try again in 15 minutes.' },
});

// General API limit — prevents scraping / flooding
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,  // 1 minute
  max: 120,                  // 120 req/min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests. Please slow down.' },
});

app.use('/api/auth', authLimiter);
app.use('/api',      apiLimiter);

// ── BODY PARSING ───────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// ── HEALTH ─────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));
app.get('/',           (req, res) => res.json({ message: 'TradeVault API is running.' }));

// ── START ──────────────────────────────────────────────────
async function start() {
  await initDB();

  app.use('/api/auth',    require('./routes/auth'));
  app.use('/api/trades',  require('./routes/trades'));
  app.use('/api/journal', require('./routes/journal'));
  app.use('/api/import',  require('./routes/import'));
  app.use('/api/brokers', require('./routes/brokers'));

  // Global error handler — never expose raw stack traces
  app.use((err, req, res, next) => {
    console.error(`[ERROR] ${req.method} ${req.path}:`, err.message);
    const isDev = process.env.NODE_ENV !== 'production';
    res.status(err.status || 500).json({
      success: false,
      error: isDev ? err.message : 'An internal server error occurred.',
    });
  });

  app.listen(PORT, () => {
    console.log(`\n🚀 TradeVault API running on http://localhost:${PORT}`);
    console.log(`❤️  Health: http://localhost:${PORT}/api/health\n`);
  });
}

start().catch(err => { console.error('Failed to start:', err); process.exit(1); });
