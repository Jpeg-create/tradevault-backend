require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const rateLimit = require('express-rate-limit');
const { initDB } = require('./db/database');
const errorHandler = require('./middleware/errorHandler');

// ── GUARD: crash loudly in production if secret is still default ──
if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set. Refusing to start.');
  process.exit(1);
}

const app  = express();
const PORT = process.env.PORT || 3000;

// ── SECURITY HEADERS ───────────────────────────────────────
// Applied before all other middleware so every response gets them.
app.disable('x-powered-by'); // don't leak Express version
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options',  'nosniff');
  res.setHeader('X-Frame-Options',         'DENY');
  res.setHeader('Referrer-Policy',         'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy',      'camera=(), microphone=(), geolocation=()');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// ── CORS ──────────────────────────────────────────────────
// ── CORS ──────────────────────────────────────────────────
const exactAllowedOrigins = [
  process.env.FRONTEND_URL,
  'http://localhost:5500',
  'http://localhost:3000',
  'http://localhost:3001',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:3000',
].filter(Boolean);

function isAllowedOrigin(origin) {
  if (!origin) return true;  // same-origin / server-to-server
  if (exactAllowedOrigins.includes(origin)) return true;
  // Allow any *.vercel.app preview URL (covers all deployment previews)
  if (/^https:\/\/[a-z0-9-]+\.vercel\.app$/.test(origin)) return true;
  return false;
}

app.use(cors({
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) return callback(null, true);
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
app.get('/',           (req, res) => res.json({ message: 'Quantario API is running.' }));

// ── START ──────────────────────────────────────────────────
async function start() {
  await initDB();

  app.use('/api/auth',    require('./routes/auth'));
  app.use('/api/trades',  require('./routes/trades'));
  app.use('/api/journal', require('./routes/journal'));
  app.use('/api/import',  require('./routes/import'));
  app.use('/api/brokers', require('./routes/brokers'));
  app.use('/api/ai',      require('./routes/ai'));

  app.use(errorHandler);

  app.listen(PORT, () => {
    console.log(`\n🚀 Quantario API running on http://localhost:${PORT}`);
    console.log(`❤️  Health: http://localhost:${PORT}/api/health\n`);
  });
}

start().catch(err => { console.error('Failed to start:', err); process.exit(1); });
