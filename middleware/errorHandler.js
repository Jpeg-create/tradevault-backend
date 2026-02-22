function errorHandler(err, req, res, next) {
  console.error(`[ERROR] ${req.method} ${req.path}:`, err.message);

  // Known safe client errors — always pass through as-is
  if (err.message === 'Only CSV files allowed') {
    return res.status(400).json({ success: false, error: err.message });
  }

  // In production, never expose raw error internals to the client
  const isProduction = process.env.NODE_ENV === 'production';
  const clientMessage = isProduction
    ? 'Internal server error'
    : (err.message || 'Internal server error');

  res.status(err.status || 500).json({ success: false, error: clientMessage });
}

module.exports = errorHandler;
