function errorHandler(err, req, res, next) {
  console.error(`[ERROR] ${req.method} ${req.path}:`, err.message);

  if (err.message === 'Only CSV files allowed' || err.message === 'Only CSV files are allowed') {
    return res.status(400).json({ success: false, error: 'Only CSV files are allowed' });
  }

  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ success: false, error: 'File too large. Maximum size is 5 MB.' });
  }

  if (typeof err.message === 'string' && err.message.startsWith('CORS:')) {
    return res.status(403).json({ success: false, error: 'Origin not allowed by CORS policy' });
  }

  const status = err.status || err.statusCode || 500;
  const isProduction = process.env.NODE_ENV === 'production';
  const clientMessage = isProduction
    ? 'Internal server error'
    : (err.message || 'Internal server error');

  res.status(status).json({ success: false, error: clientMessage });
}

module.exports = errorHandler;
