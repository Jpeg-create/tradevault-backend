const CONFIG = {
  API_BASE: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:3000/api'
    : 'https://tradevault-backend-xnpg.onrender.com/api',

  // Get this from Google Cloud Console after setting up OAuth
  // Instructions in README
  GOOGLE_CLIENT_ID: 'YOUR_GOOGLE_CLIENT_ID'
};

window.CONFIG = CONFIG;
