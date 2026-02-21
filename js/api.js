// All API calls — includes auth token in every request + timeout handling

function getToken()  { return localStorage.getItem('tv_token'); }
function getUser()   { return JSON.parse(localStorage.getItem('tv_user') || 'null'); }
function saveAuth(token, user) { localStorage.setItem('tv_token', token); localStorage.setItem('tv_user', JSON.stringify(user)); }
function clearAuth() { localStorage.removeItem('tv_token'); localStorage.removeItem('tv_user'); }

// Fetch with a timeout — Render free tier can take 30-60s to cold start
async function request(method, path, body = null, timeoutMs = 35000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      signal: controller.signal,
    };
    const token = getToken();
    if (token) opts.headers['Authorization'] = `Bearer ${token}`;
    if (body)  opts.body = JSON.stringify(body);

    const res  = await fetch(`${CONFIG.API_BASE}${path}`, opts);
    const json = await res.json();

    if (res.status === 401) {
      clearAuth();
      window.location.href = '/auth.html';
      return;
    }

    if (!res.ok || !json.success) throw new Error(json.error || `HTTP ${res.status}`);
    return json;
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error('Server is taking too long to respond. Render free tier may be waking up — please wait 30 seconds and try again.');
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

const api = {
  // Auth
  signup:               (data) => request('POST',   '/auth/signup', data),
  login:                (data) => request('POST',   '/auth/login',  data),
  googleLogin:          (data) => request('POST',   '/auth/google', data),
  me:                   ()     => request('GET',    '/auth/me'),
  resetPasswordRequest: (data) => request('POST',   '/auth/reset-password-request', data),
  resetPassword:        (data) => request('POST',   '/auth/reset-password', data),
  updateProfile:        (data) => request('PUT',    '/auth/profile', data),
  deleteAccount:        (data) => request('DELETE', '/auth/account', data),

  // Trades
  getTrades:   (params={}) => { const qs = new URLSearchParams(params).toString(); return request('GET', `/trades${qs ? '?' + qs : ''}`); },
  createTrade: (data)      => request('POST',   '/trades', data),
  updateTrade: (id, data)  => request('PUT',    `/trades/${id}`, data),
  deleteTrade: (id)        => request('DELETE', `/trades/${id}`),

  // Journal
  getJournal:    ()     => request('GET',    '/journal'),
  createJournal: (data) => request('POST',   '/journal', data),
  deleteJournal: (id)   => request('DELETE', `/journal/${id}`),

  // Import
  previewCSV: (fd) => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 35000);
    return fetch(`${CONFIG.API_BASE}/import/preview`, {
      method: 'POST', body: fd, credentials: 'include', signal: controller.signal,
      headers: { Authorization: `Bearer ${getToken()}` }
    }).then(r => r.json()).then(j => { if (!j.success) throw new Error(j.error); return j; });
  },
  confirmImport:  (rows) => request('POST', '/import/confirm', { rows }),
  getSampleCSVUrl: ()   => `${CONFIG.API_BASE}/import/sample`,

  // Brokers
  getBrokers:   ()     => request('GET',    '/brokers'),
  addBroker:    (data) => request('POST',   '/brokers', data),
  deleteBroker: (id)   => request('DELETE', `/brokers/${id}`),
  syncBroker:   (id)   => request('POST',   `/brokers/${id}/sync`),

  // Health ping (used to pre-warm the server)
  ping: () => fetch(`${CONFIG.API_BASE}/health`, { signal: AbortSignal.timeout(60000) })
               .then(r => r.json()).catch(() => null),
};

window.api = api;
window.getToken = getToken;
window.getUser  = getUser;
window.saveAuth = saveAuth;
window.clearAuth = clearAuth;
