// ── SECURITY: HTML escape to prevent XSS ─────────────────
function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ── STATE ─────────────────────────────────────────────────
let state = {
  currentView: 'dashboard',
  trades: [], journalEntries: [], brokers: [],
  loading: true, syncing: false,
  filterAssetType: 'all', filterDirection: 'all',
  calendarDate: new Date(),
  showTradeModal: false, selectedTrade: null,
  showProfileModal: false,
  csvParsed: null, csvImporting: false, csvProgress: 0,
};

// ── TOAST ─────────────────────────────────────────────────
function toast(message, type = 'info', duration = 3500) {
  const icons = { success:'✅', error:'❌', info:'ℹ️', warn:'⚠️' };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span style="flex-shrink:0">${icons[type]||'ℹ️'}</span><span>${esc(message)}</span>`;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => el.remove(), duration);
}

// ── BOOT ──────────────────────────────────────────────────
async function init() {
  state.loading = true; render();
  try {
    const [t, j, b] = await Promise.all([api.getTrades(), api.getJournal(), api.getBrokers()]);
    state.trades = t.data; state.journalEntries = j.data; state.brokers = b.data;
  } catch (err) {
    toast('Could not reach server. Check your connection.', 'error', 7000);
  }
  state.loading = false; render();
}

// ── STATS ─────────────────────────────────────────────────
function calcStats(trades) {
  const w = trades.filter(t => t.pnl > 0);
  const l = trades.filter(t => t.pnl < 0);
  const tp = trades.reduce((s,t) => s + Number(t.pnl), 0);
  const tw = w.reduce((s,t) => s + Number(t.pnl), 0);
  const tl = Math.abs(l.reduce((s,t) => s + Number(t.pnl), 0));
  const aw = w.length ? tw / w.length : 0;
  const al = l.length ? tl / l.length : 0;
  return {
    totalTrades: trades.length, totalPnL: tp,
    winningTrades: w.length, losingTrades: l.length,
    winRate: trades.length ? ((w.length / trades.length) * 100).toFixed(1) : '0.0',
    avgWin: aw, avgLoss: al,
    profitFactor: tl > 0 ? (tw / tl).toFixed(2) : '—',
    rMultiple: al > 0 ? (aw / al).toFixed(2) : '—'
  };
}

// ── RENDER ────────────────────────────────────────────────
function render() {
  const app = document.getElementById('app');
  const stats = calcStats(state.trades);
  const views = ['dashboard','trades','analytics','calendar','journal','import','brokers'];
  const icons  = { dashboard:'📊',trades:'💹',analytics:'📈',calendar:'📅',journal:'📝',import:'📁',brokers:'🔌' };
  const labels = { dashboard:'Dashboard',trades:'Trades',analytics:'Analytics',calendar:'Calendar',journal:'Journal',import:'Import',brokers:'Brokers' };
  const user = getUser() || {};

  app.innerHTML = `
    <div class="app-container">
      <div class="sidebar">
        <div class="logo">TradeVault</div>
        <nav>
          ${views.map(v => `
            <div class="nav-item ${state.currentView === v ? 'active' : ''}" onclick="changeView('${v}')">
              <span class="nav-icon">${icons[v]}</span> ${labels[v]}
            </div>`).join('')}
        </nav>
        <div class="sidebar-footer">
          <button class="sidebar-profile-btn" onclick="openProfileModal()">
            <div class="sidebar-avatar">${esc((user.name||'U').charAt(0).toUpperCase())}</div>
            <div class="sidebar-user-info">
              <div class="sidebar-user-name">${esc(user.name || 'User')}</div>
              <div class="sidebar-user-label">${esc(user.email || '')}</div>
            </div>
            <span class="sidebar-profile-icon">⚙</span>
          </button>
          <button class="btn btn-secondary btn-sm" style="width:100%;margin-top:0.6rem" onclick="handleLogout()">Logout</button>
        </div>
        <div class="sync-status">
          <div class="sync-dot ${state.syncing ? 'syncing' : ''}"></div>
          <span>${state.syncing ? 'Syncing…' : 'Live'}</span>
        </div>
      </div>
      <div class="main-content">
        ${state.loading ? skeleton() : renderView(stats)}
      </div>
      ${state.showTradeModal ? tradeModal() : ''}
      ${state.showProfileModal ? profileModal() : ''}
    </div>
  `;
}

function renderView(stats) {
  switch (state.currentView) {
    case 'dashboard':  return dashboard(stats);
    case 'trades':     return tradesView();
    case 'analytics':  return analytics(stats);
    case 'calendar':   return calendar();
    case 'journal':    return journal();
    case 'import':     return importView();
    case 'brokers':    return brokers();
    default:           return dashboard(stats);
  }
}

function skeleton() {
  return `
    <div class="page-header"><h1 class="header">Loading…</h1></div>
    <div class="stats-grid">
      ${[1,2,3,4].map(() => '<div class="stat-card skeleton" style="height:110px"></div>').join('')}
    </div>
    <div class="card">
      ${[1,2,3].map(() => '<div class="skeleton" style="height:72px;margin-bottom:0.875rem;border-radius:8px"></div>').join('')}
    </div>`;
}

function statCard(label, value, sub, positive = null) {
  const color = positive === true ? 'var(--accent-green)' : positive === false ? 'var(--accent-red)' : 'inherit';
  return `
    <div class="stat-card">
      <div class="stat-label">${label}</div>
      <div class="stat-value" style="color:${color}">${value}</div>
      <div class="stat-change">${sub}</div>
    </div>`;
}

function empty(icon, title, sub) {
  return `
    <div class="empty-state">
      <div class="empty-state-icon">${icon}</div>
      <h3>${title}</h3>
      <p>${sub}</p>
    </div>`;
}

// ── DASHBOARD ─────────────────────────────────────────────
function dashboard(s) {
  return `
    <div class="page-header">
      <h1 class="header">Dashboard</h1>
      <button class="btn btn-primary" onclick="openAddTradeModal()">+ Add Trade</button>
    </div>
    <div class="stats-grid">
      ${statCard('Total P&L', `${s.totalPnL >= 0 ? '+' : ''}$${s.totalPnL.toFixed(2)}`, `${s.winningTrades}W / ${s.losingTrades}L`, s.totalPnL >= 0)}
      ${statCard('Win Rate', `${s.winRate}%`, `${s.totalTrades} total trades`)}
      ${statCard('Avg Win', `$${s.avgWin.toFixed(2)}`, 'Per winning trade', true)}
      ${statCard('Avg Loss', `$${s.avgLoss.toFixed(2)}`, 'Per losing trade', false)}
      ${statCard('Profit Factor', s.profitFactor, 'Gross wins ÷ losses')}
      ${statCard('R-Multiple', s.rMultiple, 'Avg win ÷ avg loss')}
    </div>
    <div class="card">
      <div class="card-title">Recent Trades</div>
      ${state.trades.length === 0
        ? empty('📊', 'No trades yet', 'Click "+ Add Trade" to log your first trade')
        : state.trades.slice(0, 5).map(t => tradeCard(t, false)).join('')}
    </div>`;
}

// ── TRADES VIEW ───────────────────────────────────────────
function tradesView() {
  const filtered = state.trades.filter(t =>
    (state.filterAssetType === 'all' || t.asset_type === state.filterAssetType) &&
    (state.filterDirection  === 'all' || t.direction  === state.filterDirection)
  );
  return `
    <div class="page-header">
      <h1 class="header">Trade History</h1>
      <button class="btn btn-primary" onclick="openAddTradeModal()">+ Add Trade</button>
    </div>
    <div class="filter-bar">
      <select class="form-select filter-select" onchange="updateFilter('assetType', this.value)">
        <option value="all">All Asset Types</option>
        ${['stock','forex','crypto','futures','options'].map(v =>
          `<option value="${v}" ${state.filterAssetType === v ? 'selected' : ''}>${v.charAt(0).toUpperCase() + v.slice(1)}</option>`
        ).join('')}
      </select>
      <select class="form-select filter-select" onchange="updateFilter('direction', this.value)">
        <option value="all">All Directions</option>
        <option value="long"  ${state.filterDirection === 'long'  ? 'selected' : ''}>Long</option>
        <option value="short" ${state.filterDirection === 'short' ? 'selected' : ''}>Short</option>
      </select>
      <span class="filter-count">${filtered.length} trade${filtered.length !== 1 ? 's' : ''}</span>
    </div>
    <div class="card">
      ${filtered.length === 0
        ? empty('🔍', 'No trades found', 'Try adjusting your filters')
        : filtered.map(t => tradeCard(t, true)).join('')}
    </div>`;
}

function tradeCard(t, showDelete = false) {
  const pnl = Number(t.pnl);
  const ep  = Number(t.entry_price);
  const xp  = Number(t.exit_price);
  const dec = ep < 10 ? 4 : 2;
  const pnlColor = pnl >= 0 ? 'var(--accent-green)' : 'var(--accent-red)';
  return `
    <div class="trade-item" onclick="viewTrade('${esc(t.id)}')">
      <div class="trade-header">
        <div class="trade-left">
          <span class="trade-symbol">${esc(t.symbol)}</span>
          <span class="trade-badges">
            <span class="badge badge-${t.direction}">${t.direction}</span>
            <span class="badge badge-${t.asset_type}">${t.asset_type}</span>
            ${t.broker && t.broker !== 'manual'
              ? `<span class="badge badge-broker">${esc(t.broker)}</span>`
              : ''}
          </span>
        </div>
        <div class="trade-right">
          <span class="trade-pnl" style="color:${pnlColor}">${pnl >= 0 ? '+' : ''}$${pnl.toFixed(2)}</span>
          ${showDelete
            ? `<button class="btn btn-danger btn-sm" onclick="event.stopPropagation();doDeleteTrade('${esc(t.id)}')">✕</button>`
            : ''}
        </div>
      </div>
      <div class="trade-meta">
        <span class="trade-meta-item">📅 ${t.exit_date ? new Date(t.exit_date).toLocaleDateString() : '—'}</span>
        ${t.strategy ? `<span class="trade-meta-item">📋 ${esc(t.strategy)}</span>` : ''}
        <span class="trade-meta-item">💰 $${ep.toFixed(dec)} → $${xp.toFixed(dec)}</span>
        <span class="trade-meta-item">📦 ${t.quantity}</span>
        ${t.market_conditions ? `<span class="trade-meta-item">🌡️ ${esc(t.market_conditions)}</span>` : ''}
      </div>
      ${t.notes ? `<div class="trade-notes">${esc(t.notes)}</div>` : ''}
    </div>`;
}

// ── ANALYTICS ─────────────────────────────────────────────
function analytics(s) {
  const byStrategy = state.trades.reduce((acc, t) => {
    const k = t.strategy || 'No Strategy';
    if (!acc[k]) acc[k] = { pnl: 0, count: 0, wins: 0 };
    acc[k].pnl += Number(t.pnl);
    acc[k].count++;
    if (t.pnl > 0) acc[k].wins++;
    return acc;
  }, {});

  const byAsset = state.trades.reduce((acc, t) => {
    acc[t.asset_type] = (acc[t.asset_type] || 0) + 1;
    return acc;
  }, {});

  return `
    <div class="page-header"><h1 class="header">Analytics</h1></div>
    <div class="stats-grid">
      ${statCard('Total Trades', s.totalTrades, '')}
      ${statCard('Win Rate', `${s.winRate}%`, '')}
      ${statCard('Profit Factor', s.profitFactor, '')}
      ${statCard('Total P&L', `${s.totalPnL >= 0 ? '+' : ''}$${s.totalPnL.toFixed(2)}`, '', s.totalPnL >= 0)}
    </div>
    <div class="card">
      <div class="card-title">Performance by Strategy</div>
      ${!Object.keys(byStrategy).length
        ? empty('📈', 'No data yet', 'Add trades with strategy names to see breakdown')
        : Object.entries(byStrategy).sort((a, b) => b[1].pnl - a[1].pnl).map(([k, d]) => `
            <div class="trade-item" style="cursor:default">
              <div class="trade-header">
                <span class="trade-symbol">${esc(k)}</span>
                <span class="trade-pnl" style="color:${d.pnl >= 0 ? 'var(--accent-green)' : 'var(--accent-red)'}">
                  ${d.pnl >= 0 ? '+' : ''}$${d.pnl.toFixed(2)}
                </span>
              </div>
              <div class="trade-meta">
                <span class="trade-meta-item">📊 ${d.count} trades</span>
                <span class="trade-meta-item">✅ ${d.wins} wins</span>
                <span class="trade-meta-item">📈 ${((d.wins / d.count) * 100).toFixed(1)}% win rate</span>
              </div>
            </div>`).join('')}
    </div>
    <div class="card">
      <div class="card-title">Asset Distribution</div>
      ${!Object.keys(byAsset).length
        ? empty('📊', 'No data yet', 'Add trades to see asset breakdown')
        : Object.entries(byAsset).map(([asset, count]) => {
            const pct = ((count / state.trades.length) * 100).toFixed(1);
            return `
              <div class="trade-item" style="cursor:default;margin-bottom:0.875rem">
                <div class="trade-header" style="margin-bottom:0.5rem">
                  <span class="badge badge-${asset}">${asset}</span>
                  <span style="color:var(--text-secondary);font-size:0.82rem">${count} trades · ${pct}%</span>
                </div>
                <div class="progress-bar" style="margin-top:0">
                  <div class="progress-fill" style="width:${pct}%"></div>
                </div>
              </div>`;
          }).join('')}
    </div>`;
}

// ── CALENDAR ──────────────────────────────────────────────
function calendar() {
  const year  = state.calendarDate.getFullYear();
  const month = state.calendarDate.getMonth();
  const monthName  = state.calendarDate.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  const startDOW    = new Date(year, month, 1).getDay();

  // Group trades and journal entries by day
  const tradesByDay = {}, pnlByDay = {}, hasJournal = {};
  state.trades
    .filter(t => t.exit_date && new Date(t.exit_date).getMonth() === month && new Date(t.exit_date).getFullYear() === year)
    .forEach(t => {
      const d = new Date(t.exit_date).getDate();
      if (!tradesByDay[d]) tradesByDay[d] = [];
      tradesByDay[d].push(t);
      pnlByDay[d] = (pnlByDay[d] || 0) + Number(t.pnl);
    });
  state.journalEntries.forEach(e => {
    const d = new Date(e.entry_date + 'T12:00:00');
    if (d.getMonth() === month && d.getFullYear() === year) hasJournal[d.getDate()] = true;
  });

  const tradingDays = Object.keys(tradesByDay).length;
  const winDays     = Object.values(pnlByDay).filter(p => p > 0).length;
  const lossDays    = Object.values(pnlByDay).filter(p => p < 0).length;
  const monthPnL    = Object.values(pnlByDay).reduce((s, p) => s + p, 0);
  const avgDaily    = tradingDays > 0 ? monthPnL / tradingDays : 0;

  const cells = [];
  for (let i = 0; i < startDOW; i++) cells.push('<div class="calendar-day empty"></div>');
  for (let day = 1; day <= daysInMonth; day++) {
    const pnl = pnlByDay[day] ?? null;
    const ts  = tradesByDay[day] || [];
    let cls = 'calendar-day';
    if (ts.length) cls += pnl > 0 ? ' profit' : pnl < 0 ? ' loss' : ' breakeven';
    const ds = `${year}-${String(month+1).padStart(2,'0')}-${String(day).padStart(2,'0')}`;
    cells.push(`
      <div class="${cls}" onclick="viewCalendarDay('${ds}')">
        ${hasJournal[day] ? '<div class="calendar-day-journal">📝</div>' : ''}
        <div class="calendar-day-number">${day}</div>
        ${ts.length ? `
          <div class="calendar-day-pnl" style="color:${pnl >= 0 ? 'var(--accent-green)' : 'var(--accent-red)'}">
            ${pnl >= 0 ? '+' : ''}$${Math.abs(pnl).toFixed(0)}
          </div>
          <div class="calendar-day-trades">${ts.length}t</div>` : ''}
      </div>`);
  }

  return `
    <div class="page-header"><h1 class="header">Calendar</h1></div>
    <div class="card">
      <div class="calendar-stats">
        <div class="calendar-stat-item">
          <div class="calendar-stat-label">Monthly P&L</div>
          <div class="calendar-stat-value" style="color:${monthPnL >= 0 ? 'var(--accent-green)' : 'var(--accent-red)'}">
            ${monthPnL >= 0 ? '+' : ''}$${monthPnL.toFixed(2)}
          </div>
        </div>
        <div class="calendar-stat-item">
          <div class="calendar-stat-label">Trading Days</div>
          <div class="calendar-stat-value">${tradingDays}</div>
        </div>
        <div class="calendar-stat-item">
          <div class="calendar-stat-label">Green Days</div>
          <div class="calendar-stat-value positive">${winDays}</div>
        </div>
        <div class="calendar-stat-item">
          <div class="calendar-stat-label">Red Days</div>
          <div class="calendar-stat-value negative">${lossDays}</div>
        </div>
        <div class="calendar-stat-item">
          <div class="calendar-stat-label">Avg Daily</div>
          <div class="calendar-stat-value" style="color:${avgDaily >= 0 ? 'var(--accent-green)' : 'var(--accent-red)'}">
            ${avgDaily >= 0 ? '+' : ''}$${Math.abs(avgDaily).toFixed(2)}
          </div>
        </div>
        <div class="calendar-stat-item">
          <div class="calendar-stat-label">Day Win Rate</div>
          <div class="calendar-stat-value">${tradingDays ? ((winDays / tradingDays) * 100).toFixed(1) : 0}%</div>
        </div>
      </div>
    </div>
    <div class="calendar-container">
      <div class="calendar-header">
        <button class="calendar-nav-btn" onclick="changeCalendarMonth(-1)">‹</button>
        <div class="calendar-month-title">${monthName}</div>
        <button class="calendar-nav-btn" onclick="changeCalendarMonth(1)">›</button>
      </div>
      <div class="calendar-grid">
        ${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map(d => `<div class="calendar-day-header">${d}</div>`).join('')}
        ${cells.join('')}
      </div>
    </div>`;
}

// ── JOURNAL ───────────────────────────────────────────────
function journal() {
  const today = new Date().toISOString().split('T')[0];
  return `
    <div class="page-header"><h1 class="header">Journal</h1></div>
    <div class="card">
      <div class="card-title">New Entry</div>
      <div class="form-group">
        <label class="form-label">Date</label>
        <input type="date" class="form-input" id="jdate" value="${today}" style="max-width:220px">
      </div>
      <div class="form-group">
        <label class="form-label">Entry</label>
        <textarea class="form-textarea" id="jcontent" placeholder="What did you learn today? How did you execute? How did you feel?" style="min-height:140px"></textarea>
      </div>
      <button class="btn btn-primary" id="jsave" onclick="doSaveJournal()">Save Entry</button>
    </div>
    <div class="card">
      <div class="card-title">
        Past Entries
        <span class="card-title-count">${state.journalEntries.length}</span>
      </div>
      ${!state.journalEntries.length
        ? empty('📝', 'No entries yet', 'Start documenting your trading journey above')
        : state.journalEntries.map(e => `
            <div class="journal-entry">
              <button class="journal-delete" onclick="doDeleteJournal('${esc(e.id)}')" title="Delete entry">✕</button>
              <div class="journal-date">
                ${new Date(e.entry_date + 'T12:00:00').toLocaleDateString('en-US', { weekday:'long', year:'numeric', month:'long', day:'numeric' })}
              </div>
              <div class="journal-text">${esc(e.content).replace(/\n/g, '<br>')}</div>
            </div>`).join('')}
    </div>
    <div class="card">
      <div class="card-title">Trade Notes</div>
      ${!state.trades.filter(t => t.notes).length
        ? empty('💭', 'No trade notes', 'Add notes when logging trades')
        : state.trades.filter(t => t.notes).map(t => {
            const pnl = Number(t.pnl);
            const color = pnl >= 0 ? 'var(--accent-green)' : 'var(--accent-red)';
            return `
              <div class="journal-entry" style="border-left-color:${color}">
                <div class="journal-date" style="color:${color}">
                  ${esc(t.symbol)} · ${t.exit_date ? new Date(t.exit_date).toLocaleDateString() : '—'}
                  <span style="margin-left:1rem">${pnl >= 0 ? '+' : ''}$${pnl.toFixed(2)}</span>
                </div>
                <div class="journal-text">${esc(t.notes)}</div>
              </div>`;
          }).join('')}
    </div>`;
}

// ── IMPORT ────────────────────────────────────────────────
function importView() {
  const p = state.csvParsed;
  return `
    <div class="page-header"><h1 class="header">Import Trades</h1></div>
    <div class="card">
      <div class="card-title">Upload CSV</div>
      <div class="drop-zone" id="drop-zone"
        onclick="document.getElementById('csv-file').click()"
        ondragover="event.preventDefault();this.classList.add('dragover')"
        ondragleave="this.classList.remove('dragover')"
        ondrop="handleDrop(event)">
        <div style="font-size:2.5rem;margin-bottom:0.75rem">📁</div>
        <h3>Drop CSV here or click to browse</h3>
        <p>Preview shown before any data is imported</p>
        <input type="file" accept=".csv" id="csv-file" style="display:none" onchange="handleCSVFile(event)">
        <button class="btn btn-primary" style="margin-top:1.25rem" onclick="event.stopPropagation();document.getElementById('csv-file').click()">
          Choose File
        </button>
      </div>
      ${p ? csvPreview(p) : ''}
    </div>
    <div class="card">
      <div class="card-title">Expected Format</div>
      <div class="csv-table-wrap">
        <table class="csv-table">
          <thead><tr>
            ${['symbol','asset_type','direction','entry_price','exit_price','quantity','entry_date','exit_date','strategy','commission'].map(h => `<th>${h}</th>`).join('')}
          </tr></thead>
          <tbody><tr>
            ${['AAPL','stock','long','178.50','182.30','100','2025-01-10','2025-01-10','Breakout','2.00'].map(v => `<td>${v}</td>`).join('')}
          </tr></tbody>
        </table>
      </div>
      <div style="margin-top:1rem">
        <a href="${api.getSampleCSVUrl()}" class="btn btn-secondary btn-sm" download>⬇ Download Sample CSV</a>
      </div>
    </div>`;
}

function csvPreview(p) {
  const valid = p.rows.filter(r => !r._error).length;
  const errs  = p.rows.filter(r => r._error).length;
  return `
    <div class="csv-preview">
      <div class="csv-preview-header">
        <span>
          📋 <strong>${p.rows.length}</strong> rows —
          <span class="positive">${valid} valid</span>
          ${errs ? ` · <span class="negative">${errs} errors</span>` : ''}
        </span>
        <div style="display:flex;gap:0.75rem">
          <button class="btn btn-secondary btn-sm" onclick="clearCSV()">Clear</button>
          <button class="btn btn-primary btn-sm" id="import-btn" onclick="doConfirmImport()" ${!valid ? 'disabled' : ''}>
            Import ${valid} Trade${valid !== 1 ? 's' : ''}
          </button>
        </div>
      </div>
      <div class="csv-table-wrap">
        <table class="csv-table">
          <thead><tr>
            <th>#</th><th>Symbol</th><th>Type</th><th>Dir</th>
            <th>Entry</th><th>Exit</th><th>Qty</th><th>P&L</th><th>Status</th>
          </tr></thead>
          <tbody>
            ${p.rows.slice(0, 20).map((r, i) => `
              <tr>
                <td style="color:var(--text-secondary)">${i + 1}</td>
                <td>${esc(r.symbol || '—')}</td>
                <td>${esc(r.asset_type || '—')}</td>
                <td class="${r.direction === 'long' ? 'positive' : 'negative'}">${esc(r.direction || '—')}</td>
                <td>${r.entry_price || '—'}</td>
                <td>${r.exit_price || '—'}</td>
                <td>${r.quantity || '—'}</td>
                <td class="${r.pnl >= 0 ? 'positive' : 'negative'}">
                  ${r.pnl != null ? (r.pnl >= 0 ? '+' : '') + '$' + r.pnl.toFixed(2) : '—'}
                </td>
                <td class="${r._error ? 'row-error' : 'row-valid'}">${r._error ? esc(r._error) : '✓'}</td>
              </tr>`).join('')}
          </tbody>
        </table>
        ${p.rows.length > 20 ? `<p class="csv-more">Showing first 20 of ${p.rows.length} rows</p>` : ''}
      </div>
      ${state.csvImporting ? `
        <div style="margin-top:1rem">
          <div class="progress-bar"><div class="progress-fill" style="width:${state.csvProgress}%"></div></div>
          <div class="progress-text">Importing… ${state.csvProgress}%</div>
        </div>` : ''}
    </div>`;
}

// ── BROKERS ───────────────────────────────────────────────
function brokers() {
  const INFO = {
    alpaca:     { name:'Alpaca', icon:'🦙', desc:'US Stocks & Crypto. Free paper + live trading API.' },
    binance:    { name:'Binance', icon:'🟡', desc:'Crypto. Requires API key + secret from your Binance account.' },
    metatrader: { name:'MetaTrader 5', icon:'📉', desc:'Forex & CFDs. Requires MT5 API token from your broker.' },
    ibkr:       { name:'Interactive Brokers', icon:'🏦', desc:'Coming soon — requires TWS Gateway setup.', disabled: true },
  };

  return `
    <div class="page-header"><h1 class="header">Broker Connections</h1></div>
    ${state.brokers.length ? `
      <div class="card">
        <div class="card-title">Connected Brokers</div>
        ${state.brokers.map(b => `
          <div class="trade-item" style="cursor:default">
            <div class="trade-header">
              <div>
                <span class="trade-symbol">${esc(b.broker_name)}</span>
                ${b.account_id ? `<span class="broker-account">${esc(b.account_id)}</span>` : ''}
              </div>
              <div style="display:flex;gap:0.75rem;align-items:center">
                ${b.last_sync ? `<span class="broker-sync-time">Synced ${new Date(b.last_sync).toLocaleString()}</span>` : ''}
                <button class="btn btn-primary btn-sm" onclick="doSyncBroker('${esc(b.id)}','${esc(b.broker_name)}')">🔄 Sync</button>
                <button class="btn btn-danger btn-sm" onclick="doDeleteBroker('${esc(b.id)}')">✕</button>
              </div>
            </div>
          </div>`).join('')}
      </div>` : ''}
    <div class="card">
      <div class="card-title">Add Broker</div>
      <div class="broker-grid">
        ${Object.entries(INFO).map(([k, b]) => `
          <div class="trade-item ${b.disabled ? '' : 'broker-card'}"
            style="cursor:${b.disabled ? 'not-allowed' : 'pointer'};opacity:${b.disabled ? 0.5 : 1}"
            ${!b.disabled ? `onclick="showBrokerForm('${k}')"` : ''}>
            <div class="broker-icon">${b.icon}</div>
            <div class="broker-name">${b.name}</div>
            <div class="broker-desc">${b.desc}</div>
            ${b.disabled ? '<div class="broker-soon">Coming Soon</div>' : ''}
          </div>`).join('')}
      </div>
      <div id="broker-form"></div>
    </div>
    <div class="card">
      <div class="card-title">How It Works</div>
      <p style="color:var(--text-secondary);font-size:0.875rem;line-height:1.75">
        Connect a broker, click Sync, and TradeVault fetches your completed trades automatically via the broker's API.
        Duplicates are skipped — sync as often as you like. Your API keys are stored securely on the server, never in the browser.
        For brokers without an API, export a CSV and use the Import tab.
      </p>
    </div>`;
}

function showBrokerForm(key) {
  const forms = {
    alpaca: `
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">API Key ID</label>
          <input class="form-input" id="bk-key" placeholder="PKXXXXXXXXXXXXXXXX" autocomplete="off">
        </div>
        <div class="form-group">
          <label class="form-label">API Secret</label>
          <input type="password" class="form-input" id="bk-secret" autocomplete="off">
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">Mode</label>
        <select class="form-select" id="bk-paper" style="max-width:220px">
          <option value="true">Paper Trading</option>
          <option value="false">Live Trading</option>
        </select>
      </div>`,
    binance: `
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">API Key</label>
          <input class="form-input" id="bk-key" placeholder="Your Binance API key" autocomplete="off">
        </div>
        <div class="form-group">
          <label class="form-label">API Secret</label>
          <input type="password" class="form-input" id="bk-secret" autocomplete="off">
        </div>
      </div>`,
    metatrader: `
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">API Token</label>
          <input class="form-input" id="bk-key" placeholder="MT5 API token" autocomplete="off">
        </div>
        <div class="form-group">
          <label class="form-label">Account ID</label>
          <input class="form-input" id="bk-account" autocomplete="off">
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">MT5 Server URL</label>
        <input class="form-input" id="bk-server" placeholder="https://mt5.yourbroker.com">
      </div>`
  };

  document.getElementById('broker-form').innerHTML = `
    <div class="broker-form-inner">
      <h3 class="broker-form-title">${INFO_ICONS[key] || ''} Connect ${key.charAt(0).toUpperCase() + key.slice(1)}</h3>
      ${forms[key] || ''}
      <div style="display:flex;gap:0.75rem;margin-top:1.25rem">
        <button class="btn btn-primary" onclick="doAddBroker('${key}')">Save Connection</button>
        <button class="btn btn-secondary" onclick="document.getElementById('broker-form').innerHTML=''">Cancel</button>
      </div>
    </div>`;
}

const INFO_ICONS = { alpaca:'🦙', binance:'🟡', metatrader:'📉' };

// ── TRADE MODAL ───────────────────────────────────────────
function tradeModal() {
  const t = state.selectedTrade;
  const isView = !!t;
  const d = t || {};
  const fmtDT = dt => dt ? new Date(dt).toISOString().slice(0, 16) : '';
  const assetTypes  = ['stock','forex','crypto','futures','options'];
  const pnl = Number(d.pnl);

  return `
    <div class="modal" onclick="closeTradeModal()">
      <div class="modal-content" onclick="event.stopPropagation()">
        <div class="modal-header">
          <h2 class="modal-title">${isView ? 'Trade Details' : 'New Trade'}</h2>
          <button class="btn btn-secondary btn-sm" onclick="closeTradeModal()">✕ Close</button>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Symbol *</label>
            <input class="form-input" id="t-sym" placeholder="AAPL, EUR/USD, BTC…"
              value="${esc(d.symbol || '')}" ${isView ? 'disabled' : ''} autocomplete="off">
          </div>
          <div class="form-group">
            <label class="form-label">Asset Type</label>
            <select class="form-select" id="t-at" ${isView ? 'disabled' : ''}>
              ${assetTypes.map(v => `<option value="${v}" ${d.asset_type === v ? 'selected' : ''}>${v.charAt(0).toUpperCase() + v.slice(1)}</option>`).join('')}
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Direction</label>
            <select class="form-select" id="t-dir" ${isView ? 'disabled' : ''}>
              <option value="long"  ${d.direction === 'long'  ? 'selected' : ''}>Long  (Buy)</option>
              <option value="short" ${d.direction === 'short' ? 'selected' : ''}>Short (Sell)</option>
            </select>
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Entry Price *</label>
            <input type="number" step="any" class="form-input" id="t-ep"
              value="${d.entry_price || ''}" ${isView ? 'disabled' : ''} placeholder="0.00">
          </div>
          <div class="form-group">
            <label class="form-label">Exit Price *</label>
            <input type="number" step="any" class="form-input" id="t-xp"
              value="${d.exit_price || ''}" ${isView ? 'disabled' : ''} placeholder="0.00">
          </div>
          <div class="form-group">
            <label class="form-label">Quantity *</label>
            <input type="number" step="any" class="form-input" id="t-qty"
              value="${d.quantity || ''}" ${isView ? 'disabled' : ''} placeholder="0">
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Stop Loss</label>
            <input type="number" step="any" class="form-input" id="t-sl"
              value="${d.stop_loss || ''}" ${isView ? 'disabled' : ''} placeholder="Optional">
          </div>
          <div class="form-group">
            <label class="form-label">Take Profit</label>
            <input type="number" step="any" class="form-input" id="t-tp"
              value="${d.take_profit || ''}" ${isView ? 'disabled' : ''} placeholder="Optional">
          </div>
          <div class="form-group">
            <label class="form-label">Commission</label>
            <input type="number" step="any" class="form-input" id="t-com"
              value="${d.commission || 0}" ${isView ? 'disabled' : ''} placeholder="0.00">
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Entry Date / Time</label>
            <input type="datetime-local" class="form-input" id="t-ed"
              value="${fmtDT(d.entry_date)}" ${isView ? 'disabled' : ''}>
          </div>
          <div class="form-group">
            <label class="form-label">Exit Date / Time</label>
            <input type="datetime-local" class="form-input" id="t-xd"
              value="${fmtDT(d.exit_date)}" ${isView ? 'disabled' : ''}>
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Strategy</label>
            <input class="form-input" id="t-strat" placeholder="Breakout, Trend Following, Scalp…"
              value="${esc(d.strategy || '')}" ${isView ? 'disabled' : ''}>
          </div>
          <div class="form-group">
            <label class="form-label">Market Conditions</label>
            <input class="form-input" id="t-cond" placeholder="Bullish, Ranging, News…"
              value="${esc(d.market_conditions || '')}" ${isView ? 'disabled' : ''}>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label">Notes</label>
          <textarea class="form-textarea" id="t-notes"
            placeholder="Your reasoning, emotions, lessons learned…"
            ${isView ? 'disabled' : ''}>${esc(d.notes || '')}</textarea>
        </div>

        ${isView ? `
          <div class="pnl-result" style="border-color:${pnl >= 0 ? 'var(--accent-green)' : 'var(--accent-red)'}">
            <div class="stat-label">Final P&L</div>
            <div class="stat-value" style="color:${pnl >= 0 ? 'var(--accent-green)' : 'var(--accent-red)'}">
              ${pnl >= 0 ? '+' : ''}$${pnl.toFixed(2)}
            </div>
          </div>
          <div class="modal-actions">
            <button class="btn btn-danger" onclick="doDeleteTrade('${esc(d.id)}');closeTradeModal()">Delete Trade</button>
            <button class="btn btn-secondary" onclick="closeTradeModal()">Close</button>
          </div>` : `
          <div class="modal-actions">
            <button class="btn btn-primary" id="save-btn" onclick="doSaveTrade()">Save Trade</button>
            <button class="btn btn-secondary" onclick="closeTradeModal()">Cancel</button>
          </div>`}
      </div>
    </div>`;
}

// ── NAVIGATION ────────────────────────────────────────────
function changeView(v)          { state.currentView = v; render(); }
function openAddTradeModal()    { state.selectedTrade = null; state.showTradeModal = true; render(); }
function closeTradeModal()      { state.showTradeModal = false; state.selectedTrade = null; render(); }
function updateFilter(type, val){ type === 'assetType' ? state.filterAssetType = val : state.filterDirection = val; render(); }
function changeCalendarMonth(d) { const dt = new Date(state.calendarDate); dt.setMonth(dt.getMonth() + d); state.calendarDate = dt; render(); }

function viewTrade(id) {
  state.selectedTrade = state.trades.find(t => String(t.id) === String(id)) || null;
  state.showTradeModal = true;
  render();
}

function viewCalendarDay(ds) {
  const date = new Date(ds + 'T12:00:00');
  const dayTrades = state.trades.filter(t =>
    t.exit_date && new Date(t.exit_date).toDateString() === date.toDateString()
  );
  if (!dayTrades.length) return;
  const totalPnL = dayTrades.reduce((s, t) => s + Number(t.pnl), 0);
  const summary  = dayTrades.map(t => `${t.symbol}: ${Number(t.pnl) >= 0 ? '+' : ''}$${Number(t.pnl).toFixed(2)}`).join('  |  ');
  toast(
    `${date.toLocaleDateString('en-US',{month:'short',day:'numeric'})} — ${dayTrades.length} trade${dayTrades.length !== 1 ? 's' : ''} — P&L: ${totalPnL >= 0 ? '+' : ''}$${totalPnL.toFixed(2)}  |  ${summary}`,
    totalPnL >= 0 ? 'success' : 'error',
    6000
  );
}

// ── TRADE ACTIONS ─────────────────────────────────────────
async function doSaveTrade() {
  const btn = document.getElementById('save-btn');
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Saving…'; }

  const sym  = (document.getElementById('t-sym').value || '').trim().toUpperCase();
  const ep   = parseFloat(document.getElementById('t-ep').value);
  const xp   = parseFloat(document.getElementById('t-xp').value);
  const qty  = parseFloat(document.getElementById('t-qty').value);

  if (!sym || isNaN(ep) || isNaN(xp) || isNaN(qty)) {
    toast('Symbol, entry price, exit price and quantity are required', 'error');
    if (btn) { btn.disabled = false; btn.textContent = 'Save Trade'; }
    return;
  }

  try {
    state.syncing = true;
    const res = await api.createTrade({
      symbol:            sym,
      entry_price:       ep,
      exit_price:        xp,
      quantity:          qty,
      asset_type:        document.getElementById('t-at').value,
      direction:         document.getElementById('t-dir').value,
      commission:        parseFloat(document.getElementById('t-com').value) || 0,
      entry_date:        document.getElementById('t-ed').value  || null,
      exit_date:         document.getElementById('t-xd').value  || null,
      stop_loss:         parseFloat(document.getElementById('t-sl').value)   || null,
      take_profit:       parseFloat(document.getElementById('t-tp').value)   || null,
      strategy:          document.getElementById('t-strat').value || null,
      notes:             document.getElementById('t-notes').value || null,
      market_conditions: document.getElementById('t-cond').value  || null,
    });
    state.trades.unshift(res.data);
    state.syncing = false;
    toast(`${sym} saved — ${res.data.pnl >= 0 ? '+' : ''}$${Number(res.data.pnl).toFixed(2)}`, 'success');
    closeTradeModal();
  } catch (err) {
    state.syncing = false;
    toast(`Save failed: ${err.message}`, 'error');
    if (btn) { btn.disabled = false; btn.textContent = 'Save Trade'; }
  }
}

async function doDeleteTrade(id) {
  if (!confirm('Delete this trade? This cannot be undone.')) return;
  try {
    state.syncing = true;
    await api.deleteTrade(id);
    state.trades = state.trades.filter(t => String(t.id) !== String(id));
    state.syncing = false;
    toast('Trade deleted', 'info');
    render();
  } catch (err) {
    state.syncing = false;
    toast(`Delete failed: ${err.message}`, 'error');
  }
}

// ── JOURNAL ACTIONS ───────────────────────────────────────
async function doSaveJournal() {
  const btn     = document.getElementById('jsave');
  const date    = document.getElementById('jdate').value;
  const content = document.getElementById('jcontent').value.trim();

  if (!date || !content) { toast('Date and content are required', 'error'); return; }

  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Saving…'; }
  try {
    state.syncing = true;
    const res = await api.createJournal({ entry_date: date, content });
    state.journalEntries.unshift(res.data);
    state.syncing = false;
    toast('Journal entry saved!', 'success');
    render();
  } catch (err) {
    state.syncing = false;
    toast(`Save failed: ${err.message}`, 'error');
    if (btn) { btn.disabled = false; btn.textContent = 'Save Entry'; }
  }
}

async function doDeleteJournal(id) {
  if (!confirm('Delete this journal entry?')) return;
  try {
    await api.deleteJournal(id);
    state.journalEntries = state.journalEntries.filter(e => String(e.id) !== String(id));
    toast('Entry deleted', 'info');
    render();
  } catch (err) {
    toast(`Delete failed: ${err.message}`, 'error');
  }
}

// ── CSV IMPORT ────────────────────────────────────────────
function handleDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.remove('dragover');
  const f = e.dataTransfer.files[0];
  if (f && f.name.endsWith('.csv')) uploadCSV(f);
  else toast('Please drop a .csv file', 'error');
}

function handleCSVFile(e) {
  if (e.target.files[0]) uploadCSV(e.target.files[0]);
}

async function uploadCSV(file) {
  const fd = new FormData();
  fd.append('file', file);
  try {
    toast('Parsing CSV…', 'info', 2000);
    const res = await api.previewCSV(fd);
    state.csvParsed = res.data;
    render();
  } catch (err) {
    toast(`Parse error: ${err.message}`, 'error');
  }
}

async function doConfirmImport() {
  if (!state.csvParsed) return;
  const valid = state.csvParsed.rows.filter(r => !r._error);
  state.csvImporting = true; state.csvProgress = 10; render();
  try {
    state.csvProgress = 50; render();
    const res = await api.confirmImport(valid);
    state.csvProgress = 100;
    const fresh = await api.getTrades();
    state.trades = fresh.data;
    state.csvParsed = null;
    state.csvImporting = false;
    toast(`Imported ${res.imported} trade${res.imported !== 1 ? 's' : ''}!`, 'success');
    render();
  } catch (err) {
    state.csvImporting = false;
    toast(`Import failed: ${err.message}`, 'error');
    render();
  }
}

function clearCSV() { state.csvParsed = null; render(); }

// ── BROKER ACTIONS ────────────────────────────────────────
async function doAddBroker(key) {
  const api_key    = document.getElementById('bk-key')?.value?.trim();
  const api_secret = document.getElementById('bk-secret')?.value?.trim();
  const account_id = document.getElementById('bk-account')?.value?.trim();
  if (!api_key) { toast('API key is required', 'error'); return; }
  try {
    const res = await api.addBroker({ broker_name: key, api_key, api_secret, account_id });
    state.brokers.push(res.data);
    toast(`${key} connected successfully!`, 'success');
    render();
  } catch (err) {
    toast(`Connection failed: ${err.message}`, 'error');
  }
}

async function doSyncBroker(id, name) {
  toast(`Syncing ${name}…`, 'info', 3000);
  try {
    const res = await api.syncBroker(id);
    if (res.imported > 0) {
      const fresh = await api.getTrades();
      state.trades = fresh.data;
    }
    const idx = state.brokers.findIndex(b => b.id === id);
    if (idx >= 0) state.brokers[idx].last_sync = new Date().toISOString();
    toast(`Synced ${res.imported} trade${res.imported !== 1 ? 's' : ''} from ${name}`, 'success');
    render();
  } catch (err) {
    toast(`Sync failed: ${err.message}`, 'error');
  }
}

async function doDeleteBroker(id) {
  if (!confirm('Remove this broker connection?')) return;
  try {
    await api.deleteBroker(id);
    state.brokers = state.brokers.filter(b => b.id !== id);
    toast('Broker removed', 'info');
    render();
  } catch (err) {
    toast(`Delete failed: ${err.message}`, 'error');
  }
}


// ── PROFILE MODAL ─────────────────────────────────────────
function openProfileModal()  { state.showProfileModal = true;  render(); }
function closeProfileModal() { state.showProfileModal = false; render(); }

function profileModal() {
  const user = getUser() || {};
  const initial = (user.name || 'U').charAt(0).toUpperCase();
  return `
    <div class="modal" onclick="closeProfileModal()">
      <div class="modal-content" style="max-width:520px" onclick="event.stopPropagation()">
        <div class="modal-header">
          <h2 class="modal-title">Profile & Settings</h2>
          <button class="btn btn-secondary btn-sm" onclick="closeProfileModal()">✕ Close</button>
        </div>

        <!-- Avatar + name -->
        <div class="profile-header">
          <div class="profile-avatar">${esc(initial)}</div>
          <div>
            <div class="profile-name">${esc(user.name || 'User')}</div>
            <div class="profile-email">${esc(user.email || '')}</div>
            <div class="profile-joined">Member since ${user.created_at ? new Date(user.created_at).toLocaleDateString('en-US',{month:'long',year:'numeric'}) : '—'}</div>
          </div>
        </div>

        <!-- Stats summary -->
        <div class="profile-stats">
          <div class="profile-stat">
            <div class="profile-stat-value">${state.trades.length}</div>
            <div class="profile-stat-label">Total Trades</div>
          </div>
          <div class="profile-stat">
            <div class="profile-stat-value">${state.journalEntries.length}</div>
            <div class="profile-stat-label">Journal Entries</div>
          </div>
          <div class="profile-stat">
            <div class="profile-stat-value" style="color:${calcStats(state.trades).totalPnL >= 0 ? 'var(--accent-green)' : 'var(--accent-red)'}">
              ${calcStats(state.trades).totalPnL >= 0 ? '+' : ''}$${calcStats(state.trades).totalPnL.toFixed(0)}
            </div>
            <div class="profile-stat-label">Total P&L</div>
          </div>
          <div class="profile-stat">
            <div class="profile-stat-value">${calcStats(state.trades).winRate}%</div>
            <div class="profile-stat-label">Win Rate</div>
          </div>
        </div>

        <!-- Divider -->
        <div class="profile-section-title">Edit Profile</div>

        <!-- Update name -->
        <div class="form-group">
          <label class="form-label">Display Name</label>
          <input class="form-input" id="profile-name" value="${esc(user.name || '')}" placeholder="Your name">
        </div>
        <div style="margin-bottom:1.5rem">
          <button class="btn btn-primary btn-sm" id="update-name-btn" onclick="doUpdateName()">Update Name</button>
        </div>

        <!-- Change password -->
        <div class="profile-section-title">Change Password</div>
        <div class="form-group">
          <label class="form-label">Current Password</label>
          <input type="password" class="form-input" id="profile-cur-pw" placeholder="Your current password" autocomplete="current-password">
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">New Password</label>
            <input type="password" class="form-input" id="profile-new-pw" placeholder="Min 6 characters" autocomplete="new-password">
          </div>
          <div class="form-group">
            <label class="form-label">Confirm New Password</label>
            <input type="password" class="form-input" id="profile-confirm-pw" placeholder="Repeat new password" autocomplete="new-password">
          </div>
        </div>
        <div style="margin-bottom:1.5rem">
          <button class="btn btn-secondary btn-sm" id="update-pw-btn" onclick="doUpdatePassword()">Change Password</button>
        </div>

        <!-- Danger zone -->
        <div class="profile-section-title danger">Danger Zone</div>
        <div class="danger-zone">
          <div>
            <div style="font-weight:600;margin-bottom:0.25rem">Export My Data</div>
            <div style="font-size:0.8rem;color:var(--text-secondary)">Download all your trades as a CSV file</div>
          </div>
          <button class="btn btn-secondary btn-sm" onclick="doExportData()">⬇ Export</button>
        </div>
        <div class="danger-zone" style="margin-top:0.75rem">
          <div>
            <div style="font-weight:600;margin-bottom:0.25rem;color:var(--accent-red)">Delete Account</div>
            <div style="font-size:0.8rem;color:var(--text-secondary)">Permanently delete your account and all data</div>
          </div>
          <button class="btn btn-danger btn-sm" onclick="doDeleteAccount()">Delete</button>
        </div>

      </div>
    </div>`;
}

async function doUpdateName() {
  const name = document.getElementById('profile-name').value.trim();
  if (!name) { toast('Name cannot be empty', 'error'); return; }
  const btn = document.getElementById('update-name-btn');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const res = await api.updateProfile({ name });
    saveAuth(res.token, res.user);
    toast('Name updated!', 'success');
    btn.disabled = false; btn.textContent = 'Update Name';
    render();
  } catch (err) {
    toast(err.message, 'error');
    btn.disabled = false; btn.textContent = 'Update Name';
  }
}

async function doUpdatePassword() {
  const currentPassword = document.getElementById('profile-cur-pw').value;
  const newPassword     = document.getElementById('profile-new-pw').value;
  const confirm         = document.getElementById('profile-confirm-pw').value;
  if (!currentPassword || !newPassword) { toast('All password fields required', 'error'); return; }
  if (newPassword.length < 6) { toast('New password must be at least 6 characters', 'error'); return; }
  if (newPassword !== confirm) { toast('New passwords do not match', 'error'); return; }
  const btn = document.getElementById('update-pw-btn');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    await api.updateProfile({ currentPassword, newPassword });
    toast('Password changed successfully!', 'success');
    document.getElementById('profile-cur-pw').value = '';
    document.getElementById('profile-new-pw').value = '';
    document.getElementById('profile-confirm-pw').value = '';
    btn.disabled = false; btn.textContent = 'Change Password';
  } catch (err) {
    toast(err.message, 'error');
    btn.disabled = false; btn.textContent = 'Change Password';
  }
}

function doExportData() {
  if (!state.trades.length) { toast('No trades to export', 'warn'); return; }
  const headers = ['symbol','asset_type','direction','entry_price','exit_price','quantity','pnl','commission','entry_date','exit_date','strategy','market_conditions','notes','broker'];
  const rows = state.trades.map(t => headers.map(h => {
    const v = t[h] == null ? '' : String(t[h]);
    return v.includes(',') || v.includes('"') || v.includes('\n') ? `"${v.replace(/"/g,'""')}"` : v;
  }).join(','));
  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `tradevault-export-${new Date().toISOString().split('T')[0]}.csv`;
  a.click(); URL.revokeObjectURL(url);
  toast('Export downloaded!', 'success');
}

async function doDeleteAccount() {
  const confirmText = prompt('Type DELETE (all caps) to permanently delete your account and all data. This cannot be undone.');
  if (confirmText !== 'DELETE') { toast('Account deletion cancelled', 'info'); return; }
  const password = prompt('Enter your password to confirm:');
  if (password === null) return;
  try {
    await api.deleteAccount({ password, confirmText });
    toast('Account deleted. Goodbye!', 'info', 3000);
    setTimeout(() => { clearAuth(); window.location.href = '/auth.html'; }, 2000);
  } catch (err) {
    toast(err.message, 'error');
  }
}

// ── AUTH ──────────────────────────────────────────────────
function handleLogout() {
  if (confirm('Log out of TradeVault?')) {
    clearAuth();
    window.location.href = '/auth.html';
  }
}

// ── INIT ──────────────────────────────────────────────────
init();
