const API = {
  token() { return localStorage.getItem('vs_token'); },
  setToken(t) { localStorage.setItem('vs_token', t); },
  clearToken() { localStorage.removeItem('vs_token'); },
  authHeaders(extra) {
    const h = extra || {};
    const t = this.token();
    if (t) h['Authorization'] = 'Bearer ' + t;
    return h;
  },
  _check(r) {
    if (r.status === 401) { API.clearToken(); if (!location.pathname.endsWith('login.html')) location.href = '/login.html'; throw new Error('Not authenticated'); }
  },
  async get(path) {
    const r = await fetch(path, { headers: this.authHeaders() });
    this._check(r);
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || 'Request failed');
    return r.json();
  },
  async post(path, body) {
    const r = await fetch(path, { method: 'POST', headers: this.authHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify(body) });
    this._check(r);
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || 'Request failed');
    return r.json();
  },
  async del(path) {
    const r = await fetch(path, { method: 'DELETE', headers: this.authHeaders() });
    this._check(r);
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || 'Request failed');
  },
  async patch(path, body) {
    const r = await fetch(path, { method: 'PATCH', headers: this.authHeaders({ 'Content-Type': 'application/json' }), body: body ? JSON.stringify(body) : undefined });
    this._check(r);
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || 'Request failed');
    return r.json().catch(() => ({}));
  },
};

// Redirect to login if not authenticated (call at the top of gated pages).
function requireAuth() {
  if (!API.token()) { location.href = '/login.html'; return false; }
  return true;
}

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const GRADE_COLOR = { A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444' };

function sevBadge(sev) {
  return `<span class="badge badge-${sev}">${sev}</span>`;
}

function confidenceBadge(conf) {
  const c = (conf || '').toLowerCase();
  return `<span class="conf-tag conf-${c}" title="Confidence: ${conf}">${conf}</span>`;
}

function gradeBadge(grade, score) {
  if (!grade) return '<span style="color:var(--muted);font-size:0.8rem">—</span>';
  const color = GRADE_COLOR[grade] || '#64748b';
  return `<span class="grade-badge" style="background:${color}" title="Risk score: ${score}/100">${grade}</span>`;
}

function tagChips(tags) {
  if (!tags) return '';
  return tags.split(',').filter(t => t.trim())
    .map(t => `<span class="tag-chip">${escHtml(t.trim())}</span>`).join('');
}

function statusBadge(status) {
  const dot = status === 'running' ? '<span class="dot pulse"></span>' : '<span class="dot"></span>';
  return `<span class="status-badge status-${status}">${dot} ${status.toUpperCase()}</span>`;
}

function sevCounts(scan) {
  const parts = [];
  if (scan.critical) parts.push(`<span class="sev-chip c">${scan.critical}C</span>`);
  if (scan.high)     parts.push(`<span class="sev-chip h">${scan.high}H</span>`);
  if (scan.medium)   parts.push(`<span class="sev-chip m">${scan.medium}M</span>`);
  if (scan.low)      parts.push(`<span class="sev-chip l">${scan.low}L</span>`);
  if (scan.info)     parts.push(`<span class="sev-chip i">${scan.info}I</span>`);
  return parts.length ? `<div class="sev-counts">${parts.join('')}</div>` : '<span style="color:var(--muted);font-size:0.8rem">—</span>';
}

function timeAgo(iso) {
  // Backend timestamps are UTC but serialized without a 'Z' suffix; add it so
  // the browser doesn't misinterpret them as local time.
  if (iso && !iso.endsWith('Z') && !iso.includes('+')) iso += 'Z';
  const d = new Date(iso);
  const diff = Math.floor((Date.now() - d) / 1000);
  if (diff < 0) {  // future (e.g. next scheduled run)
    const f = -diff;
    if (f < 60) return 'in <1m';
    if (f < 3600) return `in ${Math.floor(f/60)}m`;
    if (f < 86400) return `in ${Math.floor(f/3600)}h`;
    return `in ${Math.floor(f/86400)}d`;
  }
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return d.toLocaleDateString();
}

function escHtml(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
