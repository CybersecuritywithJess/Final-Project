/**
 * Shared UI: the page shell, formatting helpers, and the risk/status badges
 * that have to look the same everywhere for an auditor to read them at a glance.
 */

// -------------------------------------------------------------- formatting

const fmt = {
  money(amount) {
    if (amount === null || amount === undefined || amount === '') return '—';
    return 'KES ' + Number(amount).toLocaleString('en-KE', { maximumFractionDigits: 0 });
  },

  number(n) {
    return Number(n || 0).toLocaleString('en-KE');
  },

  /** "14 Jul 2026, 09:22" — MySQL DATETIME needs the space swapped for a T. */
  dateTime(value) {
    if (!value) return '—';
    const d = new Date(String(value).replace(' ', 'T'));
    return d.toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  },

  time(value) {
    if (!value) return '—';
    const d = new Date(String(value).replace(' ', 'T'));
    return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  },

  date(value) {
    if (!value) return '—';
    const d = new Date(String(value).replace(' ', 'T'));
    return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
  },

  /** "3 minutes ago" — what an analyst actually wants on a live feed. */
  ago(value) {
    if (!value) return '—';
    const seconds = Math.floor((Date.now() - new Date(String(value).replace(' ', 'T'))) / 1000);
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  },

  /** snake_case_event -> "Snake case event" */
  label(key) {
    if (!key) return '—';
    const s = String(key).replace(/_/g, ' ');
    return s.charAt(0).toUpperCase() + s.slice(1);
  },
};

// ------------------------------------------------------------------ badges

const RISK_STYLES = {
  LOW:      'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30',
  MEDIUM:   'bg-amber-500/10  text-amber-400   ring-amber-500/30',
  HIGH:     'bg-orange-500/10 text-orange-400  ring-orange-500/30',
  CRITICAL: 'bg-rose-500/10   text-rose-400    ring-rose-500/30',
};

const STATUS_STYLES = {
  new:                 'bg-sky-500/10     text-sky-400     ring-sky-500/30',
  under_investigation: 'bg-violet-500/10  text-violet-400  ring-violet-500/30',
  confirmed_fraud:     'bg-rose-500/10    text-rose-400    ring-rose-500/30',
  false_positive:      'bg-slate-500/10   text-slate-400   ring-slate-500/30',
  resolved:            'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30',
  closed:              'bg-slate-500/10   text-slate-400   ring-slate-500/30',
  active:              'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30',
  locked:              'bg-rose-500/10    text-rose-400    ring-rose-500/30',
  flagged:             'bg-rose-500/10    text-rose-400    ring-rose-500/30',
  completed:           'bg-emerald-500/10 text-emerald-400 ring-emerald-500/30',
  failed:              'bg-slate-500/10   text-slate-400   ring-slate-500/30',
};

function riskBadge(level) {
  const style = RISK_STYLES[level] || RISK_STYLES.LOW;
  return `<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ring-1 ${style}">${level}</span>`;
}

function statusBadge(status) {
  const style = STATUS_STYLES[status] || STATUS_STYLES.closed;
  return `<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ${style}">${fmt.label(status)}</span>`;
}

/** Escape anything that came from a user before it goes near innerHTML. */
function esc(value) {
  const div = document.createElement('div');
  div.textContent = value ?? '';
  return div.innerHTML;
}

// ------------------------------------------------------------------- shell

const NAV = {
  customer: [
    { href: '/bank.html', label: 'My Bank', icon: '🏦' },
  ],
  auditor: [
    { href: '/dashboard.html', label: 'Dashboard', icon: '📊' },
    { href: '/alerts.html', label: 'Fraud Alerts', icon: '🚨' },
    { href: '/audits.html', label: 'Audit Log', icon: '🔍' },
  ],
  admin: [
    { href: '/dashboard.html', label: 'Dashboard', icon: '📊' },
    { href: '/alerts.html', label: 'Fraud Alerts', icon: '🚨' },
    { href: '/audits.html', label: 'Audit Log', icon: '🔍' },
    { href: '/admin.html', label: 'Administration', icon: '⚙️' },
    { href: '/bank.html', label: 'Demo Bank', icon: '🏦' },
  ],
};

/**
 * Verify the session, draw the sidebar, and hand the page its user.
 * Every protected page starts with this.
 */
async function mountShell(activePath, allowedRoles = null) {
  let user;
  try {
    ({ user } = await API.me());
  } catch {
    window.location.href = '/login.html';
    return null;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    // Send people to their own home rather than showing a dead end.
    window.location.href = user.role === 'customer' ? '/bank.html' : '/dashboard.html';
    return null;
  }

  const links = (NAV[user.role] || []).map((item) => {
    const active = item.href === activePath;
    const classes = active
      ? 'bg-sky-500/10 text-sky-300 ring-1 ring-sky-500/30'
      : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200';
    return `
      <a href="${item.href}" class="flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition ${classes}">
        <span class="text-base">${item.icon}</span>${item.label}
      </a>`;
  }).join('');

  const shell = document.createElement('div');
  shell.innerHTML = `
    <aside class="fixed inset-y-0 left-0 z-20 flex w-60 flex-col border-r border-slate-800 bg-slate-900">
      <div class="flex items-center gap-2 border-b border-slate-800 px-5 py-4">
        <span class="text-xl">🛡️</span>
        <div>
          <div class="text-sm font-bold leading-tight text-slate-100">Audit Tracking</div>
          <div class="text-[11px] leading-tight text-slate-500">Demo Bank</div>
        </div>
      </div>

      <nav class="flex-1 space-y-1 p-3">${links}</nav>

      <div class="border-t border-slate-800 p-3">
        <div class="mb-2 px-2">
          <div class="truncate text-sm font-medium text-slate-200">${esc(user.full_name)}</div>
          <div class="text-xs capitalize text-slate-500">${esc(user.role)}</div>
        </div>
        <button id="logout-btn"
          class="w-full rounded-lg px-3 py-2 text-left text-sm font-medium text-slate-400 transition hover:bg-slate-800 hover:text-rose-400">
          Sign out
        </button>
      </div>
    </aside>`;

  document.body.prepend(shell.firstElementChild);
  document.getElementById('logout-btn').addEventListener('click', async () => {
    await API.logout().catch(() => {});
    window.location.href = '/login.html';
  });

  return user;
}

/** A brief message in the corner. Errors stay put a little longer. */
function toast(message, type = 'info') {
  const colors = {
    info:    'bg-slate-800 text-slate-100 ring-slate-700',
    success: 'bg-emerald-900/90 text-emerald-100 ring-emerald-700',
    error:   'bg-rose-900/90 text-rose-100 ring-rose-700',
    alert:   'bg-orange-900/90 text-orange-100 ring-orange-700',
  };

  const el = document.createElement('div');
  el.className = `pointer-events-none fixed bottom-6 right-6 z-50 max-w-sm rounded-xl px-4 py-3
                  text-sm font-medium shadow-2xl ring-1 ${colors[type]} animate-[fadein_.15s_ease-out]`;
  el.innerHTML = message;
  document.body.appendChild(el);

  setTimeout(() => el.remove(), type === 'error' || type === 'alert' ? 6000 : 3000);
}

/** The page-level spinner. */
function loading(container, message = 'Loading…') {
  container.innerHTML = `
    <div class="flex items-center justify-center gap-3 py-20 text-slate-500">
      <div class="h-5 w-5 animate-spin rounded-full border-2 border-slate-700 border-t-sky-400"></div>
      <span class="text-sm">${message}</span>
    </div>`;
}
