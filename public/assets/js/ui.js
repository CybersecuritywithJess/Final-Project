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

  date(value) {
    if (!value) return '—';
    const d = new Date(String(value).replace(' ', 'T'));
    return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
  },

  /** "3m ago" — what an analyst actually wants on a live feed. */
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
  LOW:      'bg-forest-50 text-forest-700 ring-forest-200',
  MEDIUM:   'bg-gold-50   text-gold-600   ring-gold-100',
  HIGH:     'bg-orange-50 text-orange-700 ring-orange-200',
  CRITICAL: 'bg-rose-50   text-rose-700   ring-rose-200',
};

const STATUS_STYLES = {
  new:                 'bg-sky-50     text-sky-700     ring-sky-200',
  under_investigation: 'bg-violet-50  text-violet-700  ring-violet-200',
  confirmed_fraud:     'bg-rose-50    text-rose-700    ring-rose-200',
  false_positive:      'bg-stone-100  text-stone-600   ring-stone-200',
  resolved:            'bg-forest-50  text-forest-700  ring-forest-200',
  closed:              'bg-stone-100  text-stone-600   ring-stone-200',
  active:              'bg-forest-50  text-forest-700  ring-forest-200',
  locked:              'bg-rose-50    text-rose-700    ring-rose-200',
  flagged:             'bg-rose-50    text-rose-700    ring-rose-200',
  completed:           'bg-forest-50  text-forest-700  ring-forest-200',
  failed:              'bg-stone-100  text-stone-600   ring-stone-200',
  pending:             'bg-gold-50    text-gold-600    ring-gold-100',
};

function riskBadge(level) {
  const style = RISK_STYLES[level] || RISK_STYLES.LOW;
  return `<span class="inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-bold tracking-wide ring-1 ${style}">${level}</span>`;
}

function statusBadge(status) {
  const style = STATUS_STYLES[status] || STATUS_STYLES.closed;
  return `<span class="inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ${style}">${fmt.label(status)}</span>`;
}

/** The colour a risk score should be shown in. */
function riskColor(score) {
  if (score >= 95) return 'rose';
  if (score >= 70) return 'orange';
  if (score >= 40) return 'gold';
  return 'forest';
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
    { href: '/bank.html', label: 'My accounts' },
  ],
  auditor: [
    { href: '/dashboard.html', label: 'Dashboard' },
    { href: '/alerts.html', label: 'Fraud alerts' },
    { href: '/audits.html', label: 'Audit log' },
    { href: '/assistant.html', label: 'AI assistant' },
  ],
  admin: [
    { href: '/dashboard.html', label: 'Dashboard' },
    { href: '/alerts.html', label: 'Fraud alerts' },
    { href: '/audits.html', label: 'Audit log' },
    { href: '/assistant.html', label: 'AI assistant' },
    { href: '/admin.html', label: 'Administration' },
    { href: '/bank.html', label: 'Demo bank' },
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
    // Send people to their own home rather than showing them a dead end.
    window.location.href = roleHome(user.role);
    return null;
  }

  const links = (NAV[user.role] || []).map((item) => {
    const active = item.href === activePath;
    const classes = active
      ? 'bg-forest-50 text-forest-800 font-semibold'
      : 'text-stone-600 hover:bg-stone-100 hover:text-ink';
    return `
      <a href="${item.href}"
         class="flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${classes}">
        ${active ? '<span class="h-1.5 w-1.5 rounded-full bg-forest-700"></span>' : '<span class="h-1.5 w-1.5"></span>'}
        ${item.label}
      </a>`;
  }).join('');

  const initials = user.full_name.split(' ').map((w) => w[0]).slice(0, 2).join('');

  const shell = document.createElement('div');
  shell.innerHTML = `
    <aside class="fixed inset-y-0 left-0 z-20 flex w-60 flex-col border-r border-stone-200 bg-white">

      <a href="/" class="flex items-center gap-2.5 border-b border-stone-200 px-5 py-4">
        <span class="grid h-9 w-9 place-items-center rounded-lg bg-forest-800 text-sm font-bold text-white">UBA</span>
        <span class="font-display text-base font-semibold tracking-tight text-ink">
          Union Bank of <span class="text-forest-700">Africa</span>
        </span>
      </a>

      <nav class="flex-1 space-y-1 p-3">${links}</nav>

      <div class="border-t border-stone-200 p-3">
        <div class="mb-2 flex items-center gap-2.5 px-2 py-1">
          <span class="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-forest-100 text-xs font-bold text-forest-800">
            ${esc(initials)}
          </span>
          <div class="min-w-0">
            <div class="truncate text-sm font-semibold text-ink">${esc(user.full_name)}</div>
            <div class="text-xs capitalize text-stone-500">${esc(user.role)}</div>
          </div>
        </div>
        <button id="logout-btn"
          class="w-full rounded-lg px-3 py-2 text-left text-sm font-medium text-stone-500 transition hover:bg-rose-50 hover:text-rose-700">
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

/** A brief message in the corner. Errors and alerts stay put a little longer. */
function toast(message, type = 'info') {
  const colors = {
    info:    'bg-white text-ink ring-stone-200',
    success: 'bg-forest-800 text-white ring-forest-900',
    error:   'bg-rose-600 text-white ring-rose-700',
    alert:   'bg-orange-600 text-white ring-orange-700',
  };

  const el = document.createElement('div');
  el.className = `fixed bottom-6 right-6 z-50 max-w-sm rounded-xl px-4 py-3 text-sm
                  font-medium shadow-2xl ring-1 ${colors[type]}`;
  el.innerHTML = message;
  document.body.appendChild(el);

  setTimeout(() => el.remove(), type === 'error' || type === 'alert' ? 6000 : 3000);
}

/** The page-level spinner. */
function loading(container, message = 'Loading…') {
  container.innerHTML = `
    <div class="flex items-center justify-center gap-3 py-20 text-stone-400">
      <div class="h-5 w-5 animate-spin rounded-full border-2 border-stone-200 border-t-forest-700"></div>
      <span class="text-sm">${message}</span>
    </div>`;
}
