/**
 * The AI Audit Assistant, as a floating chat widget.
 *
 * Include this on any auditor/admin page and it drops a launcher button in the
 * bottom-right corner that opens a compact chat panel — the same assistant as
 * the full page, reachable without leaving whatever you're investigating.
 *
 * It renders only for auditors and admins: it asks the assistant config
 * endpoint first, and that endpoint is role-gated, so a customer (or a signed
 * -out visitor) simply never sees the button. Relies on api.js and ui.js
 * (esc, fmt, riskBadge, statusBadge) already being loaded on the page.
 */
(function () {
  // The full page already IS the assistant — no floating copy needed there.
  if (location.pathname === '/assistant.html') return;

  document.addEventListener('DOMContentLoaded', init);

  async function init() {
    let config;
    try {
      config = await API.get('assistant.php?action=config');
    } catch {
      return; // not an auditor/admin, or signed out — no widget
    }
    mount(config);
  }

  function mount(config) {
    const claude = config.claude_enabled;

    const root = document.createElement('div');
    root.innerHTML = `
      <button id="aiw-launch" aria-label="Open the AI assistant"
        class="fixed bottom-6 right-6 z-40 flex items-center gap-2 rounded-full bg-forest-800 px-5 py-3.5
               text-sm font-semibold text-white shadow-xl shadow-forest-900/20 transition
               hover:-translate-y-0.5 hover:bg-forest-900">
        Ask the AI assistant
      </button>

      <section id="aiw-panel"
        class="fixed bottom-6 right-6 z-50 hidden h-[560px] max-h-[85vh] w-[400px] max-w-[92vw]
               flex-col overflow-hidden rounded-2xl border border-stone-200 bg-white shadow-2xl">

        <header class="flex items-center justify-between border-b border-stone-200 bg-white px-4 py-3">
          <div>
            <p class="font-display text-sm font-semibold text-ink">AI Audit Assistant</p>
            <p class="text-[11px] ${claude ? 'text-forest-700' : 'text-stone-400'}">
              ${claude ? 'Powered by Claude' : 'Built-in engine'} · read-only
            </p>
          </div>
          <button id="aiw-close" aria-label="Close"
            class="rounded-lg px-2 py-1 text-sm font-medium text-stone-400 transition hover:bg-stone-100 hover:text-ink">
            Close
          </button>
        </header>

        <div id="aiw-thread" class="flex-1 space-y-4 overflow-y-auto bg-[#fdfcfa] px-4 py-4"></div>

        <form id="aiw-form" class="flex items-end gap-2 border-t border-stone-200 bg-white px-3 py-3">
          <textarea id="aiw-input" rows="1" required placeholder="Ask about the audit data…"
            class="max-h-24 flex-1 resize-none rounded-xl border border-stone-300 px-3 py-2 text-sm
                   outline-none transition focus:border-forest-700 focus:ring-2 focus:ring-forest-700/15"></textarea>
          <button type="submit" id="aiw-send"
            class="rounded-xl bg-forest-800 px-3.5 py-2 text-sm font-semibold text-white transition
                   hover:bg-forest-900 disabled:opacity-50">Ask</button>
        </form>
      </section>`;
    document.body.appendChild(root);

    const launch = root.querySelector('#aiw-launch');
    const panel = root.querySelector('#aiw-panel');
    const thread = root.querySelector('#aiw-thread');
    const form = root.querySelector('#aiw-form');
    const input = root.querySelector('#aiw-input');

    let greeted = false;
    const open = () => {
      panel.classList.remove('hidden');
      panel.classList.add('flex');
      launch.classList.add('hidden');
      if (!greeted) { greet(config.suggestions); greeted = true; }
      input.focus();
    };
    const close = () => {
      panel.classList.add('hidden');
      panel.classList.remove('flex');
      launch.classList.remove('hidden');
    };

    launch.addEventListener('click', open);
    root.querySelector('#aiw-close').addEventListener('click', close);

    form.addEventListener('submit', (e) => { e.preventDefault(); submit(); });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(); }
    });
    input.addEventListener('input', () => {
      input.style.height = 'auto';
      input.style.height = Math.min(input.scrollHeight, 96) + 'px';
    });

    // ---- chat

    function greet(suggestions) {
      const chips = (suggestions || []).slice(0, 6).map((s) =>
        `<button class="aiw-chip rounded-full border border-stone-300 bg-white px-2.5 py-1 text-[11px]
                        text-stone-700 transition hover:border-forest-700 hover:text-forest-800">${esc(s)}</button>`).join('');
      thread.insertAdjacentHTML('beforeend', `
        <div class="rounded-xl border border-stone-200 bg-white p-3">
          <p class="text-xs text-stone-600">Ask me about logins, transactions, alerts, or a customer.</p>
          <div class="mt-2.5 flex flex-wrap gap-1.5">${chips}</div>
        </div>`);
      wireChips();
    }

    function wireChips() {
      thread.querySelectorAll('.aiw-chip').forEach((b) =>
        b.addEventListener('click', () => submit(b.textContent)));
    }

    function addQuestion(text) {
      thread.insertAdjacentHTML('beforeend', `
        <div class="flex justify-end">
          <div class="max-w-[85%] rounded-2xl rounded-br-sm bg-forest-800 px-3 py-2 text-xs text-white">${esc(text)}</div>
        </div>`);
      scroll();
    }

    function addThinking() {
      const id = 'aiw-t' + Date.now();
      thread.insertAdjacentHTML('beforeend', `
        <div id="${id}" class="inline-flex items-center gap-2 rounded-2xl rounded-bl-sm border border-stone-200 bg-white px-3 py-2 text-xs text-stone-400">
          <span class="h-3 w-3 animate-spin rounded-full border-2 border-stone-200 border-t-forest-700"></span>
          Searching the audit log…
        </div>`);
      scroll();
      return id;
    }

    function addAnswer(result) {
      const table = result.rows && result.rows.length ? miniTable(result.rows) : '';
      const sql = result.sql
        ? `<details class="mt-2"><summary class="cursor-pointer text-[11px] text-stone-400 hover:text-stone-600">query</summary>
             <pre class="mt-1 overflow-x-auto rounded bg-stone-900 p-2 text-[10px] leading-relaxed text-stone-100">${esc(result.sql)}</pre></details>` : '';
      const chips = result.suggestions
        ? `<div class="mt-2 flex flex-wrap gap-1.5">${result.suggestions.slice(0, 6).map((s) =>
             `<button class="aiw-chip rounded-full border border-stone-300 bg-white px-2.5 py-1 text-[11px] text-stone-700 transition hover:border-forest-700 hover:text-forest-800">${esc(s)}</button>`).join('')}</div>` : '';
      const note = result.fallback_note
        ? `<p class="mt-2 rounded bg-amber-50 px-2 py-1 text-[11px] text-amber-800">${esc(result.fallback_note)}</p>` : '';

      thread.insertAdjacentHTML('beforeend', `
        <div class="rounded-2xl rounded-bl-sm border border-stone-200 bg-white p-3">
          <p class="mb-1 text-[10px] font-semibold uppercase tracking-wide text-stone-400">${esc(result.interpretation || 'Answer')}</p>
          <p class="text-xs leading-relaxed text-ink">${esc(result.answer)}</p>
          ${table}${sql}${note}${chips}
        </div>`);
      wireChips();
      scroll();
    }

    /** A compact table: first three helpful columns keep the panel readable. */
    function miniTable(rows) {
      const all = Object.keys(rows[0]);
      const cols = all.slice(0, 4);
      const head = cols.map((c) => `<th class="px-2 py-1 text-left font-semibold text-stone-500">${esc(fmt.label(c))}</th>`).join('');
      const body = rows.slice(0, 12).map((r) => `
        <tr class="border-t border-stone-100">
          ${cols.map((c) => `<td class="px-2 py-1 text-stone-700">${cell(c, r[c])}</td>`).join('')}
        </tr>`).join('');
      const more = rows.length > 12 ? `<p class="px-2 py-1 text-[10px] text-stone-400">+${rows.length - 12} more — open the AI assistant page for the full list</p>` : '';
      return `<div class="mt-2 overflow-x-auto rounded-lg border border-stone-200">
                <table class="min-w-full text-[11px]"><thead class="bg-stone-50">${head}</thead><tbody>${body}</tbody></table>${more}
              </div>`;
    }

    function cell(col, value) {
      if (value === null || value === undefined || value === '') return '<span class="text-stone-300">—</span>';
      if (/risk_level/.test(col)) return riskBadge(String(value));
      if (/^status$/.test(col)) return statusBadge(String(value));
      if (/(amount|balance|total|value)/.test(col)) return esc(fmt.money(value));
      if (/(created_at|last_|_at)/.test(col)) return esc(fmt.dateTime(value));
      if (/event_type|type/.test(col)) return esc(fmt.label(value));
      const s = String(value);
      return esc(s.length > 40 ? s.slice(0, 40) + '…' : s);
    }

    async function submit(text) {
      const question = (text ?? input.value).trim();
      if (!question) return;
      input.value = '';
      input.style.height = 'auto';
      addQuestion(question);
      const tid = addThinking();
      root.querySelector('#aiw-send').disabled = true;
      try {
        const result = await API.post('assistant.php?action=ask', { question });
        document.getElementById(tid)?.remove();
        addAnswer(result);
      } catch (err) {
        document.getElementById(tid)?.remove();
        addAnswer({ interpretation: 'Error', answer: err.message, rows: [] });
      } finally {
        root.querySelector('#aiw-send').disabled = false;
        input.focus();
      }
    }

    function scroll() { thread.scrollTop = thread.scrollHeight; }
  }
})();
