(() => {
  const { h, api, fmtDate, peso, ICON } = window.BS;
  const $ = (id) => document.getElementById(id);
  const describe = (l) => (l ? `${fmtDate(l.time)} · ${l.ip}${l.location ? ' · ' + l.location : ''}` : '—');
  const TYPE = { LOGIN_FAILED: 'Wrong password', ACCOUNT_LOCKED: 'Account locked', LOCKED_ATTEMPT: 'Attempt while locked', FIREWALL_BLOCKED: 'Blocked by firewall' };

  function render(d) {
    const first = d.user.name.split(' ')[0];
    $('who').textContent = d.user.name;
    const hr = new Date().getHours();
    $('greet').textContent = `${hr < 12 ? 'Good morning' : hr < 18 ? 'Good afternoon' : 'Good evening'}, ${first}`;
    const s = d.security;
    $('lastSeen').textContent = s.previous ? `Your previous sign-in was ${describe(s.previous)}.` : 'Welcome to BankSecure Online Banking. This is your first recorded sign-in.';

    $('accounts').replaceChildren(...d.accounts.map((a) => h('article', { class: 'acct' },
      h('div', { class: 'type' }, a.type === 'Credit Card' ? 'Credit Card · outstanding' : a.type + ' account'),
      h('div', { class: 'bal' }, peso.format(a.type === 'Credit Card' ? Math.abs(a.balance) : a.balance)),
      h('div', { class: 'no' }, a.number + (a.limit ? ` · limit ${peso.format(a.limit)}` : '')))));

    $('txns').replaceChildren(...d.transactions.map((t) => h('tr', {},
      h('td', { class: 'nowrap' }, new Date(t.date + 'T00:00:00').toLocaleDateString(undefined, { month: 'short', day: 'numeric' })),
      h('td', {}, t.description),
      h('td', { class: 'sub' }, t.account),
      h('td', { class: 'num nowrap' + (t.amount > 0 ? ' amt-in' : '') }, (t.amount > 0 ? '+' : '−') + peso.format(Math.abs(t.amount))))));

    const warn = s.failedSinceLast > 0;
    $('shield').className = 'shield' + (warn ? ' warn' : '');
    $('shieldIcon').innerHTML = warn ? ICON.shieldAlert : ICON.shield;
    $('shieldTitle').textContent = warn ? `${s.failedSinceLast} failed sign-in attempt${s.failedSinceLast === 1 ? '' : 's'} since your last visit` : 'Your account is protected';
    $('shieldText').textContent = warn
      ? ' If these weren\'t you, someone may be guessing your password. The attempts were stopped by account lockout and the firewall.'
      : ' No failed sign-in attempts since your last visit.';
    $('curLogin').textContent = describe(s.current);
    $('prevLogin').textContent = describe(s.previous);
    $('failCount').textContent = String(s.failedSinceLast);
    $('policy').textContent = `${s.policy.maxAttempts} tries → ${s.policy.lockMinutes} min lock`;

    $('attemptsWrap').classList.toggle('hidden', !s.failedRecent.length);
    $('attempts').replaceChildren(...s.failedRecent.map((a) => h('div', { class: 'att' },
      h('span', {}, `${TYPE[a.type] || a.type} · ${a.ip}${a.location ? ' · ' + a.location : ''}`),
      h('span', { class: 'sub nowrap' }, fmtDate(a.time)))));

    $('alertsWrap').classList.toggle('hidden', !s.alerts.length);
    $('custAlerts').replaceChildren(...s.alerts.map((a) => h('div', { class: 'att' },
      h('span', {}, h('span', { class: 'sev ' + a.severity }, a.severity), ' ', a.title),
      h('span', { class: 'sub nowrap' }, fmtDate(a.time)))));
  }

  async function load() {
    try {
      const d = await api('/api/me', { redirect401: '/' });
      if (d.__status === 403) { location.href = '/'; return; }
      render(d);
    } catch { /* redirected */ }
  }
  $('logout').addEventListener('click', async () => {
    const d = await api('/api/logout', { method: 'POST' });
    location.href = d.redirect || '/';
  });
  load();
  setInterval(load, 60000);
})();
