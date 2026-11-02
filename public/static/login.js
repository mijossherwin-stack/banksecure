(() => {
  const { api, fmtCd } = window.BS;
  const $ = (id) => document.getElementById(id);
  const form = $('loginForm');
  const portal = form.dataset.portal;
  const endpoint = portal === 'admin' ? '/api/admin/login' : '/api/login';
  const msg = $('msg');
  const btn = $('submitBtn');
  const baseTitle = document.title;
  let lockTimer = null; let fwTimer = null;
  let lockedUser = null;

  const setMsg = (text, kind) => { msg.textContent = text || ''; msg.className = 'msg ' + (kind || ''); };

  // ---------- exact device location (GPS / Wi-Fi), asked through the browser's permission prompt
  const geoNote = $('geoNote');
  let geoPromise = null;
  function setGeoNote(text, kind) { if (geoNote) { geoNote.textContent = text; geoNote.className = 'geo-note ' + (kind || ''); } }
  function getDeviceLocation() {
    if (geoPromise) return geoPromise;
    geoPromise = new Promise((resolve) => {
      if (!window.isSecureContext) return resolve({ error: 'insecure-context' });
      if (!navigator.geolocation) return resolve({ error: 'unsupported' });
      setGeoNote('📍 Waiting for location permission…');
      navigator.geolocation.getCurrentPosition(
        (p) => resolve({ lat: p.coords.latitude, lon: p.coords.longitude, accuracy: p.coords.accuracy }),
        (err) => resolve({ error: err.code === 1 ? 'denied' : err.code === 3 ? 'timeout' : 'unavailable' }),
        { enableHighAccuracy: true, timeout: 15000, maximumAge: 30000 });
    }).then((r) => {
      if (r.error) {
        const why = { denied: 'Location permission was declined', 'insecure-context': 'Location needs HTTPS (or localhost)', unsupported: 'This browser cannot share location', timeout: 'Location timed out', unavailable: 'Location is unavailable on this device' }[r.error] || 'Location not shared';
        setGeoNote(`📍 ${why}. Your network location will be used instead.`, 'off');
        if (r.error === 'timeout' || r.error === 'unavailable') geoPromise = null; // allow a retry on the next attempt
      } else {
        setGeoNote(`📍 Location shared · accurate to ±${Math.round(r.accuracy)} m`, 'on');
      }
      return r;
    });
    return geoPromise;
  }
  const withTimeout = (p, ms) => Promise.race([p, new Promise((r) => setTimeout(() => r({ error: 'timeout' }), ms))]);
  // ask as soon as the person starts signing in, so the position is ready by the time they press the button
  form.addEventListener('focusin', () => { getDeviceLocation(); }, { once: true });
  if (navigator.permissions && navigator.permissions.query) {
    navigator.permissions.query({ name: 'geolocation' }).then((st) => { if (st.state === 'granted') getDeviceLocation(); }).catch(() => {});
  }

  $('togglePw').addEventListener('click', (e) => {
    const show = form.password.type === 'password';
    form.password.type = show ? 'text' : 'password';
    e.currentTarget.textContent = show ? 'Hide' : 'Show';
    e.currentTarget.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  });

  // ---------- account lock countdown (per account – other accounts can still sign in)
  function applyLockState() {
    const isLocked = lockedUser !== null && form.username.value.trim().toLowerCase() === lockedUser;
    form.password.disabled = isLocked;
    btn.disabled = isLocked || fwBlocked;
    $('lockBox').classList.toggle('hidden', !isLocked);
  }
  function startLock(seconds, total, username) {
    lockedUser = username;
    const until = Date.now() + seconds * 1000;
    clearInterval(lockTimer);
    $('lockText').textContent = portal === 'admin'
      ? 'Too many failed attempts. Admin sign-in is paused. Try again when the timer reaches 00:00.'
      : `Too many failed attempts for “${username}”. You can try again when the timer reaches 00:00.`;
    setMsg('');
    const tick = () => {
      const left = Math.max(0, Math.ceil((until - Date.now()) / 1000));
      $('lockTimer').textContent = fmtCd(left);
      $('lockBar').style.width = Math.min(100, (left / (total || 300)) * 100) + '%';
      document.title = left > 0 ? `🔒 ${fmtCd(left)} · Locked` : baseTitle;
      if (left <= 0) {
        clearInterval(lockTimer);
        lockedUser = null;
        applyLockState();
        setMsg('The lock has ended. You can sign in again.', 'ok');
        form.password.focus();
      }
    };
    tick();
    lockTimer = setInterval(tick, 250);
    applyLockState();
  }
  form.username.addEventListener('input', () => { if (lockedUser !== null) applyLockState(); });

  // ---------- firewall block (whole network)
  let fwBlocked = false;
  function showFirewall(retryAfter) {
    if (!$('fwBox')) { setMsg('Access from your network is blocked.', 'err'); return; }
    fwBlocked = true;
    $('fwBox').classList.remove('hidden');
    Array.from(form.elements).forEach((el) => { el.disabled = true; });
    clearInterval(fwTimer);
    if (retryAfter == null) {
      $('fwTimer').textContent = 'Blocked';
      $('fwText').textContent = 'Access from your network is blocked because of suspicious activity. Please contact the bank to restore access.';
      return;
    }
    const until = Date.now() + retryAfter * 1000;
    $('fwText').textContent = 'Access from your network is blocked because of suspicious activity. The block lifts automatically when the timer ends.';
    const tick = () => {
      const left = Math.max(0, Math.ceil((until - Date.now()) / 1000));
      $('fwTimer').textContent = fmtCd(left);
      if (left <= 0) { clearInterval(fwTimer); checkStatus(); }
    };
    tick();
    fwTimer = setInterval(tick, 500);
  }
  function hideFirewall() {
    if (!fwBlocked) return;
    fwBlocked = false;
    $('fwBox').classList.add('hidden');
    Array.from(form.elements).forEach((el) => { el.disabled = false; });
    applyLockState();
  }

  async function checkStatus() {
    try {
      const d = await api('/api/status');
      if ($('policyText')) $('policyText').textContent = `${d.maxAttempts} wrong passwords lock the account for ${d.lockMinutes} minute${d.lockMinutes === 1 ? '' : 's'}.`;
      if (portal === 'customer') { if (d.firewall.blocked) showFirewall(d.firewall.retryAfter); else hideFirewall(); }
    } catch { /* offline */ }
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = form.username.value.trim().toLowerCase();
    if (!username || !form.password.value) return setMsg('Enter your username and password.', 'err');
    btn.disabled = true;
    setMsg('Checking your device location…');
    const device = await withTimeout(getDeviceLocation(), 20000);
    setMsg('Verifying…');
    try {
      const d = await api(endpoint, { method: 'POST', body: { username, password: form.password.value, device } });
      if (d.ok) { setMsg('Signed in. Redirecting…', 'ok'); location.href = d.redirect; return; }
      form.password.value = '';
      if (d.firewall) { setMsg(''); showFirewall(d.retryAfter); return; }
      if (d.locked) { startLock(d.retryAfter, d.lockSeconds, username); return; }
      const left = typeof d.attemptsLeft === 'number'
        ? ` ${d.attemptsLeft} attempt${d.attemptsLeft === 1 ? '' : 's'} left before the account is locked.` : '';
      setMsg((d.message || 'Sign-in failed.') + left, d.attemptsLeft <= 2 ? 'err' : 'warn');
    } catch {
      setMsg('Network error. Please try again.', 'err');
    } finally {
      if (!fwBlocked) applyLockState();
      if (lockedUser === null && !fwBlocked) btn.disabled = false;
    }
  });

  checkStatus();
})();
