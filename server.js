'use strict';
/**
 * BankSecure – Banking Login Protection
 * ---------------------------------------------------------------------------
 * Zero-dependency Node.js (18+) server. Run with:  node server.js
 *
 *  • Bank customer login + account dashboard
 *  • Account lockout: N failed attempts -> account locked for M minutes
 *  • Detection rules -> suspicious-login alerts
 *      brute force · password spray · distributed attack · success after failures
 *      new country · account lockout · admin-portal brute force · IP auto-blocked
 *  • Firewall: automatic + manual IP / CIDR blocking, allowlist, hit counters
 *  • Security event log with IP geolocation (ip-api.com, fallback ipwho.is)
 *  • Exact device location: the login page asks the browser for GPS / Wi-Fi
 *    location (the user approves it in the browser's permission prompt),
 *    and the server turns the coordinates into a street address (OpenStreetMap Nominatim)
 *  • Attack simulator: synthetic attackers (RFC 5737 documentation IPs) that
 *    run only against this app's own login logic – never against anything else.
 */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ============================================================== config
const PORT = Number(process.env.PORT) || 3000;
const TRUST_PROXY = process.env.TRUST_PROXY === '1';   // set to 1 behind nginx / Cloudflare / a load balancer
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1'; // set to 1 when served over HTTPS
const SESSION_IDLE_MS = 15 * 60 * 1000;
const MIN = 60 * 1000;
const MAX_EVENTS = 10000;
const MAX_ALERTS = 1000;
const DATA_DIR = path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');

const DEFAULT_SETTINGS = {
  maxAccountFailures: 5,       // failed logins before an account is locked
  accountLockMinutes: 5,       // how long the account stays locked
  failureWindowMinutes: 15,    // failures older than this are forgotten
  autoBlock: true,             // firewall automatically blocks attacking IPs
  ipFailureThreshold: 15,      // failed logins from one IP (any accounts) -> auto-block
  ipBlockMinutes: 30,          // auto-block duration
  bruteForceThreshold: 5,      // failures from one IP on one account -> BRUTE_FORCE alert
  sprayAccountThreshold: 4,    // distinct accounts failed from one IP -> PASSWORD_SPRAY alert + block
  distributedIpThreshold: 4,   // distinct IPs failing on one account -> DISTRIBUTED_ATTACK alert
  detectionWindowMinutes: 10   // look-back window for the detection rules
};
const SETTING_LIMITS = {
  maxAccountFailures: [1, 50], accountLockMinutes: [1, 1440], failureWindowMinutes: [1, 1440],
  ipFailureThreshold: [2, 1000], ipBlockMinutes: [1, 10080], bruteForceThreshold: [2, 100],
  sprayAccountThreshold: [2, 100], distributedIpThreshold: [2, 100], detectionWindowMinutes: [1, 60]
};

// ============================================================== storage
fs.mkdirSync(DATA_DIR, { recursive: true });
const dataFile = (name) => path.join(DATA_DIR, name);
function readJson(name, fallback) {
  try { return JSON.parse(fs.readFileSync(dataFile(name), 'utf8')); } catch { return fallback; }
}
function writeJson(name, data) {
  const f = dataFile(name);
  fs.writeFileSync(f + '.tmp', JSON.stringify(data));
  fs.renameSync(f + '.tmp', f);
}
const saveTimers = new Map();
const savers = {
  'users.json': () => users, 'events.json': () => events, 'alerts.json': () => alerts,
  'firewall.json': () => firewall, 'settings.json': () => settings
};
function save(name) {
  clearTimeout(saveTimers.get(name));
  saveTimers.set(name, setTimeout(() => { saveTimers.delete(name); writeJson(name, savers[name]()); }, 300));
}
function flushAll() {
  for (const [name, t] of saveTimers) { clearTimeout(t); writeJson(name, savers[name]()); }
  saveTimers.clear();
}
process.on('SIGINT', () => { flushAll(); process.exit(0); });
process.on('SIGTERM', () => { flushAll(); process.exit(0); });

// ============================================================== passwords (scrypt)
const SCRYPT = { N: 16384, r: 8, p: 1 };
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return `scrypt$${salt.toString('hex')}$${crypto.scryptSync(pw, salt, 32, SCRYPT).toString('hex')}`;
}
function verifyPassword(pw, stored) {
  return new Promise((resolve) => {
    const [, saltHex, hashHex] = String(stored).split('$');
    crypto.scrypt(pw, Buffer.from(saltHex, 'hex'), 32, SCRYPT, (err, h) => {
      resolve(!err && crypto.timingSafeEqual(h, Buffer.from(hashHex, 'hex')));
    });
  });
}
const DUMMY_HASH = hashPassword(crypto.randomBytes(12).toString('hex')); // equalises timing for unknown users

// ============================================================== users (seeded starter data)
function last4(seed) { return String(crypto.createHash('sha256').update(seed).digest().readUInt16BE(0) % 9000 + 1000); }
function sampleTransactions(scale) {
  const rows = [
    [1, 'InstaPay transfer – received', 2500, 'Savings'],
    [2, 'Meralco – electricity bill', -3420.55, 'Checking'],
    [3, 'SM Supermarket', -2875.4, 'Credit Card'],
    [5, 'Payroll credit', 42500, 'Savings'],
    [6, 'PLDT Fibr – internet', -1899, 'Checking'],
    [8, 'InstaPay transfer – sent', -5000, 'Savings'],
    [9, 'Grab ride', -312, 'Credit Card'],
    [11, 'Interest earned', 186.72, 'Savings'],
    [13, 'Maynilad – water bill', -684.3, 'Checking'],
    [15, 'ATM withdrawal', -5000, 'Savings'],
    [18, 'Credit card payment', 12000, 'Credit Card'],
    [20, 'Payroll credit', 42500, 'Savings']
  ];
  return rows.map(([d, description, amt, account], i) => ({
    id: 'TX' + (10400 + i), date: new Date(Date.now() - d * 86400000).toISOString().slice(0, 10),
    description, account, amount: Math.round(amt * scale * 100) / 100
  }));
}
function customer(username, pw, name, [sav, chk, cc], scale) {
  return {
    username, password: hashPassword(pw), role: 'customer', name,
    accounts: [
      { type: 'Savings', number: '•••• ' + last4(username + 's'), balance: sav },
      { type: 'Checking', number: '•••• ' + last4(username + 'c'), balance: chk },
      { type: 'Credit Card', number: '•••• ' + last4(username + 'cc'), balance: cc, limit: 150000 }
    ],
    transactions: sampleTransactions(scale)
  };
}
let users = readJson('users.json', null);
if (!users) {
  users = [
    { username: 'admin', password: hashPassword('Admin@2026'), role: 'admin', name: 'Security Administrator' },
    customer('juan', 'Juan@2026', 'Juan Dela Cruz', [248750.35, 56320.1, -12450], 1),
    customer('maria', 'Maria@2026', 'Maria Santos', [512300, 88410.75, -4380.2], 1.6),
    customer('carlo', 'Carlo@2026', 'Carlo Reyes', [93210.5, 21045.3, -21890], 0.7),
    customer('ana', 'Ana@2026', 'Ana Villanueva', [1250400, 145600, -980.5], 2.2)
  ];
  writeJson('users.json', users);
  console.log('Created starter accounts in data/users.json');
}
const findUser = (u) => users.find((x) => x.username === u);
const roleOf = (u) => (findUser(u) ? findUser(u).role : 'unknown');

let settings = { ...DEFAULT_SETTINGS, ...readJson('settings.json', {}) };
let events = readJson('events.json', []);
let alerts = readJson('alerts.json', []);
let firewall = readJson('firewall.json', { blocks: [], allow: [] });

// ============================================================== IP helpers
function clientIp(req) {
  let ip = req.socket.remoteAddress || '';
  if (TRUST_PROXY && req.headers['x-forwarded-for']) {
    const parts = String(req.headers['x-forwarded-for']).split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length) ip = parts[parts.length - 1]; // entry appended by our own proxy – can't be spoofed
  }
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip === '::1') ip = '127.0.0.1';
  return ip;
}
function ipv4ToInt(ip) {
  const p = String(ip).split('.');
  if (p.length !== 4 || p.some((n) => !/^\d{1,3}$/.test(n) || Number(n) > 255)) return null;
  return ((Number(p[0]) << 24) >>> 0) + (Number(p[1]) << 16) + (Number(p[2]) << 8) + Number(p[3]);
}
function parseCidr(t) {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(t);
  if (!m || ipv4ToInt(m[1]) == null || Number(m[2]) > 32) return null;
  const bits = Number(m[2]);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (ipv4ToInt(m[1]) & mask) >>> 0, mask };
}
function validTarget(t) {
  return ipv4ToInt(t) != null || parseCidr(t) != null || (/^[0-9a-f:]{2,45}$/i.test(t) && t.includes(':'));
}
function ipMatches(target, ip) {
  if (target === ip) return true;
  const c = parseCidr(target);
  const x = ipv4ToInt(ip);
  return !!c && x != null && ((x & c.mask) >>> 0) === c.base;
}
function isPrivateIp(ip) {
  return !ip ||
    /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip) ||
    /^(::1$|fc|fd|fe80)/i.test(ip);
}
const isSimIp = (ip) => /^(192\.0\.2|198\.51\.100|203\.0\.113)\./.test(ip); // RFC 5737 documentation ranges

// ============================================================== geolocation
const SIM_GEO = [
  ['Frankfurt', 'Hesse', 'Germany', 'DE', '60313', 50.1109, 8.6821, 'Europe/Berlin', 'SimHost Cloud GmbH', 'AS64500', 'Hosting / Data center'],
  ['Amsterdam', 'North Holland', 'Netherlands', 'NL', '1012', 52.3676, 4.9041, 'Europe/Amsterdam', 'NL VPS Networks', 'AS64501', 'Hosting / Data center, Proxy / VPN'],
  ['São Paulo', 'São Paulo', 'Brazil', 'BR', '01000-000', -23.5505, -46.6333, 'America/Sao_Paulo', 'Sim Telecom Brasil', 'AS64502', 'Residential / Fixed broadband'],
  ['Lagos', 'Lagos', 'Nigeria', 'NG', '100001', 6.5244, 3.3792, 'Africa/Lagos', 'Sim Mobile NG', 'AS64503', 'Mobile / Cellular'],
  ['Hanoi', 'Hanoi', 'Vietnam', 'VN', '100000', 21.0278, 105.8342, 'Asia/Ho_Chi_Minh', 'Sim Broadband VN', 'AS64504', 'Residential / Fixed broadband'],
  ['Bucharest', 'Bucharest', 'Romania', 'RO', '010011', 44.4268, 26.1025, 'Europe/Bucharest', 'Sim Datacenter SRL', 'AS64505', 'Hosting / Data center'],
  ['Ashburn', 'Virginia', 'United States', 'US', '20147', 39.0438, -77.4874, 'America/New_York', 'Sim Cloud Services', 'AS64506', 'Hosting / Data center'],
  ['Singapore', 'Central Singapore', 'Singapore', 'SG', '018989', 1.2789, 103.8536, 'Asia/Singapore', 'Sim Cloud SG', 'AS64507', 'Hosting / Data center'],
  ['Moscow', 'Moscow', 'Russia', 'RU', '101000', 55.7558, 37.6173, 'Europe/Moscow', 'Sim Hosting RU', 'AS64508', 'Hosting / Data center, Proxy / VPN'],
  ['Jakarta', 'Jakarta', 'Indonesia', 'ID', '10110', -6.2088, 106.8456, 'Asia/Jakarta', 'Sim Seluler ID', 'AS64509', 'Mobile / Cellular']
];
function simGeo(ip) {
  const n = Number(ip.split('.')[3]) || 0;
  const [city, region, country, countryCode, postal, lat, lon, timezone, isp, asn, networkType] = SIM_GEO[n % SIM_GEO.length];
  return {
    ip, city, region, country, countryCode, postal, lat, lon, timezone,
    isp: isp + ' (simulated)', org: isp + ' (simulated)', asn: `${asn} ${isp} (simulated)`, networkType,
    source: 'Attack simulator', simulated: true,
    note: 'Simulated attacker. This address is in an RFC 5737 documentation range that is never used on the real internet, so its location and ISP are made up for the simulation.'
  };
}
const geoCache = new Map();
const geoInflight = new Map();
const GEO_TTL = 6 * 60 * MIN;
const GEO_FAIL_TTL = MIN;
async function fetchJson(url, headers = {}) {
  const r = await fetch(url, { signal: AbortSignal.timeout(6000), headers: { 'User-Agent': 'BankSecure/1.0 (login security console)', ...headers } });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}
function networkType(mobile, proxy, hosting) {
  const t = [];
  if (mobile) t.push('Mobile / Cellular');
  if (hosting) t.push('Hosting / Data center');
  if (proxy) t.push('Proxy / VPN / Tor');
  return t.length ? t.join(', ') : 'Residential / Fixed broadband';
}
async function fromIpApi(q) { // primary – free tier 45 req/min
  const fields = 'status,message,query,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting';
  const d = await fetchJson(`http://ip-api.com/json/${q ? encodeURIComponent(q) : ''}?fields=${fields}`);
  if (d.status !== 'success') throw new Error(d.message || 'lookup failed');
  return { ip: d.query, country: d.country, countryCode: d.countryCode, region: d.regionName, city: d.city, postal: d.zip,
    lat: d.lat, lon: d.lon, timezone: d.timezone, isp: d.isp, org: d.org, asn: d.as,
    networkType: networkType(d.mobile, d.proxy, d.hosting), source: 'ip-api.com' };
}
async function fromIpWho(q) { // fallback – HTTPS
  const d = await fetchJson(`https://ipwho.is/${q ? encodeURIComponent(q) : ''}`);
  if (!d.success) throw new Error(d.message || 'lookup failed');
  const c = d.connection || {};
  return { ip: d.ip, country: d.country, countryCode: d.country_code, region: d.region, city: d.city, postal: d.postal,
    lat: d.latitude, lon: d.longitude, timezone: d.timezone && d.timezone.id, isp: c.isp, org: c.org,
    asn: c.asn ? `AS${c.asn} ${c.org || ''}`.trim() : '', networkType: 'Not reported by provider', source: 'ipwho.is' };
}
function lookupIp(ip, { fresh = false } = {}) {
  if (isSimIp(ip)) return Promise.resolve(simGeo(ip));
  const local = isPrivateIp(ip);
  const key = local ? '__self__' : ip;
  const hit = geoCache.get(key);
  if (!fresh && hit && Date.now() - hit.t < (hit.v.error ? GEO_FAIL_TTL : GEO_TTL)) return Promise.resolve(hit.v);
  if (geoInflight.has(key)) return geoInflight.get(key);
  const p = (async () => {
    const q = local ? '' : ip; // empty query = the server's own public IP
    let v;
    try { v = await fromIpApi(q); } catch (e1) {
      try { v = await fromIpWho(q); } catch (e2) { v = { error: `IP lookup unavailable (${e1.message}; ${e2.message})` }; }
    }
    if (local && !v.error) v = { ...v, note: `This request came from a local/private address (${ip}), so the public IP of the network the server is on is shown instead.` };
    geoCache.set(key, { t: Date.now(), v });
    return v;
  })().finally(() => geoInflight.delete(key));
  geoInflight.set(key, p);
  return p;
}

// ============================================================== device location (browser GPS / Wi-Fi)
// The login page asks the browser for the device's position. The browser shows its own
// permission prompt; if the person allows it we receive coordinates accurate to a few metres
// (phone GPS) up to ~100 m (laptop Wi-Fi). If they refuse, only the IP location is available.
function parseDevice(d) {
  if (!d || typeof d !== 'object') return { status: 'not-sent' };
  if (d.error) return { status: String(d.error).replace(/[^a-z-]/gi, '').slice(0, 30) || 'unavailable' };
  const lat = Number(d.lat); const lon = Number(d.lon); const acc = Number(d.accuracy);
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return { status: 'invalid' };
  return {
    status: 'ok', lat: Math.round(lat * 1e6) / 1e6, lon: Math.round(lon * 1e6) / 1e6,
    accuracy: Number.isFinite(acc) && acc >= 0 ? Math.min(Math.round(acc), 1000000) : null,
    capturedAt: new Date().toISOString(), address: null
  };
}
const revCache = new Map();
let revChain = Promise.resolve();
let lastRev = 0;
function reverseGeocode(lat, lon) { // OpenStreetMap Nominatim – max 1 request / second, results cached
  const key = lat.toFixed(5) + ',' + lon.toFixed(5);
  if (revCache.has(key)) return revCache.get(key);
  const p = revChain.then(async () => {
    const wait = lastRev + 1100 - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    lastRev = Date.now();
    const d = await fetchJson(`https://nominatim.openstreetmap.org/reverse?format=jsonv2&zoom=18&addressdetails=1&lat=${lat}&lon=${lon}`, { 'Accept-Language': 'en' });
    if (d.error) throw new Error(d.error);
    const a = d.address || {};
    return {
      display: d.display_name || '',
      street: [a.house_number, a.road || a.pedestrian || a.footway].filter(Boolean).join(' '),
      area: a.suburb || a.village || a.neighbourhood || a.quarter || a.hamlet || '',
      city: a.city || a.town || a.municipality || a.county || '',
      region: a.state || a.region || a.province || '',
      postcode: a.postcode || '', country: a.country || '', countryCode: (a.country_code || '').toUpperCase(),
      source: 'OpenStreetMap Nominatim'
    };
  }).catch((e) => ({ error: 'Address lookup unavailable (' + e.message + ')' }));
  revChain = p.then(() => {}, () => {});
  revCache.set(key, p);
  p.then((v) => { if (v.error) setTimeout(() => revCache.delete(key), MIN); });
  return p;
}
function placeOf(e) { // best human-readable place for an event: exact device address first, then IP
  const d = e.device;
  if (d && d.status === 'ok') {
    const a = d.address && !d.address.error ? d.address : null;
    const txt = a ? [a.street, a.area, a.city, a.country].filter(Boolean).join(', ') : `${d.lat.toFixed(5)}, ${d.lon.toFixed(5)}`;
    return txt + (d.accuracy != null ? ` (±${d.accuracy} m)` : '');
  }
  return e.geo && !e.geo.error ? [e.geo.city, e.geo.country].filter(Boolean).join(', ') : '';
}

// ============================================================== event log
function logEvent({ type, ip, user, role, portal, detail, ua, simulated, onGeo, device }) {
  const ev = {
    id: crypto.randomUUID(), time: new Date().toISOString(), type, portal: portal || '-',
    user: user || '-', role: role || '-', ip: ip || '-', ua: String(ua || '').slice(0, 200),
    detail: detail || '', simulated: !!simulated, geo: null, device: device ? { ...device } : null
  };
  if (ev.device && ev.device.status === 'ok') {
    reverseGeocode(ev.device.lat, ev.device.lon).then((addr) => { ev.device.address = addr; save('events.json'); });
  }
  events.unshift(ev);
  if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
  save('events.json');
  if (ip && ip !== '-') {
    lookupIp(ip).then((g) => { ev.geo = g; save('events.json'); if (onGeo) onGeo(g); }).catch(() => {});
  }
  return ev;
}
function retryMissingGeo() {
  for (const e of events.slice(0, 300)) {
    const d = e.device;
    if (d && d.status === 'ok' && (!d.address || d.address.error)) {
      reverseGeocode(d.lat, d.lon).then((addr) => { if (!addr.error) { d.address = addr; save('events.json'); } });
    }
  }
  const seen = new Set();
  for (const e of events.slice(0, 500)) {
    if (seen.size >= 5) break;
    if (e.ip !== '-' && (!e.geo || e.geo.error) && !seen.has(e.ip)) {
      seen.add(e.ip);
      lookupIp(e.ip).then((g) => {
        if (g.error) return;
        for (const x of events) if (x.ip === e.ip && (!x.geo || x.geo.error)) x.geo = g;
        save('events.json');
      });
    }
  }
}

// ============================================================== alerts
const RULES = {
  PASSWORD_SPRAY: ['critical', 'Password spray attack'],
  SUCCESS_AFTER_FAILURES: ['critical', 'Successful login after repeated failures'],
  ADMIN_BRUTE_FORCE: ['critical', 'Admin portal login failures'],
  BRUTE_FORCE: ['high', 'Brute-force attack'],
  DISTRIBUTED_ATTACK: ['high', 'Distributed attack on one account'],
  IP_AUTO_BLOCKED: ['high', 'Attacker IP blocked by firewall'],
  ACCOUNT_LOCKOUT: ['medium', 'Account locked out'],
  NEW_LOCATION: ['medium', 'Login from a new country']
};
function raiseAlert(rule, key, { ip, user, description, simulated }) {
  const now = Date.now();
  const iso = new Date(now).toISOString();
  const open = alerts.find((a) => a.rule === rule && a.key === key && a.status !== 'resolved' &&
    now - Date.parse(a.lastSeen) < settings.detectionWindowMinutes * MIN * 3);
  if (open) {
    open.count++; open.lastSeen = iso; open.description = description;
    save('alerts.json');
    return open;
  }
  const [severity, title] = RULES[rule];
  const a = { id: crypto.randomUUID(), rule, key, severity, title, description, ip: ip || '-', user: user || '-',
    count: 1, status: 'new', time: iso, lastSeen: iso, simulated: !!simulated };
  alerts.unshift(a);
  if (alerts.length > MAX_ALERTS) alerts.length = MAX_ALERTS;
  save('alerts.json');
  console.log(`[ALERT] ${severity.toUpperCase()} ${rule}: ${description}`);
  return a;
}

// ============================================================== firewall
function isAllowlisted(ip) { return firewall.allow.some((a) => ipMatches(a.target, ip)); }
function firewallCheck(ip) {
  if (isAllowlisted(ip)) return null;
  const now = Date.now();
  return firewall.blocks.find((b) => (!b.expires || b.expires > now) && ipMatches(b.target, ip)) || null;
}
function addBlock({ target, minutes, reason, source }) {
  const now = Date.now();
  const expires = minutes ? now + minutes * MIN : null;
  const existing = firewall.blocks.find((b) => b.target === target && (!b.expires || b.expires > now));
  if (existing) {
    existing.expires = existing.expires && expires ? Math.max(existing.expires, expires) : null;
    existing.reason = reason;
    save('firewall.json');
    return existing;
  }
  const b = { id: crypto.randomUUID(), target, reason, source, created: now, expires, hits: 0, lastHit: null };
  firewall.blocks.unshift(b);
  save('firewall.json');
  return b;
}
setInterval(() => { // forget blocks that expired more than 24 h ago
  const cutoff = Date.now() - 24 * 60 * MIN;
  const before = firewall.blocks.length;
  firewall.blocks = firewall.blocks.filter((b) => !b.expires || b.expires > cutoff);
  if (firewall.blocks.length !== before) save('firewall.json');
}, MIN).unref();

// ============================================================== lockout + detection
const lockState = new Map(); // "portal|user|name" or "admin|ip|1.2.3.4" -> { fails: [ts], lockedUntil }
function getLock(key) {
  const now = Date.now();
  let s = lockState.get(key);
  if (!s) { s = { fails: [], lockedUntil: 0 }; lockState.set(key, s); }
  if (s.lockedUntil && s.lockedUntil <= now) { s.lockedUntil = 0; s.fails = []; }
  const cutoff = now - settings.failureWindowMinutes * MIN;
  s.fails = s.fails.filter((t) => t >= cutoff);
  return s;
}
setInterval(() => {
  for (const [k, s] of lockState) { getLock(k); if (!s.fails.length && !s.lockedUntil) lockState.delete(k); }
}, MIN).unref();
function activeLocks() {
  const now = Date.now();
  const out = [];
  for (const [key, s] of lockState) {
    if (s.lockedUntil > now) {
      const [portal, kind, ...rest] = key.split('|');
      const value = rest.join('|');
      out.push({ key, portal, kind, value, exists: kind === 'user' ? !!findUser(value) : null,
        fails: s.fails.length, remaining: Math.ceil((s.lockedUntil - now) / 1000) });
    }
  }
  return out.sort((a, b) => b.remaining - a.remaining);
}

const recent = []; // sliding window of attempts used by the detection rules
function recordAttempt(a) {
  recent.push(a);
  const cutoff = Date.now() - 60 * MIN;
  while (recent.length && recent[0].t < cutoff) recent.shift();
}

function detect({ ip, user, portal, simulated }) {
  const W = settings.detectionWindowMinutes;
  const since = Date.now() - W * MIN;
  const fails = recent.filter((r) => !r.ok && r.t >= since && r.portal === portal);
  const ipFails = fails.filter((r) => r.ip === ip);

  if (portal === 'admin') {
    if (ipFails.length >= 3) {
      raiseAlert('ADMIN_BRUTE_FORCE', ip, { ip, user, simulated,
        description: `${ipFails.length} failed sign-ins to the ADMIN console from ${ip} in ${W} min (last username tried: “${user}”).` });
    }
    return;
  }

  let blockReason = null;
  const onAccount = ipFails.filter((r) => r.user === user).length;
  if (onAccount >= settings.bruteForceThreshold) {
    raiseAlert('BRUTE_FORCE', `${ip}|${user}`, { ip, user, simulated,
      description: `${onAccount} failed logins for “${user}” from ${ip} in ${W} min – password guessing against one account.` });
  }
  const accounts = [...new Set(ipFails.map((r) => r.user))];
  if (accounts.length >= settings.sprayAccountThreshold) {
    raiseAlert('PASSWORD_SPRAY', ip, { ip, user: accounts.length + ' accounts', simulated,
      description: `${ip} tried ${accounts.length} different accounts in ${W} min (${accounts.slice(0, 6).join(', ')}${accounts.length > 6 ? ', …' : ''}) – the same few passwords against many users.` });
    blockReason = `Password spray across ${accounts.length} accounts`;
  }
  const ips = new Set(fails.filter((r) => r.user === user).map((r) => r.ip));
  if (ips.size >= settings.distributedIpThreshold) {
    raiseAlert('DISTRIBUTED_ATTACK', user, { ip: ips.size + ' IPs', user, simulated,
      description: `“${user}” was targeted from ${ips.size} different IP addresses in ${W} min – typical of a botnet or credential-stuffing attack that stays under per-IP limits.` });
  }
  if (!blockReason && ipFails.length >= settings.ipFailureThreshold) blockReason = `${ipFails.length} failed logins in ${W} min`;

  if (blockReason && settings.autoBlock && !firewallCheck(ip) && !isAllowlisted(ip)) {
    const b = addBlock({ target: ip, minutes: settings.ipBlockMinutes, reason: blockReason, source: 'auto' });
    logEvent({ type: 'FIREWALL_AUTO_BLOCK', ip, user: 'firewall', role: 'system', portal, simulated,
      detail: `${blockReason} – blocked for ${settings.ipBlockMinutes} min` });
    raiseAlert('IP_AUTO_BLOCKED', ip, { ip, user, simulated,
      description: `Firewall automatically blocked ${ip} for ${settings.ipBlockMinutes} min: ${blockReason}.` });
    return b;
  }
  return null;
}

function checkNewLocation(ev, g) {
  if (!g || g.error || !g.country) return;
  const prev = events.filter((e) => e !== ev && e.type === 'LOGIN_SUCCESS' && e.portal === 'customer' &&
    e.user === ev.user && e.geo && e.geo.country && Date.parse(e.time) < Date.parse(ev.time));
  if (prev.length && !prev.some((e) => e.geo.country === g.country)) {
    const usual = [...new Set(prev.map((e) => e.geo.country))].slice(0, 3).join(', ');
    raiseAlert('NEW_LOCATION', `${ev.user}|${g.country}`, { ip: ev.ip, user: ev.user, simulated: ev.simulated,
      description: `“${ev.user}” signed in from ${[g.city, g.country].filter(Boolean).join(', ')} (${ev.ip}). Previous logins came from ${usual}.` });
  }
}

const lockedBody = (ms) => ({ ok: false, locked: true, retryAfter: Math.ceil(ms / 1000), lockSeconds: settings.accountLockMinutes * 60,
  message: `Too many failed attempts. This account is locked for ${settings.accountLockMinutes} minute${settings.accountLockMinutes === 1 ? '' : 's'}.` });

async function attemptLogin({ portal, username, password, ip, ua, simulated, device }) {
  const now = Date.now();
  username = String(username || '').trim().toLowerCase().slice(0, 64);
  password = String(password || '').slice(0, 128);
  const base = { portal, ip, ua, simulated, device: simulated ? null : device, user: username || '-', role: roleOf(username) };

  // 1. firewall (customer portal only, so an admin can never lock themselves out of the console)
  if (portal === 'customer') {
    const blk = firewallCheck(ip);
    if (blk) {
      blk.hits++; blk.lastHit = now; save('firewall.json');
      logEvent({ ...base, type: 'FIREWALL_BLOCKED', detail: `Dropped by firewall rule ${blk.target} – ${blk.reason}` });
      return { status: 403, body: { ok: false, firewall: true, retryAfter: blk.expires ? Math.ceil((blk.expires - now) / 1000) : null,
        message: 'Access from your network has been blocked by the BankSecure firewall because of suspicious activity.' } };
    }
  }
  if (!username || !password) return { status: 400, body: { ok: false, message: 'Enter your username and password.' } };

  // 2. account lockout
  const keys = portal === 'admin' ? [`admin|user|${username}`, `admin|ip|${ip}`] : [`customer|user|${username}`];
  const limits = portal === 'admin' ? [settings.maxAccountFailures, settings.maxAccountFailures * 2] : [settings.maxAccountFailures];
  const states = keys.map(getLock);
  const lockedUntil = Math.max(...states.map((s) => s.lockedUntil));
  if (lockedUntil > now) {
    recordAttempt({ t: now, ip, user: username, ok: false, portal });
    logEvent({ ...base, type: 'LOCKED_ATTEMPT', detail: `Attempt while ${portal === 'admin' ? 'admin sign-in' : 'the account'} is locked` });
    detect({ ip, user: username, portal, simulated });
    return { status: 423, body: lockedBody(lockedUntil - now) };
  }

  // 3. verify credentials
  const user = findUser(username);
  const passOk = await verifyPassword(password, user ? user.password : DUMMY_HASH);
  const ok = passOk && user && user.role === (portal === 'admin' ? 'admin' : 'customer');
  const t = Date.now();

  if (!ok) {
    recordAttempt({ t, ip, user: username, ok: false, portal });
    states.forEach((s) => s.fails.push(t));
    let locked = false;
    states.forEach((s, i) => { if (s.fails.length >= limits[i]) { s.lockedUntil = t + settings.accountLockMinutes * MIN; locked = true; } });
    const why = passOk && user ? `Valid password used on the wrong portal (${portal})` : user ? 'Wrong password' : 'Unknown username';
    if (locked) {
      logEvent({ ...base, type: 'ACCOUNT_LOCKED', detail: `${why} – ${states[0].fails.length} failed attempts, locked for ${settings.accountLockMinutes} min` });
      if (portal === 'customer') {
        raiseAlert('ACCOUNT_LOCKOUT', username, { ip, user: username, simulated,
          description: `Account “${username}”${user ? '' : ' (no such account)'} was locked after ${states[0].fails.length} failed attempts. Last attempt from ${ip}.` });
      }
      detect({ ip, user: username, portal, simulated });
      return { status: 423, body: lockedBody(settings.accountLockMinutes * MIN) };
    }
    logEvent({ ...base, type: 'LOGIN_FAILED', detail: why });
    detect({ ip, user: username, portal, simulated });
    const left = Math.min(...states.map((s, i) => limits[i] - s.fails.length));
    return { status: 401, body: { ok: false, message: 'Invalid username or password.', attemptsLeft: left } };
  }

  // 4. success
  const prior = recent.filter((r) => !r.ok && r.user === username && r.portal === portal && r.t >= t - 15 * MIN).length;
  states.forEach((s) => { s.fails = []; s.lockedUntil = 0; });
  recordAttempt({ t, ip, user: username, ok: true, portal });
  const ev = logEvent({ ...base, type: 'LOGIN_SUCCESS', detail: portal === 'admin' ? 'Admin console' : 'Online banking',
    onGeo: portal === 'customer' ? (g) => checkNewLocation(ev, g) : null });
  if (prior >= 3) {
    raiseAlert('SUCCESS_AFTER_FAILURES', `${portal}|${username}`, { ip, user: username, simulated,
      description: `“${username}” signed in from ${ip} after ${prior} failed attempts in the last 15 minutes. Confirm with the ${portal === 'admin' ? 'administrator' : 'customer'} – possible account takeover.` });
  }
  return { status: 200, body: { ok: true, redirect: portal === 'admin' ? '/admin' : '/account' }, user };
}

// ============================================================== attack simulator
const SIM_UA = 'BankSecure-AttackSimulator/1.0 (simulated)';
const SIM_WORDLIST = ['123456', 'password', '12345678', 'qwerty', '123456789', '12345', 'iloveyou', '111111', '123123', 'abc123',
  'password1', '1234567', 'welcome', 'letmein', 'monkey', 'dragon', 'sunshine', 'princess', 'football', 'Password123',
  'P@ssw0rd', 'Welcome1', 'Qwerty123!', 'Summer2026!', 'Spring2026', 'Banking123', 'Pa$$w0rd', 'admin123', 'trustno1', 'master'];
const SPRAY_PASSWORDS = ['Summer2026!', 'Welcome1', 'Password123', 'Pasko2026!'];
const SIM_TYPES = {
  brute_force: 'Brute force – one IP guesses many passwords for one account',
  password_spray: 'Password spray – one IP tries a common password on many accounts',
  distributed: 'Distributed / credential stuffing – many IPs attack one account'
};
const sims = new Map();
const randOctet = () => 10 + crypto.randomInt(240);
function simView(s) {
  const { timer, ...rest } = s; // eslint-disable-line no-unused-vars
  return rest;
}
function startSimulation({ type, target, count, rate }) {
  if (!SIM_TYPES[type]) throw Object.assign(new Error('Unknown attack type'), { status: 400 });
  if ([...sims.values()].filter((s) => s.status === 'running').length >= 3) {
    throw Object.assign(new Error('Three simulations are already running – stop one first.'), { status: 409 });
  }
  target = String(target || '').trim().toLowerCase().slice(0, 64);
  if (type !== 'password_spray' && !/^[a-z0-9._-]{1,64}$/.test(target)) throw Object.assign(new Error('Choose a target account'), { status: 400 });
  count = Math.min(500, Math.max(5, Math.round(Number(count) || 40)));
  rate = Math.min(20, Math.max(1, Math.round(Number(rate) || 5)));

  const sim = { id: crypto.randomBytes(4).toString('hex'), type, label: SIM_TYPES[type],
    target: type === 'password_spray' ? 'many accounts' : target, count, rate, sent: 0, done: 0,
    results: { success: 0, failed: 0, locked: 0, firewall: 0 }, status: 'running', started: new Date().toISOString(), ips: [] };
  if (type === 'brute_force') sim.ips = [`203.0.113.${randOctet()}`];
  else if (type === 'password_spray') sim.ips = [`198.51.100.${randOctet()}`];
  else { const s = new Set(); while (s.size < 16) s.add(`192.0.2.${randOctet()}`); sim.ips = [...s]; }
  const sprayUsers = [...users.filter((u) => u.role === 'customer').map((u) => u.username), 'jsmith', 'test', 'support', 'mgarcia', 'finance', 'user01'];

  sim.timer = setInterval(() => {
    if (sim.status !== 'running') return clearInterval(sim.timer);
    if (sim.sent >= sim.count) return clearInterval(sim.timer);
    const i = sim.sent++;
    let username; let password; let ip;
    if (type === 'brute_force') { username = target; password = SIM_WORDLIST[i % SIM_WORDLIST.length]; ip = sim.ips[0]; }
    else if (type === 'password_spray') {
      username = sprayUsers[i % sprayUsers.length];
      password = SPRAY_PASSWORDS[Math.floor(i / sprayUsers.length) % SPRAY_PASSWORDS.length];
      ip = sim.ips[0];
    } else { username = target; password = SIM_WORDLIST[i % SIM_WORDLIST.length]; ip = sim.ips[i % sim.ips.length]; }
    attemptLogin({ portal: 'customer', username, password, ip, ua: SIM_UA, simulated: true })
      .then((r) => { sim.results[r.status === 200 ? 'success' : r.status === 423 ? 'locked' : r.status === 403 ? 'firewall' : 'failed']++; })
      .catch(() => { sim.results.failed++; })
      .finally(() => {
        sim.done++;
        if (sim.done >= sim.count && sim.status === 'running') { sim.status = 'completed'; sim.finished = new Date().toISOString(); }
      });
  }, Math.max(50, Math.round(1000 / rate)));

  sims.set(sim.id, sim);
  const ids = [...sims.keys()];
  while (ids.length > 10) { const old = sims.get(ids.shift()); if (old.status !== 'running') sims.delete(old.id); else break; }
  return sim;
}

// ============================================================== sessions
const sessions = new Map();
function parseCookies(header) {
  const out = {};
  String(header || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function cookie(value, maxAge) {
  return `bs.sid=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${COOKIE_SECURE ? '; Secure' : ''}`;
}
function getSession(req) {
  const sid = req.cookies['bs.sid'];
  const s = sid && sessions.get(sid);
  if (!s) return null;
  if (Date.now() - s.last > SESSION_IDLE_MS) { sessions.delete(sid); return null; }
  s.last = Date.now();
  return s;
}
function createSession(req, res, user) {
  if (req.session) sessions.delete(req.session.sid); // never reuse a pre-login session id
  const sid = crypto.randomBytes(32).toString('base64url');
  sessions.set(sid, { sid, username: user.username, role: user.role, name: user.name, created: Date.now(), last: Date.now() });
  res.setHeader('Set-Cookie', cookie(sid, SESSION_IDLE_MS / 1000));
}
setInterval(() => { const now = Date.now(); for (const [k, s] of sessions) if (now - s.last > SESSION_IDLE_MS) sessions.delete(k); }, MIN).unref();

// ============================================================== http plumbing
const SECURITY_HEADERS = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(self), camera=(), microphone=()',
  'Content-Security-Policy': [
    "default-src 'self'", "script-src 'self' https://unpkg.com", "style-src 'self' https://unpkg.com",
    "img-src 'self' data: https://unpkg.com https://tile.openstreetmap.org https://*.basemaps.cartocdn.com https://server.arcgisonline.com", "connect-src 'self'",
    "frame-ancestors 'none'", "form-action 'self'", "base-uri 'none'"
  ].join('; ')
};
const MIME = { '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
function send(res, status, body, type = 'text/plain; charset=utf-8', headers = {}) {
  res.writeHead(status, { 'Content-Type': type, ...headers });
  res.end(body);
}
const json = (res, status, obj) => send(res, status, JSON.stringify(obj), 'application/json; charset=utf-8', { 'Cache-Control': 'no-store' });
const redirect = (res, to) => { res.writeHead(302, { Location: to, 'Cache-Control': 'no-store' }); res.end(); };
function page(res, name) {
  fs.readFile(path.join(PUBLIC_DIR, name), (err, buf) => (err ? send(res, 404, 'Not found')
    : send(res, 200, buf, 'text/html; charset=utf-8', { 'Cache-Control': 'no-store' })));
}
function serveStatic(req, res) {
  const root = path.join(PUBLIC_DIR, 'static');
  const full = path.normalize(path.join(root, decodeURIComponent(req.pathname.slice('/static/'.length))));
  if (!full.startsWith(root + path.sep)) return send(res, 404, 'Not found');
  fs.readFile(full, (err, buf) => (err ? send(res, 404, 'Not found')
    : send(res, 200, buf, MIME[path.extname(full)] || 'application/octet-stream', { 'Cache-Control': 'no-cache' })));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 10240) { reject(Object.assign(new Error('Payload too large'), { status: 413 })); req.destroy(); } else chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { const v = JSON.parse(Buffer.concat(chunks).toString('utf8')); resolve(v && typeof v === 'object' ? v : {}); }
      catch { reject(Object.assign(new Error('Invalid JSON'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}
const routes = [];
function route(method, pattern, handler) {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
  routes.push({ method, re, keys, handler });
}
const get = (p, h) => route('GET', p, h);
const post = (p, h) => route('POST', p, h);
const put = (p, h) => route('PUT', p, h);
const del = (p, h) => route('DELETE', p, h);
const adminOnly = (h) => (req, res, params) => (req.session && req.session.role === 'admin'
  ? h(req, res, params) : json(res, 401, { ok: false, message: 'Not authenticated' }));
const bad = (msg) => Object.assign(new Error(msg), { status: 400 });

// ============================================================== pages
get('/', (req, res) => (req.session && req.session.role === 'customer' ? redirect(res, '/account') : page(res, 'login.html')));
get('/account', (req, res) => {
  if (!req.session || req.session.role !== 'customer' || firewallCheck(req.ip)) return redirect(res, '/');
  page(res, 'account.html');
});
get('/admin/login', (req, res) => (req.session && req.session.role === 'admin' ? redirect(res, '/admin') : page(res, 'admin-login.html')));
get('/admin', (req, res) => (req.session && req.session.role === 'admin' ? page(res, 'admin.html') : redirect(res, '/admin/login')));

// ============================================================== auth API
function loginRoute(portal) {
  return async (req, res) => {
    const r = await attemptLogin({ portal, username: req.body.username, password: req.body.password, ip: req.ip, ua: req.headers['user-agent'], device: parseDevice(req.body.device) });
    if (r.user) createSession(req, res, r.user);
    json(res, r.status, r.body);
  };
}
post('/api/login', loginRoute('customer'));
post('/api/admin/login', loginRoute('admin'));
get('/api/status', (req, res) => {
  const blk = firewallCheck(req.ip);
  json(res, 200, {
    firewall: blk ? { blocked: true, retryAfter: blk.expires ? Math.ceil((blk.expires - Date.now()) / 1000) : null } : { blocked: false },
    maxAttempts: settings.maxAccountFailures, lockMinutes: settings.accountLockMinutes
  });
});
post('/api/logout', (req, res) => {
  const s = req.session;
  if (s) {
    logEvent({ type: 'LOGOUT', ip: req.ip, user: s.username, role: s.role, portal: s.role === 'admin' ? 'admin' : 'customer', ua: req.headers['user-agent'] });
    sessions.delete(s.sid);
  }
  res.setHeader('Set-Cookie', cookie('', 0));
  json(res, 200, { ok: true, redirect: s && s.role === 'admin' ? '/admin/login' : '/' });
});

// ============================================================== customer API
const FAIL_TYPES = new Set(['LOGIN_FAILED', 'ACCOUNT_LOCKED', 'LOCKED_ATTEMPT']);
get('/api/me', (req, res) => {
  if (!req.session || req.session.role !== 'customer') return json(res, 401, { ok: false, message: 'Not authenticated' });
  if (firewallCheck(req.ip)) return json(res, 403, { ok: false, message: 'Blocked by firewall' });
  const u = findUser(req.session.username);
  const mine = events.filter((e) => e.user === u.username && e.portal === 'customer');
  const logins = mine.filter((e) => e.type === 'LOGIN_SUCCESS');
  const prev = logins[1];
  const since = prev ? Date.parse(prev.time) : 0;
  const failed = mine.filter((e) => (FAIL_TYPES.has(e.type) || e.type === 'FIREWALL_BLOCKED') && Date.parse(e.time) > since);

  json(res, 200, {
    user: { username: u.username, name: u.name },
    accounts: u.accounts,
    transactions: u.transactions,
    security: {
      current: logins[0] ? { time: logins[0].time, ip: logins[0].ip, location: placeOf(logins[0]) } : null,
      previous: prev ? { time: prev.time, ip: prev.ip, location: placeOf(prev) } : null,
      failedSinceLast: failed.length,
      failedRecent: failed.slice(0, 6).map((e) => ({ time: e.time, ip: e.ip, location: placeOf(e), type: e.type })),
      alerts: alerts.filter((a) => a.user === u.username).slice(0, 5).map((a) => ({ time: a.time, title: a.title, severity: a.severity, status: a.status })),
      policy: { maxAttempts: settings.maxAccountFailures, lockMinutes: settings.accountLockMinutes }
    }
  });
});

// ============================================================== admin API
function summary(req) {
  const now = Date.now();
  const dayAgo = now - 24 * 60 * MIN;
  const hourAgo = now - 60 * MIN;
  let success = 0; let failed = 0; let dropped = 0;
  const timeline = Array.from({ length: 60 }, () => ({ s: 0, f: 0, b: 0 }));
  const ipAgg = new Map(); const userAgg = new Map();
  for (const e of events) {
    const t = Date.parse(e.time);
    if (t < dayAgo) break; // newest first
    const isS = e.type === 'LOGIN_SUCCESS';
    const isF = FAIL_TYPES.has(e.type);
    const isB = e.type === 'FIREWALL_BLOCKED';
    if (isS) success++;
    if (isF) failed++;
    if (isB) dropped++;
    if (t >= hourAgo) {
      const i = 59 - Math.floor((now - t) / MIN);
      if (i >= 0) { const b = timeline[i]; if (isS) b.s++; if (isF) b.f++; if (isB) b.b++; }
    }
    if (isF || isB) {
      const a = ipAgg.get(e.ip) || { ip: e.ip, count: 0, users: new Set(), geo: null, simulated: e.simulated, last: e.time };
      a.count++; a.users.add(e.user); if (!a.geo && e.geo && !e.geo.error) a.geo = e.geo; ipAgg.set(e.ip, a);
      if (e.user !== '-') {
        const u = userAgg.get(e.user) || { user: e.user, count: 0, ips: new Set(), exists: !!findUser(e.user) };
        u.count++; u.ips.add(e.ip); userAgg.set(e.user, u);
      }
    }
  }
  const open = alerts.filter((a) => a.status !== 'resolved');
  return {
    me: { name: req.session.name, username: req.session.username },
    stats: {
      success, failed, dropped, openAlerts: open.length,
      newAlerts: alerts.filter((a) => a.status === 'new').length,
      critical: open.filter((a) => a.severity === 'critical').length,
      blockedIps: firewall.blocks.filter((b) => !b.expires || b.expires > now).length,
      lockedAccounts: activeLocks().length
    },
    timeline,
    topIps: [...ipAgg.values()].sort((a, b) => b.count - a.count).slice(0, 6).map((a) => ({
      ip: a.ip, count: a.count, accounts: a.users.size, simulated: a.simulated, blocked: !!firewallCheck(a.ip),
      location: a.geo ? [a.geo.city, a.geo.country].filter(Boolean).join(', ') : '', isp: a.geo ? a.geo.isp || a.geo.org || '' : ''
    })),
    topAccounts: [...userAgg.values()].sort((a, b) => b.count - a.count).slice(0, 6).map((u) => ({
      user: u.user, count: u.count, ips: u.ips.size, exists: u.exists,
      locked: activeLocks().some((l) => l.kind === 'user' && l.value === u.user)
    })),
    alerts: alerts.slice(0, 8),
    recentLogins: events.filter((e) => e.type === 'LOGIN_SUCCESS').slice(0, 6),
    sims: [...sims.values()].reverse().map(simView),
    customers: users.filter((u) => u.role === 'customer').map((u) => u.username),
    settings
  };
}
get('/api/admin/summary', adminOnly((req, res) => json(res, 200, summary(req))));

get('/api/admin/events', adminOnly((req, res) => {
  retryMissingGeo();
  const limit = Math.min(MAX_EVENTS, Math.max(1, Number(req.query.limit) || 1000));
  json(res, 200, { total: events.length, events: events.slice(0, limit) });
}));
get('/api/admin/events.csv', adminOnly((req, res) => {
  const cell = (v) => {
    let s = v == null ? '' : String(v);
    if (s.length > 1 && /^[=+\-@\t\r]/.test(s)) s = "'" + s; // spreadsheet formula-injection guard
    return '"' + s.replace(/"/g, '""') + '"';
  };
  const head = ['time', 'event', 'portal', 'user', 'role', 'ip', 'country', 'region', 'city', 'isp', 'asn', 'device_location_status', 'device_lat', 'device_lon', 'device_accuracy_m', 'device_address', 'simulated', 'detail', 'user_agent'];
  const lines = [head.join(',')].concat(events.map((e) => {
    const g = e.geo && !e.geo.error ? e.geo : {};
    const d = e.device || {};
    const addr = d.address && !d.address.error ? d.address.display : '';
    return [e.time, e.type, e.portal, e.user, e.role, e.ip, g.country, g.region, g.city, g.isp, g.asn,
      d.status || '', d.lat, d.lon, d.accuracy, addr, e.simulated, e.detail, e.ua].map(cell).join(',');
  }));
  send(res, 200, lines.join('\r\n'), 'text/csv; charset=utf-8', {
    'Content-Disposition': `attachment; filename="banksecure-events-${new Date().toISOString().slice(0, 10)}.csv"`, 'Cache-Control': 'no-store'
  });
}));
del('/api/admin/events/:id', adminOnly((req, res, p) => {
  const before = events.length;
  events = events.filter((e) => e.id !== p.id);
  save('events.json');
  json(res, 200, { ok: events.length < before });
}));
del('/api/admin/events', adminOnly((req, res) => { events = []; save('events.json'); json(res, 200, { ok: true }); }));

get('/api/admin/alerts', adminOnly((req, res) => json(res, 200, { alerts })));
post('/api/admin/alerts/:id', adminOnly((req, res, p) => {
  const a = alerts.find((x) => x.id === p.id);
  if (!a) return json(res, 404, { ok: false, message: 'Alert not found' });
  if (!['new', 'acknowledged', 'resolved'].includes(req.body.status)) throw bad('Invalid status');
  a.status = req.body.status;
  a.handledBy = req.session.username;
  a.handledAt = new Date().toISOString();
  save('alerts.json');
  json(res, 200, { ok: true });
}));
del('/api/admin/alerts/:id', adminOnly((req, res, p) => {
  alerts = alerts.filter((a) => a.id !== p.id); save('alerts.json'); json(res, 200, { ok: true });
}));
del('/api/admin/alerts', adminOnly((req, res) => {
  alerts = req.query.resolved === '1' ? alerts.filter((a) => a.status !== 'resolved') : [];
  save('alerts.json'); json(res, 200, { ok: true });
}));

get('/api/admin/ip/:ip', adminOnly(async (req, res, p) => {
  if (!/^[0-9a-fA-F:.]{2,45}$/.test(p.ip)) return json(res, 400, { error: 'Invalid IP address' });
  const g = await lookupIp(p.ip, { fresh: req.query.fresh === '1' });
  // If anyone signing in from this IP shared their device location, attach the latest exact position
  const ev = events.find((e) => e.ip === p.ip && e.device && e.device.status === 'ok');
  const exact = ev ? { lat: ev.device.lat, lon: ev.device.lon, accuracy: ev.device.accuracy,
    address: ev.device.address && !ev.device.address.error ? ev.device.address : null, user: ev.user, time: ev.time } : null;
  json(res, 200, { ...g, exact });
}));

get('/api/admin/firewall', adminOnly((req, res) => {
  const now = Date.now();
  const geoOf = (ip) => { const e = events.find((x) => x.ip === ip && x.geo && !x.geo.error); return e ? [e.geo.city, e.geo.country].filter(Boolean).join(', ') : ''; };
  json(res, 200, {
    blocks: firewall.blocks.map((b) => ({ ...b, active: !b.expires || b.expires > now, remaining: b.expires ? Math.max(0, Math.ceil((b.expires - now) / 1000)) : null, location: geoOf(b.target) })),
    allow: firewall.allow,
    locks: activeLocks(),
    settings,
    yourIp: req.ip
  });
}));
post('/api/admin/firewall/block', adminOnly((req, res) => {
  const target = String(req.body.target || '').trim();
  if (!validTarget(target)) throw bad('Enter a valid IPv4 address, IPv4 CIDR range (e.g. 203.0.113.0/24) or IPv6 address.');
  const minutes = Math.max(0, Math.min(525600, Math.round(Number(req.body.minutes) || 0)));
  const reason = String(req.body.reason || 'Manual block').trim().slice(0, 200) || 'Manual block';
  const b = addBlock({ target, minutes, reason, source: 'manual' });
  logEvent({ type: 'FIREWALL_MANUAL_BLOCK', ip: target.includes('/') ? '-' : target, user: req.session.username, role: 'admin', portal: 'admin',
    detail: `${target} blocked ${minutes ? 'for ' + minutes + ' min' : 'permanently'} – ${reason}` });
  json(res, 200, { ok: true, block: b });
}));
del('/api/admin/firewall/block/:id', adminOnly((req, res, p) => {
  const b = firewall.blocks.find((x) => x.id === p.id);
  if (!b) return json(res, 404, { ok: false, message: 'Rule not found' });
  firewall.blocks = firewall.blocks.filter((x) => x.id !== p.id);
  save('firewall.json');
  logEvent({ type: 'FIREWALL_UNBLOCK', ip: b.target.includes('/') ? '-' : b.target, user: req.session.username, role: 'admin', portal: 'admin', detail: `Removed block on ${b.target}` });
  json(res, 200, { ok: true });
}));
post('/api/admin/firewall/allow', adminOnly((req, res) => {
  const target = String(req.body.target || '').trim();
  if (!validTarget(target)) throw bad('Enter a valid IPv4 address, IPv4 CIDR range or IPv6 address.');
  if (!firewall.allow.some((a) => a.target === target)) {
    firewall.allow.push({ id: crypto.randomUUID(), target, note: String(req.body.note || '').trim().slice(0, 120), created: Date.now() });
    save('firewall.json');
    logEvent({ type: 'ALLOWLIST_CHANGED', ip: '-', user: req.session.username, role: 'admin', portal: 'admin', detail: `Trusted ${target}` });
  }
  json(res, 200, { ok: true });
}));
del('/api/admin/firewall/allow/:id', adminOnly((req, res, p) => {
  const a = firewall.allow.find((x) => x.id === p.id);
  firewall.allow = firewall.allow.filter((x) => x.id !== p.id);
  save('firewall.json');
  if (a) logEvent({ type: 'ALLOWLIST_CHANGED', ip: '-', user: req.session.username, role: 'admin', portal: 'admin', detail: `Removed trusted ${a.target}` });
  json(res, 200, { ok: true });
}));
del('/api/admin/locks/:key', adminOnly((req, res, p) => {
  const ok = lockState.delete(p.key);
  if (ok) {
    const [portal, kind, ...rest] = p.key.split('|');
    logEvent({ type: 'ACCOUNT_UNLOCKED', ip: kind === 'ip' ? rest.join('|') : '-', user: kind === 'user' ? rest.join('|') : '-',
      role: 'admin', portal, detail: `Unlocked by ${req.session.username}` });
  }
  json(res, 200, { ok });
}));
put('/api/admin/settings', adminOnly((req, res) => {
  const next = { ...settings };
  for (const [k, [lo, hi]] of Object.entries(SETTING_LIMITS)) {
    if (req.body[k] === undefined) continue;
    const n = Math.round(Number(req.body[k]));
    if (!Number.isFinite(n) || n < lo || n > hi) throw bad(`${k} must be between ${lo} and ${hi}`);
    next[k] = n;
  }
  if (req.body.autoBlock !== undefined) next.autoBlock = !!req.body.autoBlock;
  const changed = Object.keys(next).filter((k) => next[k] !== settings[k]);
  settings = next;
  save('settings.json');
  if (changed.length) {
    logEvent({ type: 'SETTINGS_CHANGED', ip: req.ip, user: req.session.username, role: 'admin', portal: 'admin',
      detail: changed.map((k) => `${k}=${settings[k]}`).join(', ') });
  }
  json(res, 200, { ok: true, settings });
}));

post('/api/admin/simulate', adminOnly((req, res) => {
  const s = startSimulation(req.body);
  logEvent({ type: 'SIMULATION_STARTED', ip: req.ip, user: req.session.username, role: 'admin', portal: 'admin',
    detail: `${s.label}: ${s.count} attempts at ${s.rate}/s against ${s.target} from ${s.ips.length} simulated IP${s.ips.length > 1 ? 's' : ''}` });
  json(res, 200, { ok: true, sim: simView(s) });
}));
post('/api/admin/simulate/:id/stop', adminOnly((req, res, p) => {
  const s = sims.get(p.id);
  if (!s) return json(res, 404, { ok: false, message: 'Simulation not found' });
  if (s.status === 'running') {
    s.status = 'stopped'; s.finished = new Date().toISOString(); clearInterval(s.timer);
    logEvent({ type: 'SIMULATION_STOPPED', ip: req.ip, user: req.session.username, role: 'admin', portal: 'admin', detail: `${s.label} stopped after ${s.sent} attempts` });
  }
  json(res, 200, { ok: true });
}));

// ============================================================== server
const server = http.createServer(async (req, res) => {
  try {
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
    const url = new URL(req.url, 'http://localhost');
    req.pathname = url.pathname;
    req.query = Object.fromEntries(url.searchParams);
    req.ip = clientIp(req);
    req.cookies = parseCookies(req.headers.cookie);
    req.session = getSession(req);
    if (req.method === 'GET' && req.pathname.startsWith('/static/')) return serveStatic(req, res);
    // CSRF guard: state-changing API calls must carry a custom header (cross-site forms can't add one)
    if (req.pathname.startsWith('/api/') && req.method !== 'GET' && req.headers['x-requested-with'] !== 'BankSecure') {
      return json(res, 403, { ok: false, message: 'Missing X-Requested-With header' });
    }
    req.body = req.method === 'POST' || req.method === 'PUT' ? await readBody(req) : {};
    for (const r of routes) {
      if (r.method !== req.method) continue;
      const m = r.re.exec(req.pathname);
      if (!m) continue;
      const params = {};
      r.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); });
      return await r.handler(req, res, params);
    }
    send(res, 404, 'Not found');
  } catch (err) {
    if (res.headersSent) return;
    if (err && err.status) return json(res, err.status, { ok: false, message: err.message });
    if (err instanceof URIError) return send(res, 400, 'Bad request');
    console.error(err);
    json(res, 500, { ok: false, message: 'Server error' });
  }
});

server.listen(PORT, () => {
  console.log(`BankSecure online banking:  http://localhost:${PORT}`);
  console.log(`Security console (admin):   http://localhost:${PORT}/admin/login`);
  console.log(`Lockout: ${settings.maxAccountFailures} failed attempts -> account locked ${settings.accountLockMinutes} min; ` +
    `firewall auto-block after ${settings.ipFailureThreshold} failures from one IP (${settings.autoBlock ? 'on' : 'off'})`);
});
