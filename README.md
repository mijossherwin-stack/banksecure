# BankSecure – Banking Login Protection

A banking portal with protection against repeated password guessing. It includes a customer login, account lockout, detection rules that raise suspicious-login alerts, an auto-blocking firewall, a SOC-style admin dashboard and a built-in attack simulator.

**No dependencies.** It needs only Node.js 18+, with no `npm install`.

```bash
cd banksecure
node server.js          # or: npm start
```

| Page | URL | Starter login |
|---|---|---|
| Online banking | http://localhost:3000 | `juan` / `Juan@2026` · `maria` / `Maria@2026` · `carlo` / `Carlo@2026` · `ana` / `Ana@2026` |
| Security console | http://localhost:3000/admin/login | `admin` / `Admin@2026` |

The accounts are created in `data/users.json` on first run, with scrypt-hashed passwords. **Change these starter passwords before showing this to anyone outside your machine.** (The login pages no longer display them.) To reset all data, stop the server and delete the `data/` folder.

## Features

| Feature | How it works |
|---|---|
| **Bank account login** | Customer sign-in leads to a dashboard with Savings, Checking and Credit Card balances, recent transactions and a **Security center** that shows failed attempts since the customer's last visit. |
| **Simulated brute-force attack** | The *Attack simulator* tab launches three attack types: **brute force** (one IP, many passwords), **password spray** (one IP, common passwords across many accounts) and **distributed / botnet** (16 IPs share the guessing). Attackers use fake IPs from the RFC 5737 documentation ranges and go through the same login logic in memory. Nothing is sent over the network. |
| **Account lockout** | 5 wrong passwords lock the account for 5 minutes. The login page shows a live countdown. Other accounts on the same device can still sign in. Unknown usernames are locked the same way, so attackers can't use the lockout to discover which accounts exist. The admin portal has its own lockout, per account and per IP. |
| **Security event logs** | Every login, failure, lockout, firewall drop and admin action is logged with time, event, user, role, IP, ISP and location. You can search, filter, hide simulated events, delete single entries or everything, and **export to CSV**. Click any IP to see its lookup details (country, region, city, ORG/ISP, network type, ASN, time zone, postal code, coordinates) and a map. |
| **Admin firewall dashboard** | Shows automatic blocks (from detections) and manual blocks of an IP or CIDR range, each with a countdown, hit counter and unblock button. It also has an allowlist for trusted IPs, a list of locked accounts with "Unlock now", and editable protection rules (thresholds, durations, auto-block on/off). |
| **Suspicious login alerts** | 8 detection rules (below) raise alerts. They appear live as pop-up toasts, in the overview feed and on the Alerts tab, where you can acknowledge, resolve, reopen or delete them. Customers also see alerts about their own account. |

### Detection rules (default thresholds, all editable)

| Rule | Severity | Fires when |
|---|---|---|
| Password spray | critical | One IP fails on ≥ 4 different accounts in 10 min. The IP is auto-blocked. |
| Success after failures | critical | A login succeeds after ≥ 3 failures in 15 min, a sign of possible account takeover. |
| Admin brute force | critical | ≥ 3 failed admin-console sign-ins from one IP in 10 min. |
| Brute force | high | ≥ 5 failures from one IP on one account in 10 min. |
| Distributed attack | high | One account fails from ≥ 4 different IPs in 10 min. |
| IP auto-blocked | high | ≥ 15 failures from one IP, or a password spray. |
| Account lockout | medium | An account reaches the lockout limit. |
| New country | medium | A customer signs in from a country never seen on their account before. |

Repeats of the same rule and source are grouped into one alert with a hit count, so a 500-attempt attack produces a handful of alerts rather than 500.

## Walkthrough (about 3 minutes)

1. Sign in to the **Security console** in one window.
2. In another window, open **Online banking** and type a wrong password for `carlo` 5 times. The 5-minute lock timer appears, and the console shows a *Brute force* alert and an *Account locked out* alert.
3. In the console, open **Attack simulator** and launch **Password spray**. Within about a second you'll see a critical alert, and the attacker IP appears under **Firewall** as *Auto*.
4. Launch **Distributed / botnet** against `maria`. No single IP gets blocked, but account lockout and the *Distributed attack* alert catch it.
5. Click any IP to see its lookup details and map. Use **Block this IP**, **Unlock now** or **Unblock** to respond.

**Note:** if you type more than 15 wrong passwords from your own browser, the firewall will block your own IP (`127.0.0.1`) from the banking portal. That is the protection working. Unblock it on the **Firewall** tab, or add yourself to the **Allowlist**. The admin console is never firewalled, so you can't lock yourself out of it.

## Exact sign-in location

When someone signs in, the login page asks the browser for the device's location using the standard Geolocation API. The browser shows its own permission prompt, and if the person allows it:

- the coordinates are sent with the login and saved on the event (including failed attempts)
- the server turns them into a street address (street, barangay/area, city, province, postal code, country) using OpenStreetMap Nominatim
- the console's **Event log** and **Overview → Recent sign-ins** show that address with a green **GPS** tag; click it to open a map with the exact pin, the accuracy circle, the IP-based estimate for comparison, and a Google Maps link
- customers see the address of their current and previous sign-ins in their Security center

How accurate it is depends on the device:

| Device | Typical accuracy |
|---|---|
| Phone with GPS | 3–20 m |
| Laptop on Wi-Fi | 15–100 m |
| Desktop on cable (no Wi-Fi/GPS) | about city level |

Limits:

- **The person must allow it.** If they decline, or the browser can't get a fix, the log shows why (e.g. *GPS · location declined*) and falls back to the IP-based location. An attacker will usually decline, so attack traffic generally shows only the IP location.
- **It needs HTTPS.** Browsers only share location on `https://` sites or `http://localhost`. To test from a phone, serve the app over HTTPS (for example through a Cloudflare Tunnel or ngrok, with `TRUST_PROXY=1`).
- **Privacy:** precise location is personal data. Tell your users why you collect it, and keep it only as long as you need it.

## IP lookup accuracy

- Real IPs are looked up with **ip-api.com**, with **ipwho.is** as an automatic fallback. Results are cached for 6 hours.
- IP geolocation shows where the ISP's network is located, not the device's GPS position. Country, ISP and ASN are reliable. City and the map pin are approximate, usually within 5–50 km.
- When testing on `localhost`, the lookup shows your network's **public** IP so you still see real data.
- Simulated attacker IPs get made-up locations, clearly labelled *(simulated)*.
- The map uses Leaflet and OpenStreetMap, so it needs an internet connection in the browser.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | 3000 | HTTP port |
| `TRUST_PROXY` | off | Set to `1` behind nginx, Cloudflare or a load balancer, so the real client IP is read from `X-Forwarded-For`. Only enable it when a proxy is really in front. |
| `COOKIE_SECURE` | off | Set to `1` when served over HTTPS. |

The lockout and detection thresholds are edited in the console (**Firewall → Protection rules**) and saved to `data/settings.json`.

## Security notes

- Passwords are hashed with scrypt and compared in constant time. Unknown usernames are checked against a dummy hash, so response timing doesn't reveal which accounts exist.
- Sessions are random 256-bit IDs in HttpOnly, SameSite=Strict cookies, with a 15-minute idle timeout. A new ID is issued at every login.
- State-changing API calls require an `X-Requested-With` header as CSRF protection.
- The server sends a strict Content-Security-Policy (no inline scripts or styles), plus `X-Frame-Options: DENY`, `nosniff` and other hardening headers.
- All user and provider data is rendered with `textContent`, never as HTML. CSV export guards against spreadsheet formula injection.
- The firewall and lock counters live in memory, so restarting the server clears active locks. Firewall rules, events, alerts and settings are saved under `data/`.
- For production, put it behind HTTPS, add MFA, use a real database, and send alerts to your SIEM.

## Files

```
server.js                 HTTP server, auth, lockout, detection, firewall, simulator, APIs
public/login.html         customer sign-in
public/account.html       customer dashboard
public/admin-login.html   admin sign-in
public/admin.html         SOC console (overview · alerts · event log · firewall · simulator)
public/static/*.js|css    front-end scripts and styles
docs/screenshots/         screenshots of each screen
```
