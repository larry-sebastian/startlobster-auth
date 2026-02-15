const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.AUTH_PORT || 3000;
const GATEWAY_URL = process.env.GATEWAY_URL || 'http://127.0.0.1:18789';
const COOKIE_NAME = 'sl_session';
const COOKIE_MAX_AGE = 86400 * 7; // 7 days
const SECRET = process.env.AUTH_SECRET || crypto.randomBytes(32).toString('hex');

// Rate limiting: 3 attempts per minute per IP
const attempts = new Map();
const RATE_LIMIT = 3;
const RATE_WINDOW = 60000;

function rateCheck(ip) {
  const now = Date.now();
  const entry = attempts.get(ip) || [];
  const recent = entry.filter(t => now - t < RATE_WINDOW);
  if (recent.length >= RATE_LIMIT) return false;
  recent.push(now);
  attempts.set(ip, recent);
  return true;
}

// Cleanup old entries every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [ip, times] of attempts) {
    const recent = times.filter(t => now - t < RATE_WINDOW);
    if (recent.length === 0) attempts.delete(ip);
    else attempts.set(ip, recent);
  }
}, 300000);

function sign(token) {
  return crypto.createHmac('sha256', SECRET).update(token).digest('hex');
}

function makeSessionCookie(token, domain) {
  const sig = sign(token);
  const value = Buffer.from(JSON.stringify({ t: token, s: sig })).toString('base64url');
  return `${COOKIE_NAME}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}`;
}

function parseCookie(cookieHeader) {
  if (!cookieHeader) return null;
  const match = cookieHeader.split(';').map(c => c.trim()).find(c => c.startsWith(COOKIE_NAME + '='));
  if (!match) return null;
  try {
    const val = match.split('=')[1];
    const { t, s } = JSON.parse(Buffer.from(val, 'base64url').toString());
    if (sign(t) === s) return t;
  } catch {}
  return null;
}

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
}

const LOGIN_HTML = fs.readFileSync(path.join(__dirname, 'login.html'), 'utf8');

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // Health check
  if (url.pathname === '/auth/health') {
    res.writeHead(200);
    return res.end('ok');
  }

  // Auth check (called by Caddy forward_auth)
  if (url.pathname === '/auth/check') {
    const token = parseCookie(req.headers.cookie);
    if (token) {
      res.writeHead(200);
      return res.end();
    }
    // Return 302 redirect — Caddy forward_auth will pass this through
    res.writeHead(302, { 'Location': '/auth/login' });
    return res.end();
  }

  // Login page
  if (url.pathname === '/auth/login' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(LOGIN_HTML);
  }

  // Login submit
  if (url.pathname === '/auth/login' && req.method === 'POST') {
    const ip = getClientIp(req);
    if (!rateCheck(ip)) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Zu viele Versuche. Bitte warten.' }));
    }

    const body = await new Promise(resolve => {
      let data = '';
      req.on('data', c => data += c);
      req.on('end', () => resolve(data));
    });

    let token;
    try {
      const ct = req.headers['content-type'] || '';
      if (ct.includes('json')) {
        token = JSON.parse(body).token;
      } else {
        token = new URLSearchParams(body).get('token');
      }
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Ungültige Anfrage' }));
    }

    if (!token || token.length < 8) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Bitte Zugangsschlüssel eingeben' }));
    }

    // Validate token against gateway
    try {
      const gwRes = await fetch(`${GATEWAY_URL}/api/status`, {
        headers: { 'Authorization': `Bearer ${token}` },
        signal: AbortSignal.timeout(5000)
      });

      if (gwRes.ok || gwRes.status === 200) {
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Set-Cookie': makeSessionCookie(token)
        });
        return res.end(JSON.stringify({ ok: true }));
      }
    } catch (e) {
      console.error('Gateway check failed:', e.message);
    }

    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Ungültiger Zugangsschlüssel' }));
  }

  // Logout
  if (url.pathname === '/auth/logout') {
    res.writeHead(302, {
      'Set-Cookie': `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
      'Location': '/auth/login'
    });
    return res.end();
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`StartLobster Auth listening on :${PORT}`);
});
