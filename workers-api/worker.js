// workers-api/worker.js
// Dedicated JSON API worker (no assets). All endpoints live under /api/*

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method.toUpperCase();

      // ---- CORS preflight (safe even if same-origin) ----
      if (method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: corsHeaders(request),
        });
      }

      // ---- Health/probe ----
      if (method === 'GET' && path === '/api/__who') {
        return text(`api-worker env=${env.ENV_NAME || 'unknown'} ts=${new Date().toISOString()}`);
      }

      if (method === 'GET' && path === '/api/config') {
        const enabled = String(env.TURNSTILE_ENABLED || '').toLowerCase() === 'true';
        const siteKey = env.TURNSTILE_SITE_KEY || '';
        return json({ turnstile: { enabled, siteKey } });
      }

      // ---- Auth & session ----
      if (method === 'POST' && path === '/api/verify-email') {
        return handleVerifyEmail(request, env);
      }

      if (method === 'POST' && path === '/api/check-otp') {
        return handleCheckOtp(request, env);
      }

      if (method === 'POST' && path === '/api/logout') {
        return handleLogout(request, env);
      }

      if (method === 'GET' && path === '/api/magic-login') {
        return handleMagicLogin(request, env);
      }

      if (method === 'GET' && path === '/api/me') {
        return handleMe(request, env);
      }

      // Fallback
      return json({ success: false, error: 'Not found' }, 404);
    } catch (err) {
      console.error('API worker error:', err);
      return json({ success: false, error: 'Server error' }, 500);
    }
  }
};

/* =======================
 *  Utilities & helpers
 * ======================= */
function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store, no-cache, must-revalidate',
      'pragma': 'no-cache',
      'expires': '0',
      ...corsHeadersNoStar(),
      ...headers,
    },
  });
}
function text(s, status = 200, headers = {}) {
  return new Response(String(s), {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      ...corsHeadersNoStar(),
      ...headers,
    },
  });
}
function corsHeaders(_request) {
  const origin = '*'; // if you later need to lock to specific origins, change here
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Vary': 'Origin',
  };
}
function corsHeadersNoStar() {
  // For same-origin XHR/fetch this is fine; kept separate to avoid overriding.
  return {};
}

async function readJson(req) {
  const t = await req.text();
  try { return JSON.parse(t || '{}'); }
  catch { return {}; }
}

function sanitizeEmail(x) {
  return String(x || '').trim().toLowerCase();
}
function toISO(d) { return d.toISOString(); }
function addSeconds(date, sec) { return new Date(date.getTime() + sec * 1000); }
function addHours(date, hrs) { return new Date(date.getTime() + hrs * 3600 * 1000); }
function nowISO() { return new Date().toISOString(); }
function parseBool(v, def = false) {
  if (v === undefined || v === null) return def;
  const s = String(v).toLowerCase().trim();
  return s === '1' || s === 'true' || s === 'yes';
}
function b64url(buf) {
  let b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
async function sha256(text) {
  const enc = new TextEncoder();
  const data = enc.encode(text);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return b64url(digest);
}
function randomToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return b64url(arr);
}
function serializeCookie(name, value, opts = {}) {
  const parts = [`${name}=${value || ''}`];
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(opts.maxAge))}`);
  if (opts.domain) parts.push(`Domain=${opts.domain}`);
  if (opts.path) parts.push(`Path=${opts.path}`);
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  if (opts.secure) parts.push('Secure');
  if (opts.httpOnly) parts.push('HttpOnly');
  return parts.join('; ');
}
function readCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const pattern = "(?:^|; )" + name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&") + "=([^;]*)";
  const regex = new RegExp(pattern);
  const m = cookie.match(regex);
  return m ? decodeURIComponent(m[1]) : "";
}
function minutesRemaining(iso) {
  if (!iso) return 0;
  const ms = new Date(iso).getTime() - Date.now();
  return Math.max(0, Math.ceil(ms / 60000));
}
function baseUrl(env, request) {
  return (env.APP_BASE_URL && String(env.APP_BASE_URL).trim()) || (() => {
    const u = new URL(request.url);
    return `${u.protocol}//${u.host}`;
  })();
}

/* =======================
 *  DB helpers (D1)
 * ======================= */
async function dbGetPersonByEmail(db, email) {
  const stmt = db.prepare(
    `SELECT id, name, email, roles, active,
            otp_hash, otp_expires_at, otp_attempts, otp_last_sent_at,
            session_token_hash, session_expires_at,
            magic_link_token_hash, magic_link_expires_at
     FROM persons WHERE email = ?`
  ).bind(email);
  return await stmt.first();
}
async function dbUpdatePerson(db, email, fields) {
  const keys = Object.keys(fields);
  if (!keys.length) return;
  const sets = keys.map(k => `${k} = ?`).join(', ');
  const values = keys.map(k => fields[k]);
  const stmt = db.prepare(`UPDATE persons SET ${sets}, updated_at = datetime('now') WHERE email = ?`)
                 .bind(...values, email);
  await stmt.run();
}
async function checkRateLimit(db, key, limit, windowSec) {
  const now = new Date();
  const row = await db.prepare(`SELECT key, count, reset_at FROM rate_limits WHERE key = ?`).bind(key).first();
  if (!row) {
    const resetAt = toISO(addSeconds(now, windowSec));
    await db.prepare(`INSERT INTO rate_limits (key, count, reset_at) VALUES (?, ?, ?)`)
            .bind(key, 1, resetAt).run();
    return { allowed: true, remaining: limit - 1, reset_at: resetAt };
  }
  if (new Date(row.reset_at) <= now) {
    const resetAt = toISO(addSeconds(now, windowSec));
    await db.prepare(`UPDATE rate_limits SET count = 1, reset_at = ? WHERE key = ?`).bind(resetAt, key).run();
    return { allowed: true, remaining: limit - 1, reset_at: resetAt };
  }
  const newCount = (row.count || 0) + 1;
  await db.prepare(`UPDATE rate_limits SET count = ? WHERE key = ?`).bind(newCount, key).run();
  return { allowed: newCount <= limit, remaining: Math.max(0, limit - newCount), reset_at: row.reset_at };
}

/* =======================
 *  Mail & Turnstile
 * ======================= */
async function verifyTurnstileIfEnabled(env, token, remoteip) {
  const enabled = parseBool(env.TURNSTILE_ENABLED, false);
  if (!enabled) return { ok: true };
  if (!token) return { ok: false, reason: 'missing-token' };

  const secret = env.TURNSTILE_SECRET;
  if (!secret) {
    console.warn('TURNSTILE_ENABLED=true but TURNSTILE_SECRET missing');
    return { ok: false, reason: 'server-misconfig' };
  }

  const form = new URLSearchParams();
  form.set('secret', secret);
  form.set('response', token);
  if (remoteip) form.set('remoteip', remoteip);

  const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
  let data = null; try { data = await resp.json(); } catch {}
  if (resp.ok && data && data.success) return { ok: true };
  console.warn('Turnstile verify failed:', resp.status, data);
  return { ok: false, reason: 'invalid-token' };
}

async function sendEmail(env, { to, subject, text }) {
  const domain = env.MAILGUN_DOMAIN;
  const apiKey = env.MAILGUN_API_KEY;
  const base = env.MAILGUN_BASE_URL || 'https://api.mailgun.net';
  const fromName = env.FROM_EMAIL_NAME || 'App';
  const fromEmail = env.FROM_EMAIL || 'no-reply@example.com';
  const bcc = env.BCC_EMAIL || '';
  const override = (env.MAIL_OVERRIDE || '').trim().toLowerCase();

  let recipients = Array.isArray(to) ? to.join(',') : String(to || '').trim();
  let note = '';
  if (override && override !== 'false') {
    note = `\n\n[ORIGINAL RECIPIENT(S): ${recipients}]`;
    recipients = override;
  }

  const auth = 'Basic ' + btoa(`api:${apiKey || ''}`);
  const body = new URLSearchParams({
    from: `${fromName} <${fromEmail}>`,
    to: recipients,
    subject,
    text: text + note,
  });
  if (bcc) body.set('bcc', bcc);

  const res = await fetch(`${base}/v3/${domain}/messages`, {
    method: 'POST',
    headers: { 'Authorization': auth, 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  if (!res.ok) {
    const clone = res.clone();
    let payload; try { payload = await res.json(); } catch { payload = await clone.text(); }
    console.error('Mailgun API error:', res.status, payload);
    return false;
  }
  return true;
}

/* =======================
 *  Handlers
 * ======================= */
function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP') || request.headers.get('x-forwarded-for') || '0.0.0.0';
}

async function handleVerifyEmail(request, env) {
  const ip = getClientIP(request);
  const { email: rawEmail, turnstileToken = '' } = await readJson(request);
  const email = sanitizeEmail(rawEmail);

  // rate limits
  const ipR = await checkRateLimit(env.DATABASE, `ip:${ip}:verify`, Number(env.RATE_IP_MAX || 20), Number(env.RATE_IP_WINDOW_SEC || 60));
  if (!ipR.allowed) return json({ success: false, error: 'Too many requests. Try again later.' }, 429);
  const emailR = await checkRateLimit(env.DATABASE, `email:${email}:verify`, Number(env.RATE_EMAIL_MAX || 10), Number(env.RATE_EMAIL_WINDOW_SEC || 300));
  if (!emailR.allowed) return json({ success: false, error: 'Too many requests. Try again later.' }, 429);

  const ts = await verifyTurnstileIfEnabled(env, turnstileToken, ip);
  if (!ts.ok) return json({ success: false, error: 'Verification failed. Please refresh and try again.' }, 400);

  const person = await dbGetPersonByEmail(env.DATABASE, email);
  if (!person || !person.active) return json({ success: false, error: 'Email not authorized' }, 403);

  const cooldownSec = Number(env.OTP_RESEND_COOLDOWN_SECONDS || 45);
  if (person.otp_last_sent_at && new Date(person.otp_last_sent_at) > new Date(Date.now() - cooldownSec * 1000)) {
    const m = minutesRemaining(addSeconds(new Date(person.otp_last_sent_at), cooldownSec).toISOString());
    return json({ success: false, error: `Please wait a moment before requesting another code (${m}m).` }, 429);
  }

  const useMagic = parseBool(env.USE_MAGIC_LINK, false);
  const otpTtl = Number(env.OTP_TTL_SECONDS || 300);
  const expiresAt = toISO(addSeconds(new Date(), otpTtl));

  if (useMagic) {
    const token = randomToken(32);
    const tokenHash = await sha256(token);
    await dbUpdatePerson(env.DATABASE, email, {
      magic_link_token_hash: tokenHash,
      magic_link_expires_at: expiresAt,
      otp_hash: null,
      otp_expires_at: null,
      otp_attempts: 0,
      otp_last_sent_at: nowISO(),
    });

    const link = `${baseUrl(env, request)}/api/magic-login?e=${encodeURIComponent(email)}&t=${encodeURIComponent(token)}`;
    const ok = await sendEmail(env, {
      to: email,
      subject: 'Your secure sign-in link',
      text: `Click this link to sign in: ${link}\n\nThis link expires in ${Math.round(otpTtl/60)} minutes.`,
    });

    if (!ok) return json({ success: false, error: 'Failed to send email' }, 500);
    return json({ success: true, magicLink: true });
  }

  // OTP flow
  const otp = (Math.floor(100000 + Math.random() * 900000)).toString();
  const otpHash = await sha256(otp);

  await dbUpdatePerson(env.DATABASE, email, {
    otp_hash: otpHash,
    otp_expires_at: expiresAt,
    otp_attempts: 0,
    otp_last_sent_at: nowISO(),
    magic_link_token_hash: null,
    magic_link_expires_at: null,
  });

  const ok = await sendEmail(env, {
    to: email,
    subject: 'Your OTP',
    text: `Your OTP is: ${otp}\n\nThis code expires in ${Math.round(otpTtl/60)} minutes.`,
  });

  if (!ok) return json({ success: false, error: 'Failed to send email' }, 500);
  return json({ success: true });
}

async function handleCheckOtp(request, env) {
  const ip = getClientIP(request);
  const { email: rawEmail, otp: codeRaw } = await readJson(request);
  const email = sanitizeEmail(rawEmail);
  const code = String(codeRaw || '').trim();

  // rate limits
  const ipR = await checkRateLimit(env.DATABASE, `ip:${ip}:check`, Number(env.RATE_IP_MAX || 20), Number(env.RATE_IP_WINDOW_SEC || 60));
  if (!ipR.allowed) return json({ success: false, error: 'Too many requests. Try again later.' }, 429);
  const emailR = await checkRateLimit(env.DATABASE, `email:${email}:check`, Number(env.RATE_EMAIL_MAX || 10), Number(env.RATE_EMAIL_WINDOW_SEC || 300));
  if (!emailR.allowed) return json({ success: false, error: 'Too many requests. Try again later.' }, 429);

  const person = await dbGetPersonByEmail(env.DATABASE, email);
  if (!person || !person.active) return json({ success: false, error: 'Email not authorized' }, 403);

  const maxAttempts = Number(env.OTP_MAX_ATTEMPTS || 5);
  if (!person.otp_hash || !person.otp_expires_at) {
    return json({ success: false, error: 'No active OTP. Please request a new code.' }, 400);
  }
  if (new Date(person.otp_expires_at) < new Date()) {
    await dbUpdatePerson(env.DATABASE, email, { otp_hash: null, otp_expires_at: null, otp_attempts: 0 });
    return json({ success: false, error: 'OTP expired. Please request a new code.' }, 400);
  }
  if ((person.otp_attempts || 0) >= maxAttempts) {
    await dbUpdatePerson(env.DATABASE, email, { otp_hash: null, otp_expires_at: null, otp_attempts: 0 });
    return json({ success: false, error: 'Too many attempts. Please request a new code.' }, 429);
  }

  const inputHash = await sha256(code);
  if (inputHash !== person.otp_hash) {
    await dbUpdatePerson(env.DATABASE, email, { otp_attempts: (person.otp_attempts || 0) + 1 });
    return json({ success: false, error: 'Incorrect OTP' }, 401);
  }

  // success → create session
  const sessionTTLh = Number(env.SESSION_TTL_HOURS || 24);
  const token = randomToken(32);
  const tokenHash = await sha256(token);
  const sessionExp = toISO(addHours(new Date(), sessionTTLh));

  await dbUpdatePerson(env.DATABASE, email, {
    otp_hash: null,
    otp_expires_at: null,
    otp_attempts: 0,
    session_token_hash: tokenHash,
    session_expires_at: sessionExp,
  });

  const cookieName = env.COOKIE_NAME || 'session';
  const cookie = serializeCookie(cookieName, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    path: '/',
    maxAge: sessionTTLh * 3600,
  });

  const roles = (() => { try { return JSON.parse(person.roles || '[]') || []; } catch { return []; } })();

  return json({
    success: true,
    name: person.name || 'User',
    email,
    roles,
  }, 200, { 'Set-Cookie': cookie });
}

async function handleLogout(request, env) {
  const cookieName = env.COOKIE_NAME || 'session';
  const token = readCookie(request, cookieName);
  if (token) {
    const tokenHash = await sha256(token);
    await env.DATABASE.prepare(
      `UPDATE persons SET session_token_hash = NULL, session_expires_at = NULL, updated_at = datetime('now')
       WHERE session_token_hash = ?`
    ).bind(tokenHash).run();
  }
  const clear = serializeCookie(cookieName, '', {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    path: '/',
    maxAge: 0,
  });
  return json({ success: true }, 200, { 'Set-Cookie': clear });
}

async function handleMagicLogin(request, env) {
  if (!parseBool(env.USE_MAGIC_LINK, false)) {
    return json({ success: false, error: 'Not enabled' }, 404);
  }
  const url = new URL(request.url);
  const email = sanitizeEmail(url.searchParams.get('e'));
  const token = url.searchParams.get('t') || '';

  const person = await dbGetPersonByEmail(env.DATABASE, email);
  if (!person || !person.active) return json({ success: false, error: 'Unauthorized' }, 403);
  if (!person.magic_link_token_hash || !person.magic_link_expires_at) {
    return json({ success: false, error: 'Invalid or expired link' }, 400);
  }
  if (new Date(person.magic_link_expires_at) < new Date()) {
    await dbUpdatePerson(env.DATABASE, email, { magic_link_token_hash: null, magic_link_expires_at: null });
    return json({ success: false, error: 'Link expired' }, 400);
  }

  const inputHash = await sha256(token);
  if (inputHash !== person.magic_link_token_hash) {
    return json({ success: false, error: 'Invalid link' }, 400);
  }

  const sessionTTLh = Number(env.SESSION_TTL_HOURS || 24);
  const newToken = randomToken(32);
  const newHash = await sha256(newToken);
  const sessionExp = toISO(addHours(new Date(), sessionTTLh));

  await dbUpdatePerson(env.DATABASE, email, {
    magic_link_token_hash: null,
    magic_link_expires_at: null,
    session_token_hash: newHash,
    session_expires_at: sessionExp,
  });

  const cookieName = env.COOKIE_NAME || 'session';
  const cookie = serializeCookie(cookieName, newToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    path: '/',
    maxAge: sessionTTLh * 3600,
  });

  return new Response(null, { status: 302, headers: { 'Location': '/', 'Set-Cookie': cookie } });
}

async function handleMe(request, env) {
  const cookieName = env.COOKIE_NAME || 'session';
  const token = readCookie(request, cookieName);
  if (!token) return json({ authenticated: false });

  const tokenHash = await sha256(token);
  const row = await env.DATABASE.prepare(
    `SELECT name, email, roles, session_expires_at
     FROM persons
     WHERE session_token_hash = ?`
  ).bind(tokenHash).first();

  if (!row) return json({ authenticated: false });
  if (!row.session_expires_at || new Date(row.session_expires_at) < new Date()) {
    await env.DATABASE.prepare(
      `UPDATE persons SET session_token_hash=NULL, session_expires_at=NULL, updated_at=datetime('now')
       WHERE session_token_hash = ?`
    ).bind(tokenHash).run();
    return json({ authenticated: false });
  }

  let roles = [];
  try { roles = JSON.parse(row.roles || '[]') || []; } catch { roles = []; }

  return json({ authenticated: true, name: row.name || 'User', email: row.email, roles });
}