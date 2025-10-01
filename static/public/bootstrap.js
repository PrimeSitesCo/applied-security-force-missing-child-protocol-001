// static/public/bootstrap.js
// Public bootstrap: login shell + conditional Turnstile + SPA lazy-load (gated)

// Sections inside the login shell we toggle pre-auth
const sections = ['email-verification-form', 'otp-form', 'magic-wait'];

let CFG = {
  turnstile: { enabled: false, siteKey: '' }
};

// Idempotent flag to avoid double-mounting the app
let appMounted = false;

// ---- Dark mode cookie helpers (kept for UX) ----
function setCookie(name, value, days) {
  const date = new Date();
  date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
  document.cookie = `${name}=${value}; expires=${date.toUTCString()}; path=/; Secure; SameSite=Strict`;
}
function getCookie(name) {
  const nameEQ = name + "=";
  const ca = document.cookie.split(';');
  for (let i = 0; i < ca.length; i++) {
    let c = ca[i].trim();
    if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
  }
  return null;
}

// ---- View toggles (hide/show entire shells) ----
function showLoginShell(visible) {
  const shell = document.getElementById('login-shell');
  if (shell) shell.classList.toggle('hidden', !visible);
}
function showAppRoot(visible) {
  const root = document.getElementById('app-root');
  if (root) root.classList.toggle('hidden', !visible);
}

// ---- Toggle cards inside login shell ----
function showSection(sectionId) {
  sections.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('hidden', id !== sectionId);
  });
}

// ---- SPA mount helpers ----
function mountAppOnce({ user }) {
  if (appMounted) return;
  appMounted = true;
  import('/app/bootstrap.js')
    .then(mod => mod.mountApp({ root: '#app-root', user }))
    .catch(err => {
      console.error('Failed to load app bundle:', err);
      appMounted = false; // allow retry
    });
}
function unmountApp() {
  const root = document.getElementById('app-root');
  if (root) root.innerHTML = '';
  appMounted = false;
}

// ---- Turnstile loader (only if enabled) ----
let turnstileLoaded = false;
function loadTurnstile(siteKey) {
  if (turnstileLoaded) return Promise.resolve();
  return new Promise((resolve, reject) => {
    try {
      // Ensure the widget placeholder has the sitekey
      const widget = document.querySelector('.cf-turnstile');
      if (widget) widget.setAttribute('data-sitekey', siteKey);

      // Inject loader script
      const s = document.createElement('script');
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
      s.async = true;
      s.defer = true;
      s.onload = () => { turnstileLoaded = true; resolve(); };
      s.onerror = (e) => reject(e);
      document.head.appendChild(s);
    } catch (e) {
      reject(e);
    }
  });
}

// ---- Auth state refresh ----
function refreshAuthUI() {
  fetch('/me', { headers: { 'Accept': 'application/json' } })
    .then(r => r.json())
    .then(data => {
      if (data && data.authenticated) {
        // Hide login shell, show app, mount SPA
        showLoginShell(false);
        showAppRoot(true);
        mountAppOnce({ user: data });
      } else {
        // Show login shell; hide app
        unmountApp();
        showAppRoot(false);
        showLoginShell(true);
        showSection('email-verification-form');
      }
    })
    .catch(() => {
      unmountApp();
      showAppRoot(false);
      showLoginShell(true);
      showSection('email-verification-form');
    });
}

// ---- Event handlers (login + OTP) ----
function submitEmailForVerification() {
  const button = document.querySelector('#emailVerificationForm button');
  if (button) button.disabled = true;
  const emailEl = document.getElementById('verification-email');
  const email = emailEl ? String(emailEl.value || '').toLowerCase().trim() : '';

  // Turnstile token if present
  const tsInput = document.querySelector('input[name="cf-turnstile-response"]');
  const turnstileToken = tsInput ? tsInput.value : '';

  fetch('/verify-email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, turnstileToken })
  })
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        try { window.turnstile && window.turnstile.reset(); } catch {}
        if (data.magicLink === true) {
          showSection('magic-wait');
        } else {
          showSection('otp-form');
        }
      } else {
        alert(data.error || 'Email not authorized');
      }
    })
    .catch(err => console.error('Fetch error:', err))
    .finally(() => { if (button) button.disabled = false; });
}

function verifyOTP() {
  const button = document.querySelector('#otpVerificationForm button');
  if (button) button.disabled = true;
  const otp = document.getElementById('otp')?.value || '';
  const email = document.getElementById('verification-email')?.value.toLowerCase() || '';

  fetch('/check-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, otp })
  })
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        refreshAuthUI();
      } else {
        alert(data.error || 'Incorrect OTP');
      }
    })
    .catch(err => console.error('Fetch error:', err))
    .finally(() => { if (button) button.disabled = false; });
}

function logoutUser() {
  fetch('/logout', { method: 'POST' })
    .finally(() => window.location.reload());
}

// ---- Boot ----
document.addEventListener('DOMContentLoaded', () => {
  // Dark mode init
  const darkModeToggle = document.getElementById('dark-mode-toggle');
  const darkModeCookie = getCookie('darkMode');
  if (darkModeCookie === 'enabled' || darkModeCookie === null) {
    document.body.classList.add('dark-mode');
    darkModeToggle && (darkModeToggle.checked = true);
    if (darkModeCookie === null) setCookie('darkMode', 'enabled', 300);
  }
  darkModeToggle?.addEventListener('change', function () {
    if (this.checked) {
      document.body.classList.add('dark-mode');
      setCookie('darkMode', 'enabled', 300);
    } else {
      document.body.classList.remove('dark-mode');
      setCookie('darkMode', 'disabled', 300);
    }
  });

  // Wire forms
  document.getElementById('emailVerificationForm')?.addEventListener('submit', (e) => {
    e.preventDefault();
    submitEmailForVerification();
  });
  document.getElementById('otpVerificationForm')?.addEventListener('submit', (e) => {
    e.preventDefault();
    verifyOTP();
  });
  document.getElementById('logoutLink')?.addEventListener('click', (e) => {
    e.preventDefault();
    logoutUser();
  });

  // 1) Fetch config (decide whether to load Turnstile)
  fetch('/config', { headers: { 'Accept': 'application/json' } })
    .then(r => r.json())
    .then(cfg => {
      CFG = cfg || CFG;
      if (CFG.turnstile && CFG.turnstile.enabled && CFG.turnstile.siteKey) {
        return loadTurnstile(CFG.turnstile.siteKey);
      }
    })
    .catch(() => { /* ignore */ })
    // 2) Regardless of Turnstile, check auth and render appropriate view
    .finally(() => {
      refreshAuthUI();
    });
});