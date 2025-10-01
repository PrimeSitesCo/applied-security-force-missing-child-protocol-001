// Protected SPA entry — served only after auth by the Worker.
// Minimal client-side router with two pages: /dashboard and /account.

export function mountApp({ root, user }) {
  const mount = document.querySelector(root);
  if (!mount) return;

  // ---------- App shell (keeps your look & feel) ----------
  mount.innerHTML = `
    <div class="form-container">
      <div class="logo-container">
        <img src="/public/assets/logo-light.png" id="light-logo" alt="App" class="logo">
        <img src="/public/assets/logo-dark.png" id="dark-logo" alt="App" class="logo">
      </div>

      <!-- Simple nav -->
      <div class="form-section textSmaller" style="padding:12px 0;">
        <a href="/dashboard" data-nav>Dashboard</a>
        &nbsp;|&nbsp;
        <a href="/account" data-nav>Account</a>
        <span style="float:right;">
          <span class="textSmaller">Signed in as ${escapeHtml(user.name || 'User')} &lt;${escapeHtml(user.email)}&gt;</span>
          &nbsp;|&nbsp;
          <a href="#" id="logoutBtn">Log Out</a>
        </span>
      </div>

      <!-- Routed view gets rendered here -->
      <div id="view"></div>

      <div style="text-align:center; margin-top:30px;">
        <span class="textSmaller">Design &amp; Hosting by</span><br>
        <a href="https://www.primesites.com.au/" target="_blank" class="primesites_footer" title="Hosted &amp; Designed by PrimeSites Digital" alt="Hosted &amp; Designed by PrimeSites Digital">PrimeSites Digital</a>
      </div>
    </div>
  `;

  // Wire up logout
  document.getElementById('logoutBtn')?.addEventListener('click', (e) => {
    e.preventDefault();
    fetch('/logout', { method: 'POST' }).finally(() => (window.location.href = '/'));
  });

  // Router: map paths to renderers
  const routes = {
    '/': renderDashboard,
    '/dashboard': renderDashboard,
    '/account': renderAccount,
  };

  // Intercept in-app nav clicks
  delegateNavClicks();

  // Handle back/forward
  window.addEventListener('popstate', () => render(location.pathname));

  // Initial render (supports deep links)
  render(location.pathname);

  // -------- helpers --------
  function delegateNavClicks() {
    mount.addEventListener('click', (e) => {
      const link = e.target.closest('a[data-nav]');
      if (!link) return;
      const href = link.getAttribute('href');
      // Same-origin, client-side route only
      if (href && href.startsWith('/')) {
        e.preventDefault();
        navigate(href);
      }
    });
  }

  function navigate(path) {
    if (location.pathname !== path) history.pushState({}, '', path);
    render(path);
  }

  function render(path) {
    const view = document.getElementById('view');
    if (!view) return;

    const route = routes[path] || routes['/']; // fallback to dashboard
    // Render the view content
    view.innerHTML = route(user);

    // Optional: focus first heading for accessibility
    const h1 = view.querySelector('h1');
    h1 && h1.focus && h1.focus();
  }
}

// ---------- Views ----------
function renderDashboard(user) {
  return `
    <div class="form-section" tabindex="-1">
      <div>
        <h1>Dashboard</h1>
        <p>
          Welcome ${escapeHtml(user.name || 'User')}. This is the dashboard page.
        </p>
      </div>
      <div class="form-field">
        <label>Roles</label>
        <div>${Array.isArray(user.roles) && user.roles.length ? escapeHtml(user.roles.join(', ')) : 'No roles'}</div>
      </div>
    </div>
  `;
}

function renderAccount(user) {
  return `
    <div class="form-section" tabindex="-1">
      <div>
        <h1>Account</h1>
        <p>
          Your registered email is <strong>${escapeHtml(user.email)}</strong>.
        </p>
      </div>
      <div class="form-field">
        <label>Name</label>
        <div>${escapeHtml(user.name || 'Unknown')}</div>
      </div>
    </div>
  `;
}

// ---------- Utils ----------
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;', "'":'&#39;' }[c]
  ));
}