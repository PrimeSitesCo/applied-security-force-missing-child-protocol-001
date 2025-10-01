// Add magic-wait + welcome-card to the sections so showSection works
const sections = ['email-verification-form', 'otp-form', 'welcome-card', 'magic-wait'];

document.addEventListener('DOMContentLoaded', function() {
    // ---- Dark mode (unchanged) ----
    const darkModeToggle = document.getElementById('dark-mode-toggle');
    const darkModeCookie = getCookie('darkMode');
    if (darkModeCookie === 'enabled') {
        document.body.classList.add('dark-mode');
        darkModeToggle.checked = true;
    } else if (darkModeCookie === null) {
        document.body.classList.add('dark-mode');
        darkModeToggle.checked = true;
        setCookie('darkMode', 'enabled', 300);
    }
    darkModeToggle.addEventListener('change', function() {
        if (this.checked) {
            document.body.classList.add('dark-mode');
            setCookie('darkMode', 'enabled', 300);
        } else {
            document.body.classList.remove('dark-mode');
            setCookie('darkMode', 'disabled', 300);
        }
    });

    // On load, ask the server who we are (since session is HttpOnly)
    refreshAuthUI();

    document.getElementById('emailVerificationForm').addEventListener('submit', function(event) {
        event.preventDefault();
        submitEmailForVerification();
    });

    document.getElementById('otpVerificationForm').addEventListener('submit', function(event) {
        event.preventDefault();
        verifyOTP();
    });

    document.getElementById('logoutLink').addEventListener('click', function(event) {
        event.preventDefault();
        logoutUser();
    });
});

function refreshAuthUI() {
    fetch('/me', { method: 'GET', headers: { 'Accept': 'application/json' } })
      .then(r => r.json())
      .then(data => {
          const loggedInInfo = document.getElementById('loggedInInfo');
          if (data && data.authenticated) {
              // Show welcome view
              loggedInInfo.classList.remove('hidden');
              const roles = Array.isArray(data.roles) ? data.roles : [];
              document.getElementById('loggedInEmail').textContent =
                  `Logged in as ${data.name || 'User'} (${roles.join(', ') || 'No roles'})`;
              showSection('welcome-card');
          } else {
              // Not logged in; show email form by default
              loggedInInfo.classList.add('hidden');
              showSection('email-verification-form');
          }
      })
      .catch(err => {
          console.warn('Failed to load /me:', err);
          showSection('email-verification-form');
      });
}

// === Login mechanism with Turnstile support ===
function submitEmailForVerification() {
    const button = document.querySelector('#emailVerificationForm button');
    button.disabled = true;
    const email = document.getElementById('verification-email').value.toLowerCase();

    // Turnstile token if present
    const tsInput = document.querySelector('input[name="cf-turnstile-response"]');
    const turnstileToken = tsInput ? tsInput.value : '';

    console.log(`Fetching /verify-email for ${email} (turnstile token present: ${!!turnstileToken})`);

    fetch('/verify-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, turnstileToken })
    })
    .then(response => {
        console.log(`Verify status: ${response.status}`);
        return response.json();
    })
    .then(data => {
        if (data.success) {
            try { window.turnstile && window.turnstile.reset(); } catch (e) {}
            if (data.magicLink === true) {
                // Magic-link mode: show waiting message, do NOT show OTP form
                showSection('magic-wait');
            } else {
                // OTP mode
                showSection('otp-form');
            }
        } else {
            alert(data.error || 'Email not authorized');
        }
    })
    .catch(error => console.error(`Fetch error: ${error}`))
    .finally(() => button.disabled = false);
}

function verifyOTP() {
    const button = document.querySelector('#otpVerificationForm button');
    button.disabled = true;
    const otp = document.getElementById('otp').value;
    const email = document.getElementById('verification-email').value.toLowerCase();

    console.log(`Fetching /check-otp with OTP ${otp}`);

    fetch('/check-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp })
    })
    .then(response => {
        console.log(`Check OTP status: ${response.status}`);
        return response.json();
    })
    .then(data => {
        if (data.success) {
            // No need to rely on client cookies; the server set an HttpOnly session cookie.
            // Just refresh the UI from /me
            refreshAuthUI();
        } else {
            alert(data.error || 'Incorrect OTP');
        }
    })
    .catch(error => console.error(`Fetch error: ${error}`))
    .finally(() => button.disabled = false);
}

function showSection(sectionId) {
    sections.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.classList.toggle('hidden', id !== sectionId);
        } else {
            console.warn(`Element with ID ${id} not found in DOM`);
        }
    });
    console.log(`Showing section: ${sectionId}`);
}

// --- Legacy cookie helpers kept for dark-mode + compatibility ---
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
        if (c.indexOf(nameEQ) === 0) {
            const value = c.substring(nameEQ.length, c.length);
            console.log(`Cookie ${name} found: ${value}`);
            return value;
        }
    }
    console.log(`Cookie ${name} not found`);
    return null;
}
function logoutUser() {
    fetch('/logout', { method: 'POST', headers: { 'Accept': 'application/json' } })
      .then(() => window.location.reload())
      .catch(() => window.location.reload());
}