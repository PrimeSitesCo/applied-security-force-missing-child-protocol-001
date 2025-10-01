# applied-security-force-missing-child-protocol-001

Workers-only starter template for a Single Page Application (SPA): a single Cloudflare Worker serves both the **static site** and the **API**. Two environments: 

- **Prod Worker**: `app-template-001`
- **Dev Worker**: `app-template-001-dev`

Static files live in `/static`. Worker code, config, and D1 migrations live in `/workers`.

---

## New Project — Quick Start (VS Code only, no CLI)

**Flow:** duplicate → **create D1 DBs first** → wire IDs/names in config → initial commit → publish to GitHub → add GitHub Environments + Secrets → push `dev` → deploy → seed admin → promote to prod.

### 0) Duplicate the template
- Copy the entire folder to a new name (e.g., `my-new-app`).
- Delete the `.git/` folder in the copy (VS Code Explorer ➜ right-click ➜ Delete).

---

### 1) Create D1 databases **first**
Cloudflare Dashboard ➜ **D1**:
- Create **prod** DB (e.g., `my-new-app-database`). Copy its **Database ID**.
- Create **dev** DB (e.g., `my-new-app-database-dev`). Copy its **Database ID**.

---

### 2) Wire service names, D1 IDs, and vars
Open **`workers/wrangler.jsonc`** and update:
- **Service names**
  - `"name"` ➜ prod Worker service (e.g., `"my-new-app"`)
  - `"env.dev.name"` ➜ dev Worker service (e.g., `"my-new-app-dev"`)
- **D1 bindings (IDs & names)**
  - Root `d1_databases[0].database_id` ➜ prod DB ID
  - `env.dev.d1_databases[0].database_id` ➜ dev DB ID
  - Optionally update `database_name` fields to match your DB names
- **Turnstile**
  - Set upa new Turnstile instance on Cloudflare 
  - Copy the Site Key to the wrangler.jsonc for prod and dev, and into /static/public/index.html
  - Keep the Secret Key to add to Env Secrets in Github
- **Vars**
  - Update email/domain branding as needed (see “Variables to customize” below)
- **Assets**
  - Ensure `"assets.directory": "../static"` (unless you moved the static folder)

---

### 3) First commit (initialize repo history)
VS Code ➜ **Source Control**:
- **Initialize Repository** ➜ stage all ➜ commit (e.g., `init: workers-only template + D1 IDs`).

---

### 4) Publish to GitHub (main), then create `dev` branch
VS Code ➜ **Source Control**:
- **Publish Branch** ➜ creates `main` on GitHub.
- Bottom-left branch menu ➜ **Create new branch…** ➜ `dev` ➜ **Publish Branch**.

> You’ll do day-to-day work on `dev`. Promote to prod by PR `dev → main`.

---

### 5) Create GitHub **Environments** + **Secrets** (one-time per repo)
GitHub repo ➜ **Settings ➜ Environments**:
- Create **production**, **dev**
- In each environment, add Secrets:
  - `CF_API_TOKEN` ➜ Cloudflare API token with:
    - **Workers Scripts: Edit**
    - **D1: Read & Write**
  - `CF_ACCOUNT_ID` ➜ your Cloudflare account ID
  - `MAILGUN_API_KEY` ➜ your Mailgun key (use a test key in `dev` if preferred)
  - `TURNSTILE_SECRET` ➜ The Turnstyle Secret Key we got in an earlier step

---

### 6) Push on `dev` to deploy the dev Worker
Ensure `.github/workflows/deploy-worker.yml` exists (from the template).  
VS Code ➜ commit/push on `dev`.

GitHub ➜ **Actions**:
- “Put secrets (dev)” ➜ OK
- “Apply migrations (dev)” ➜ applies `migrations/0001_init.sql` to **remote** dev DB
- “Deploy (dev)” ➜ prints your dev Worker URL:
  - `https://my-new-app-dev.<your-subdomain>.workers.dev/`

Open that URL; the site should load.

---

### 7) Seed the admin user (dev)
Cloudflare Dashboard ➜ **D1** ➜ your **dev** DB ➜ **Query**:
```sql
INSERT INTO persons (name, email, roles, active, updated_at)
VALUES ('Admin', 'info@primesites.co', '["Administrator"]', 1, datetime('now'))
ON CONFLICT(email) DO UPDATE SET
  roles='["Administrator"]',
  active=1,
  updated_at=datetime('now');
```

---

### 8) Promote to prod (PR in VS Code)

1. Ensure you’re on the **`dev`** branch (bottom-left branch picker shows `dev`).
2. Open the **GitHub Pull Requests and Issues** view (left sidebar → GitHub icon).
3. Click **Create Pull Request**.
4. In the PR form:
   - **Base**: `main`
   - **Compare**: `dev`
   - Title: `Promote dev to prod`
   - Description: optional
5. Click **Create**, wait for checks to start, then **Merge** when green.

---

### 9) Watch the prod deploy (GitHub Actions)

1. In VS Code, open the **Actions** view (same GitHub extension) **or** open the **Actions** tab on GitHub.
2. Open the run for the merge to `main` (or the push that resulted from the merge).
3. Confirm the **prod** job ran these steps successfully, in order:
   - **Put secrets (prod)**
   - **Apply migrations (prod)** — should say it applied any new migrations to the *remote* DB
   - **Deploy (prod)** — shows your prod Worker URL, e.g.:
     - `https://my-new-app.<your-subdomain>.workers.dev/`
4. If any step failed, open it to read the logs (common causes: missing secret or incorrect D1 database_id).

---

### 10) Seed the admin in prod (D1 UI)

Cloudflare Dashboard → **D1** → select your **prod** DB → **Query** → run:

    INSERT INTO persons (name, email, roles, active, updated_at)
    VALUES ('Admin', 'info@primesites.co', '["Administrator"]', 1, datetime('now'))
    ON CONFLICT(email) DO UPDATE SET
      roles='["Administrator"]',
      active=1,
      updated_at=datetime('now');

Optional verification:

    SELECT id, name, email, roles, active
    FROM persons
    WHERE email='info@primesites.co';

---

### 11) Smoke-test prod

1. Visit the **prod Worker** URL (shown in the deploy step), e.g.  
   `https://my-new-app.<your-subdomain>.workers.dev/`
2. Request an OTP, enter it, and confirm:
   - The **logged-in header** (email/roles + logout) appears.
   - The **Welcome** card is visible.

---

### 12) Keep `dev` in sync (VS Code only)

After the PR merge:

1. Switch to **`main`** in VS Code → **Pull** (Source Control) if you want the latest prod state locally.
2. Switch back to **`dev`**.
3. Merge `main` into `dev`:
   - Command Palette → **Git: Merge Branch…** → choose `main`.
   - Resolve any conflicts if prompted → **Commit Merge**.
   - **Push** `dev`.

This keeps `dev` current for your next round of changes.

---

### 13) Optional finishing touches

- **Custom domains (later):** Map clean hostnames to your Worker routes (separately for dev/prod) in Cloudflare → Workers → *Triggers / Routes*.
- **Health endpoint (later):** Add `/srvr` in the Worker to return JSON `{ ok, d1_ok, env: {...} }` for quick environment checks.
- **Dev mail safety:** Ensure `MAIL_OVERRIDE` under `env.dev.vars` is set to a safe inbox (e.g., your address) so real users aren’t emailed from dev.