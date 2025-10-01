-- 0001_init.sql  (fresh installs)

-- Persons: core identity + security columns for OTP, sessions, magic links
CREATE TABLE IF NOT EXISTS persons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  roles TEXT NOT NULL DEFAULT '[]',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),

  -- OTP
  otp_hash TEXT,
  otp_expires_at TEXT,
  otp_attempts INTEGER NOT NULL DEFAULT 0,
  otp_last_sent_at TEXT,

  -- Session
  session_token_hash TEXT,
  session_expires_at TEXT,

  -- Magic links
  magic_link_token_hash TEXT,
  magic_link_expires_at TEXT
);

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_persons_otp_expires_at ON persons(otp_expires_at);
CREATE INDEX IF NOT EXISTS idx_persons_session_expires_at ON persons(session_expires_at);
CREATE INDEX IF NOT EXISTS idx_persons_magic_expires_at ON persons(magic_link_expires_at);

-- Simple fixed-window rate limits
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,          -- e.g. "ip:1.2.3.4" or "email:someone@x.com"
  count INTEGER NOT NULL DEFAULT 0,
  reset_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rl_reset_at ON rate_limits(reset_at);

-- Seed admin (idempotent upsert)
INSERT INTO persons (name, email, roles, active, updated_at)
VALUES ('Admin', 'info@primesites.co', '["Administrator"]', 1, datetime('now'))
ON CONFLICT(email) DO UPDATE SET
  roles='["Administrator"]',
  active=1,
  updated_at=datetime('now');