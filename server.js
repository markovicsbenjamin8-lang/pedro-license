const express      = require("express");
const { v4: uuid } = require("uuid");
const crypto       = require("crypto");
const bcrypt       = require("bcryptjs");
const path         = require("path");
const fs           = require("fs");
const cookieParser = require("cookie-parser");
const rateLimit    = require("express-rate-limit");
const helmet       = require("helmet");
const { Pool }     = require("pg");

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme123";
const PORT           = process.env.PORT || 3000;
const SESSION_TTL    = 4 * 60 * 60 * 1000;
const BCRYPT_ROUNDS  = 12;
const COOKIE_SECRET  = process.env.COOKIE_SECRET || crypto.randomBytes(32).toString("hex");
const JAR_PATH       = path.join(__dirname, "pedro-debug-1.0.0.jar");

// ─── DATABASE ─────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS keys (
      id TEXT PRIMARY KEY,
      key TEXT UNIQUE NOT NULL,
      email TEXT,
      hwid TEXT,
      mc_username TEXT,
      blacklisted BOOLEAN DEFAULT false,
      expiry BIGINT,
      created_at BIGINT NOT NULL,
      redeemed_at BIGINT
    );
    CREATE TABLE IF NOT EXISTS accounts (
      email TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      failed_logins INT DEFAULT 0,
      locked_until BIGINT
    );
    CREATE TABLE IF NOT EXISTS banned_hwids (
      hwid TEXT PRIMARY KEY
    );
  `);
  console.log("Database ready");
}

// ─── SESSIONS (in-memory — fine since they expire in 4h) ─────────────────────
const adminSessions = new Map();
const userSessions  = new Map();

function mkToken() { return crypto.randomBytes(32).toString("hex"); }
function mkCsrf()  { return crypto.randomBytes(24).toString("hex"); }

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function getAdminSession(req) {
  const t = req.signedCookies?.adminToken || req.headers["x-admin-token"];
  if (!t || !adminSessions.has(t)) return null;
  const s = adminSessions.get(t);
  if (Date.now() > s.expiresAt) { adminSessions.delete(t); return null; }
  s.expiresAt = Date.now() + SESSION_TTL;
  return s;
}
function requireAdmin(req, res, next) {
  if (!getAdminSession(req)) return res.status(401).json({ error: "unauthorized" });
  next();
}

function getUserSession(req) {
  const t = req.signedCookies?.userToken || req.headers["x-user-token"];
  if (!t || !userSessions.has(t)) return null;
  const s = userSessions.get(t);
  if (Date.now() > s.expiresAt) { userSessions.delete(t); return null; }
  s.expiresAt = Date.now() + SESSION_TTL;
  return s;
}
function requireUser(req, res, next) {
  const s = getUserSession(req);
  if (!s) return res.status(401).json({ error: "not logged in" });
  req.userSession = s;
  next();
}
function requireCsrf(req, res, next) {
  const s = getUserSession(req);
  if (!s) return res.status(401).json({ error: "not logged in" });
  if (!safeEqual(req.headers["x-csrf-token"] || "", s.csrfToken))
    return res.status(403).json({ error: "invalid csrf token" });
  req.userSession = s;
  next();
}

function genKey() {
  const s = () => Math.random().toString(36).substring(2, 6).toUpperCase();
  return `${s()}-${s()}-${s()}-${s()}`;
}

const cookieOpts = (maxAge) => ({
  httpOnly: true, signed: true, sameSite: "strict",
  secure: process.env.NODE_ENV === "production", maxAge,
});

// ─── APP ──────────────────────────────────────────────────────────────────────
const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser(COOKIE_SECRET));
app.set("trust proxy", 1);

app.get("/",      (req, res) => res.sendFile(path.join(__dirname, "user.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

// ─── RATE LIMITING ────────────────────────────────────────────────────────────
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, message: { error: "too_many_attempts" } });
const apiLimiter  = rateLimit({ windowMs: 60*1000, max: 100, message: { error: "rate_limited" } });
app.use("/user/login",    authLimiter);
app.use("/user/register", authLimiter);
app.use("/auth/login",    authLimiter);
app.use("/api/",          apiLimiter);

// ─── ADMIN AUTH ───────────────────────────────────────────────────────────────
app.post("/auth/login", (req, res) => {
  const provided = Buffer.from(req.body.password || "");
  const expected = Buffer.from(ADMIN_PASSWORD);
  const match = provided.length === expected.length &&
    crypto.timingSafeEqual(expected, provided);
  if (!match) return res.status(403).json({ error: "wrong password" });
  const token = mkToken();
  adminSessions.set(token, { expiresAt: Date.now() + SESSION_TTL });
  res.cookie("adminToken", token, cookieOpts(SESSION_TTL));
  res.json({ token });
});
app.post("/auth/logout", (req, res) => {
  const t = req.signedCookies?.adminToken;
  if (t) adminSessions.delete(t);
  res.clearCookie("adminToken");
  res.json({ success: true });
});

// ─── ADMIN: KEYS ─────────────────────────────────────────────────────────────
app.get("/admin/keys", requireAdmin, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM keys ORDER BY created_at DESC");
  res.json(rows.map(r => ({
    id: r.id, key: r.key, email: r.email, hwid: r.hwid,
    mcUsername: r.mc_username, blacklisted: r.blacklisted,
    expiry: r.expiry ? Number(r.expiry) : null,
    createdAt: Number(r.created_at),
    redeemedAt: r.redeemed_at ? Number(r.redeemed_at) : null,
  })));
});

app.post("/admin/add-key", requireAdmin, async (req, res) => {
  const id  = uuid(), key = genKey(), now = Date.now();
  const exp = req.body.expiry ?? null;
  await pool.query(
    "INSERT INTO keys (id,key,blacklisted,expiry,created_at) VALUES ($1,$2,false,$3,$4)",
    [id, key, exp, now]
  );
  res.json({ id, key, email: null, hwid: null, mcUsername: null, blacklisted: false, expiry: exp, createdAt: now });
});

app.post("/admin/blacklist/:id", requireAdmin, async (req, res) => {
  const val = req.body.blacklisted !== false;
  const { rows } = await pool.query(
    "UPDATE keys SET blacklisted=$1 WHERE id=$2 RETURNING *", [val, req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: "not found" });
  res.json({ ...rows[0], mcUsername: rows[0].mc_username });
});

app.delete("/admin/key/:id", requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM keys WHERE id=$1", [req.params.id]);
  res.json({ success: true });
});

app.put("/admin/key/:id/expiry", requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    "UPDATE keys SET expiry=$1 WHERE id=$2 RETURNING *", [req.body.expiry ?? null, req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: "not found" });
  res.json(rows[0]);
});

// ─── ADMIN: HWIDS ─────────────────────────────────────────────────────────────
app.get("/admin/hwids", requireAdmin, async (req, res) => {
  const { rows: keys }  = await pool.query("SELECT * FROM keys WHERE hwid IS NOT NULL");
  const { rows: banned } = await pool.query("SELECT hwid FROM banned_hwids");
  const bannedSet = new Set(banned.map(b => b.hwid));
  res.json(keys.map(k => ({
    id: k.id, key: k.key, hwid: k.hwid, email: k.email,
    mcUsername: k.mc_username, blacklisted: k.blacklisted,
    banned: bannedSet.has(k.hwid),
  })));
});

app.post("/admin/ban-hwid", requireAdmin, async (req, res) => {
  const { hwid, ban } = req.body;
  if (!hwid) return res.status(400).json({ error: "hwid required" });
  if (ban !== false) {
    await pool.query("INSERT INTO banned_hwids (hwid) VALUES ($1) ON CONFLICT DO NOTHING", [hwid]);
  } else {
    await pool.query("DELETE FROM banned_hwids WHERE hwid=$1", [hwid]);
  }
  res.json({ success: true });
});

// ─── LICENSE CHECK (Java client) ─────────────────────────────────────────────
app.post("/check", async (req, res) => {
  const { hwid, email, mcUsername } = req.body;
  if (!hwid || !email) return res.json({ valid: false, reason: "missing" });
  const now = Date.now();
  const { rows: banned } = await pool.query("SELECT 1 FROM banned_hwids WHERE hwid=$1", [hwid]);
  if (banned.length) return res.json({ valid: false, reason: "banned" });
  const { rows } = await pool.query(
    "SELECT * FROM keys WHERE LOWER(email)=$1 AND blacklisted=false AND (expiry IS NULL OR expiry>$2)",
    [email.toLowerCase(), now]
  );
  const key = rows[0];
  if (!key) return res.json({ valid: false, reason: "no_key" });
  if (key.hwid && key.hwid !== hwid) return res.json({ valid: false, reason: "hwid_mismatch" });
  if (!key.hwid) await pool.query("UPDATE keys SET hwid=$1 WHERE id=$2", [hwid, key.id]);
  if (mcUsername) await pool.query("UPDATE keys SET mc_username=$1 WHERE id=$2", [mcUsername, key.id]);
  res.json({ valid: true });
});

// ─── USER AUTH ────────────────────────────────────────────────────────────────
app.post("/user/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "missing_fields" });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "invalid_email" });
  if (password.length < 8)  return res.status(400).json({ error: "password_too_short" });
  if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) return res.status(400).json({ error: "password_too_weak" });
  const { rows } = await pool.query("SELECT 1 FROM accounts WHERE email=$1", [email.toLowerCase()]);
  if (rows.length) return res.status(400).json({ error: "email_taken" });
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  await pool.query("INSERT INTO accounts (email,password_hash,created_at) VALUES ($1,$2,$3)",
    [email.toLowerCase(), hash, Date.now()]);
  res.json({ success: true });
});

app.post("/user/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "missing_fields" });
  const { rows } = await pool.query("SELECT * FROM accounts WHERE email=$1", [email.toLowerCase()]);
  const account = rows[0];
  const dummyHash = "$2a$12$invalidhashfortimingattacks0000000000000000000000000000000";
  const hashToCheck = account ? account.password_hash : dummyHash;
  if (account && account.locked_until && Date.now() < Number(account.locked_until)) {
    const mins = Math.ceil((Number(account.locked_until) - Date.now()) / 60000);
    return res.status(429).json({ error: "account_locked", minutesLeft: mins });
  }
  const ok = await bcrypt.compare(password, hashToCheck);
  if (!account || !ok) {
    if (account) {
      const fails = (account.failed_logins || 0) + 1;
      if (fails >= 5) {
        await pool.query("UPDATE accounts SET failed_logins=0,locked_until=$1 WHERE email=$2",
          [Date.now() + 15*60*1000, account.email]);
      } else {
        await pool.query("UPDATE accounts SET failed_logins=$1 WHERE email=$2", [fails, account.email]);
      }
    }
    return res.status(401).json({ error: "invalid_credentials" });
  }
  await pool.query("UPDATE accounts SET failed_logins=0,locked_until=NULL WHERE email=$1", [account.email]);
  const token = mkToken(), csrfToken = mkCsrf();
  userSessions.set(token, { email: account.email, expiresAt: Date.now() + SESSION_TTL, csrfToken });
  res.cookie("userToken", token, cookieOpts(SESSION_TTL));
  res.json({ token, csrfToken, email: account.email });
});

app.post("/user/logout", (req, res) => {
  const t = req.signedCookies?.userToken || req.headers["x-user-token"];
  if (t) userSessions.delete(t);
  res.clearCookie("userToken");
  res.json({ success: true });
});

app.get("/user/me", requireUser, async (req, res) => {
  const now = Date.now();
  const { rows } = await pool.query(
    "SELECT * FROM keys WHERE LOWER(email)=$1", [req.userSession.email]
  );
  const key = rows[0];
  res.json({
    email: req.userSession.email,
    csrfToken: req.userSession.csrfToken,
    hasKey: !!key,
    keyBlacklisted: key?.blacklisted ?? false,
    keyExpired: key ? (key.expiry !== null && Number(key.expiry) < now) : false,
    expiry: key?.expiry ? Number(key.expiry) : null,
  });
});

app.post("/user/redeem", requireCsrf, async (req, res) => {
  const keyCode = (req.body.key || "").trim().toUpperCase();
  if (!keyCode) return res.status(400).json({ error: "no_key" });
  const now = Date.now(), email = req.userSession.email;
  const { rows: existing } = await pool.query(
    "SELECT 1 FROM keys WHERE LOWER(email)=$1", [email]
  );
  if (existing.length) return res.status(400).json({ error: "already_redeemed" });
  const { rows } = await pool.query("SELECT * FROM keys WHERE key=$1", [keyCode]);
  const entry = rows[0];
  if (!entry)                                          return res.status(400).json({ error: "invalid_key" });
  if (entry.blacklisted)                               return res.status(400).json({ error: "blacklisted" });
  if (entry.email)                                     return res.status(400).json({ error: "already_used" });
  if (entry.expiry !== null && Number(entry.expiry) < now) return res.status(400).json({ error: "expired" });
  await pool.query("UPDATE keys SET email=$1,redeemed_at=$2 WHERE id=$3", [email, now, entry.id]);
  res.json({ success: true });
});

app.get("/user/download", requireUser, async (req, res) => {
  const now = Date.now();
  const { rows } = await pool.query(
    "SELECT 1 FROM keys WHERE LOWER(email)=$1 AND blacklisted=false AND (expiry IS NULL OR expiry>$2)",
    [req.userSession.email, now]
  );
  if (!rows.length) return res.status(403).json({ error: "no valid key" });
  if (!fs.existsSync(JAR_PATH)) return res.status(404).json({ error: "jar not found" });
  res.download(JAR_PATH, "pedro-debug.jar");
});

// ─── START ────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Admin: http://localhost:${PORT}/admin`);
    console.log(`User:  http://localhost:${PORT}/`);
  });
}).catch(err => {
  console.error("Failed to init DB:", err);
  process.exit(1);
});
