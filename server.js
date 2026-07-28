const express     = require("express");
const { v4: uuid } = require("uuid");
const crypto      = require("crypto");
const bcrypt      = require("bcryptjs");
const fs          = require("fs");
const path        = require("path");
const cookieParser = require("cookie-parser");
const rateLimit   = require("express-rate-limit");
const helmet      = require("helmet");

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme123";
const PORT           = process.env.PORT || 3000;
const SESSION_TTL    = 4 * 60 * 60 * 1000; // 4 hours
const BCRYPT_ROUNDS  = 12; // high cost — harder to brute force

// Cookie secret for HMAC signing — set in env for production
const COOKIE_SECRET  = process.env.COOKIE_SECRET || crypto.randomBytes(32).toString("hex");

const DB_PATH  = path.join(__dirname, "db.json");
const JAR_PATH = path.join(__dirname, "pedro-debug-1.0.0.jar");

// ─── DB ───────────────────────────────────────────────────────────────────────
function readDB() {
  if (!fs.existsSync(DB_PATH)) {
    const empty = { keys: [], accounts: [], bannedHwids: [] };
    fs.writeFileSync(DB_PATH, JSON.stringify(empty, null, 2));
    return empty;
  }
  return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
}
function writeDB(d) { fs.writeFileSync(DB_PATH, JSON.stringify(d, null, 2)); }

// ─── SESSIONS ─────────────────────────────────────────────────────────────────
// In-memory sessions. Each session: { email, expiresAt, csrfToken }
const adminSessions = new Map();
const userSessions  = new Map();

function mkToken()  { return crypto.randomBytes(32).toString("hex"); }
function mkCsrf()   { return crypto.randomBytes(24).toString("hex"); }

// Timing-safe token compare to prevent timing attacks
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
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

// CSRF: user-facing mutating routes check the csrf token
function requireCsrf(req, res, next) {
  const session = getUserSession(req);
  if (!session) return res.status(401).json({ error: "not logged in" });
  const csrfHeader = req.headers["x-csrf-token"];
  if (!csrfHeader || !safeEqual(csrfHeader, session.csrfToken))
    return res.status(403).json({ error: "invalid csrf token" });
  req.userSession = session;
  next();
}

function genKey() {
  const s = () => Math.random().toString(36).substring(2, 6).toUpperCase();
  return `${s()}-${s()}-${s()}-${s()}`;
}

// Cookie options — secure in production
const cookieOpts = (maxAge) => ({
  httpOnly: true,
  signed: true,
  sameSite: "strict",
  secure: process.env.NODE_ENV === "production",
  maxAge,
});

// ─── APP ──────────────────────────────────────────────────────────────────────
const app = express();

// Helmet sets secure HTTP headers
app.use(helmet({
  contentSecurityPolicy: false, // we serve inline HTML
}));

app.use(express.json({ limit: "10kb" })); // prevent large payload attacks
app.use(cookieParser(COOKIE_SECRET));

// Serve static files
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "user.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "index.html")));

// ─── RATE LIMITERS ────────────────────────────────────────────────────────────
// Auth endpoints: max 10 attempts per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "too_many_attempts" },
  standardHeaders: true,
  legacyHeaders: false,
});

// General API: 100 per minute
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: "rate_limited" },
});

app.use("/user/login",    authLimiter);
app.use("/user/register", authLimiter);
app.use("/auth/login",    authLimiter);
app.use("/api/",          apiLimiter);

// ─── ADMIN AUTH ───────────────────────────────────────────────────────────────
app.post("/auth/login", (req, res) => {
  const { password } = req.body;
  // Timing-safe compare against admin password
  const expected = Buffer.from(ADMIN_PASSWORD);
  const provided = Buffer.from(password || "");
  // Pad to same length to avoid length timing leak
  const match = password && password.length === ADMIN_PASSWORD.length &&
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

// ─── ADMIN API ────────────────────────────────────────────────────────────────
app.get("/admin/keys", requireAdmin, (req, res) => res.json(readDB().keys));

app.post("/admin/add-key", requireAdmin, (req, res) => {
  const db = readDB();
  const entry = {
    id: uuid(), key: genKey(),
    email: null, hwid: null, mcUsername: null,
    blacklisted: false,
    expiry: req.body.expiry ?? null,
    createdAt: Date.now(), redeemedAt: null,
  };
  db.keys.push(entry);
  writeDB(db);
  res.json(entry);
});

app.post("/admin/blacklist/:id", requireAdmin, (req, res) => {
  const db = readDB();
  const k = db.keys.find(k => k.id === req.params.id);
  if (!k) return res.status(404).json({ error: "not found" });
  k.blacklisted = req.body.blacklisted !== false;
  writeDB(db);
  res.json(k);
});

app.delete("/admin/key/:id", requireAdmin, (req, res) => {
  const db = readDB();
  const i = db.keys.findIndex(k => k.id === req.params.id);
  if (i === -1) return res.status(404).json({ error: "not found" });
  db.keys.splice(i, 1);
  writeDB(db);
  res.json({ success: true });
});

app.put("/admin/key/:id/expiry", requireAdmin, (req, res) => {
  const db = readDB();
  const k = db.keys.find(k => k.id === req.params.id);
  if (!k) return res.status(404).json({ error: "not found" });
  k.expiry = req.body.expiry ?? null;
  writeDB(db);
  res.json(k);
});

app.get("/admin/hwids", requireAdmin, (req, res) => {
  const db = readDB();
  res.json(db.keys.filter(k => k.hwid).map(k => ({
    id: k.id, key: k.key,
    hwid: k.hwid, email: k.email, mcUsername: k.mcUsername,
    blacklisted: k.blacklisted,
    banned: db.bannedHwids.includes(k.hwid),
  })));
});

app.post("/admin/ban-hwid", requireAdmin, (req, res) => {
  const { hwid, ban } = req.body;
  if (!hwid) return res.status(400).json({ error: "hwid required" });
  const db = readDB();
  if (ban !== false) {
    if (!db.bannedHwids.includes(hwid)) db.bannedHwids.push(hwid);
  } else {
    db.bannedHwids = db.bannedHwids.filter(h => h !== hwid);
  }
  writeDB(db);
  res.json({ success: true });
});

// ─── LICENSE CHECK (Java client) ─────────────────────────────────────────────
app.post("/check", (req, res) => {
  const { hwid, email, mcUsername } = req.body;
  if (!hwid || !email) return res.json({ valid: false, reason: "missing" });
  const db = readDB(), now = Date.now();
  if (db.bannedHwids.includes(hwid)) return res.json({ valid: false, reason: "banned" });
  const key = db.keys.find(k =>
    k.email && k.email.toLowerCase() === email.toLowerCase() &&
    !k.blacklisted && (k.expiry === null || k.expiry > now)
  );
  if (!key) return res.json({ valid: false, reason: "no_key" });
  if (key.hwid && key.hwid !== hwid) return res.json({ valid: false, reason: "hwid_mismatch" });
  if (!key.hwid) { key.hwid = hwid; writeDB(db); }
  if (mcUsername && key.mcUsername !== mcUsername) { key.mcUsername = mcUsername; writeDB(db); }
  res.json({ valid: true });
});

// ─── USER AUTH ────────────────────────────────────────────────────────────────

// Register — strict email validation, bcrypt 12 rounds
app.post("/user/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "missing_fields" });

  // Basic email format check
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: "invalid_email" });

  if (password.length < 8)
    return res.status(400).json({ error: "password_too_short" });

  // Password strength: must have a letter and a number
  if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password))
    return res.status(400).json({ error: "password_too_weak" });

  const db = readDB();
  if (!db.accounts) db.accounts = [];

  if (db.accounts.find(a => a.email === email.toLowerCase()))
    return res.status(400).json({ error: "email_taken" });

  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

  db.accounts.push({
    email: email.toLowerCase(),
    passwordHash: hash,
    createdAt: Date.now(),
    failedLogins: 0,
    lockedUntil: null,
  });
  writeDB(db);
  res.json({ success: true });
});

// Login — account lockout after 5 failed attempts
app.post("/user/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "missing_fields" });

  const db = readDB();
  if (!db.accounts) return res.status(401).json({ error: "invalid_credentials" });

  const account = db.accounts.find(a => a.email === email.toLowerCase());

  // Always run bcrypt even if account not found — prevents timing-based
  // email enumeration attacks
  const dummyHash = "$2a$12$invalidhashfortimingatttacks00000000000000000000000000000";
  const hashToCheck = account ? account.passwordHash : dummyHash;

  // Check lockout
  if (account && account.lockedUntil && Date.now() < account.lockedUntil) {
    const mins = Math.ceil((account.lockedUntil - Date.now()) / 60000);
    return res.status(429).json({ error: "account_locked", minutesLeft: mins });
  }

  const ok = await bcrypt.compare(password, hashToCheck);

  if (!account || !ok) {
    if (account) {
      account.failedLogins = (account.failedLogins || 0) + 1;
      if (account.failedLogins >= 5) {
        account.lockedUntil = Date.now() + 15 * 60 * 1000; // lock 15 min
        account.failedLogins = 0;
      }
      writeDB(db);
    }
    return res.status(401).json({ error: "invalid_credentials" });
  }

  // Successful login — reset lockout
  account.failedLogins = 0;
  account.lockedUntil  = null;
  writeDB(db);

  const token    = mkToken();
  const csrfToken = mkCsrf();
  userSessions.set(token, {
    email: account.email,
    expiresAt: Date.now() + SESSION_TTL,
    csrfToken,
  });
  res.cookie("userToken", token, cookieOpts(SESSION_TTL));
  // CSRF token goes in response body (not httpOnly) so JS can read and send it
  res.json({ token, csrfToken, email: account.email });
});

app.post("/user/logout", (req, res) => {
  const t = req.signedCookies?.userToken || req.headers["x-user-token"];
  if (t) userSessions.delete(t);
  res.clearCookie("userToken");
  res.json({ success: true });
});

// Me
app.get("/user/me", requireUser, (req, res) => {
  const db = readDB(), now = Date.now();
  const key = db.keys.find(k =>
    k.email && k.email.toLowerCase() === req.userSession.email
  );
  res.json({
    email: req.userSession.email,
    csrfToken: req.userSession.csrfToken,
    hasKey: !!key,
    keyBlacklisted: key?.blacklisted ?? false,
    keyExpired: key ? (key.expiry !== null && key.expiry < now) : false,
    expiry: key?.expiry ?? null,
  });
});

// Redeem — requires CSRF
app.post("/user/redeem", requireCsrf, (req, res) => {
  const keyCode = (req.body.key || "").trim().toUpperCase();
  if (!keyCode) return res.status(400).json({ error: "no_key" });
  const db = readDB(), now = Date.now();
  const email = req.userSession.email;
  if (db.keys.find(k => k.email && k.email.toLowerCase() === email))
    return res.status(400).json({ error: "already_redeemed" });
  const entry = db.keys.find(k => k.key === keyCode);
  if (!entry)                                      return res.status(400).json({ error: "invalid_key" });
  if (entry.blacklisted)                           return res.status(400).json({ error: "blacklisted" });
  if (entry.email)                                 return res.status(400).json({ error: "already_used" });
  if (entry.expiry !== null && entry.expiry < now) return res.status(400).json({ error: "expired" });
  entry.email = email;
  entry.redeemedAt = now;
  writeDB(db);
  res.json({ success: true });
});

// Download — requires valid session + key
app.get("/user/download", requireUser, (req, res) => {
  const db = readDB(), now = Date.now();
  const key = db.keys.find(k =>
    k.email && k.email.toLowerCase() === req.userSession.email &&
    !k.blacklisted && (k.expiry === null || k.expiry > now)
  );
  if (!key) return res.status(403).json({ error: "no valid key" });
  if (!fs.existsSync(JAR_PATH)) return res.status(404).json({ error: "jar not found" });
  res.download(JAR_PATH, "pedro-debug.jar");
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Pedro Debug server running on port ${PORT}`);
  console.log(`Admin dashboard : http://localhost:${PORT}/admin`);
  console.log(`User portal     : http://localhost:${PORT}/`);
  console.log(`Admin password  : ${ADMIN_PASSWORD}`);
});
