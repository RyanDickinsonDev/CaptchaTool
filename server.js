// const express = require("express");
// const cors = require("cors");
// const crypto = require("crypto");
// const rateLimit = require("express-rate-limit");
// const fs = require("fs");
// const path = require("path");
// const RedisStore = require("rate-limit-redis").default;
// const redis = require("redis").createClient();
// require("dotenv").config();

// const app = express();
// const PORT = process.env.PORT || 3000;
// const SECRET_KEY = Buffer.from(process.env.CAPTCHA_SECRET, "hex"); // 32 bytes hex
// const CAPTCHA_TTL = 5 * 60 * 1000; // 5 minutes
// // const usedTokens = new Set();
// const BOT_TRACK_FILE = path.join(__dirname, "botCount.json");

// const LOG_DIR = path.join(__dirname, "site-logs");

// // Create site-logs directory if it doesn't exist
// if (!fs.existsSync(LOG_DIR)) {
//   fs.mkdirSync(LOG_DIR);
// }

// const dashboardRoutes = require("./dashboard");


// let stats = { bots: 0, successfulValidations: 0 };
// function loadStats() {
//   try {
//     const data = fs.readFileSync(BOT_TRACK_FILE, "utf8");
//     const parsed = JSON.parse(data);
//     stats.bots = parsed.bots || 0;
//     stats.successfulValidations = parsed.successfulValidations || 0;
//     console.log("Stats loaded:", stats);
//   } catch {
//     console.warn("No botCount.json found, starting fresh.");
//   }
// }
// function saveStats() {
//   try {
//     fs.writeFileSync(BOT_TRACK_FILE, JSON.stringify(stats, null, 2));
//   } catch (err) {
//     console.error("Failed to save stats:", err);
//   }
// }
// loadStats();


// // Redis-based global rate limiter
// redis.connect().catch(console.error);
// const globalLimiter = rateLimit({
//   store: new RedisStore({
//     sendCommand: (...args) => redis.sendCommand(args),
//   }),
//   windowMs: 60 * 1000,
//   max: 100,
//   message: { error: "Too many requests. Please slow down." },
// });
// app.use(globalLimiter);

// // Referrer/host check (localhost + NGINX-safe)
// app.use((req, res, next) => {
//   const referer = req.get("Referer") || "";
//   const host = req.get("Host") || "";
//   const allowedDomains = [
//     "localhost",
//     "127.0.0.1",
//     "captchatool.com"
//   ];
//   if (!allowedDomains.some(domain => referer.includes(domain) || host.includes(domain))) {
//     console.warn("Blocked request - invalid referer/host:", referer, host);
//     return res.status(403).json({ error: "Access denied" });
//   }
//   next();
// });

// app.use(cors({
//   origin: (origin, callback) => callback(null, origin),
//   credentials: true
// }));

// app.use(express.json());
// app.set("trust proxy", 1); // NGINX trust

// app.use(express.static("public"));


// //  1. Protect the /admin route FIRST
// // app.use("/admin", basicAuth({
// //   users: { [process.env.ADMIN_USER]: process.env.ADMIN_PASS },
// //   unauthorizedResponse: "Not authorized"
// // }));

// //  2. THEN serve static files and dashboard routes
// app.use("/admin", express.static(path.join(__dirname, "admin")));
// app.use(dashboardRoutes);



// const ipRequestTimestamps = new Map(); // key: IP, value: last timestamp

// function encrypt(text) {
//   const iv = crypto.randomBytes(16);
//   const cipher = crypto.createCipheriv("aes-256-cbc", SECRET_KEY, iv);
//   let encrypted = cipher.update(text);
//   encrypted = Buffer.concat([encrypted, cipher.final()]);
//   return iv.toString("hex") + ":" + encrypted.toString("hex");
// }

// function decrypt(encrypted) {
//   const [ivHex, encryptedHex] = encrypted.split(":");
//   const iv = Buffer.from(ivHex, "hex");
//   const encryptedText = Buffer.from(encryptedHex, "hex");
//   const decipher = crypto.createDecipheriv("aes-256-cbc", SECRET_KEY, iv);
//   let decrypted = decipher.update(encryptedText);
//   decrypted = Buffer.concat([decrypted, decipher.final()]);
//   return decrypted.toString();
// }

// function generateToken() {
//   const timestamp = Date.now();
//   const payload = `checkbox:${timestamp}`;
//   return encrypt(payload);
// }

// async function validateToken(token, answer) {
//   try {
//     // Check if token was already used
//     const tokenUsed = await redis.get(`used:${token}`);
//     if (tokenUsed) return false;

//     const decrypted = decrypt(token);
//     const [type, timestamp] = decrypted.split(":");

//     if (type !== "checkbox") return false;
//     if (Date.now() - parseInt(timestamp) > CAPTCHA_TTL) return false;
//     if (answer !== "checkbox") return false;

//     // Mark token as used in Redis with expiration
//     await redis.set(`used:${token}`, "1", {
//       EX: CAPTCHA_TTL / 1000, // TTL in seconds
//     });

//     return true;
//   } catch (err) {
//     console.error("validateToken error:", err);
//     return false;
//   }
// }


// app.post("/generate", (req, res) => {
//   const token = generateToken();
//   res.json({
//     captchaId: token,
//     question: "Please check the box to verify you're human.",
//   });
// });

// function delay(ms) {
//   return new Promise(resolve => setTimeout(resolve, ms));
// }

// app.post("/validate", async (req, res) => {
//   await delay(Math.floor(300 + Math.random() * 700));

//   const { captchaId, answer, botCheck } = req.body;
//   const ip = getClientIp(req);
//   const now = Date.now();
//   const referer = req.get("Referer") || "unknown";

//   console.log(`[${new Date().toISOString()}] Validation Attempt - IP: ${ip} - Referrer: ${referer}`);

//   if (botCheck && botCheck.trim() !== "") {
//     stats.bots++;
//     saveStats();
//     console.warn(`Bot detected via honeypot - IP: ${ip}`);
//     return res.status(400).json({ valid: false, error: "Bot detected via honeypot." });
//   }

//   const lastRequestTime = ipRequestTimestamps.get(ip);
//   ipRequestTimestamps.set(ip, now);

//   const MIN_INTERVAL = 4000;
//   if (lastRequestTime && now - lastRequestTime < MIN_INTERVAL) {
//     stats.bots++;
//     saveStats();
//     console.warn(`Spammy CAPTCHA attempt - IP: ${ip} - Interval: ${now - lastRequestTime}ms`);
//     return res.status(429).json({
//       valid: false,
//       error: "Too many CAPTCHA attempts too quickly. Please wait.",
//     });
//   }

//   const valid = await validateToken(captchaId, answer);
//   if (valid) {
//     stats.successfulValidations++;
//     saveStats();

//     // Log which site had a successful validation
//     const refDomain = (new URL(referer).hostname).replace(/^www\./, '');
//     const domainLogPath = path.join(LOG_DIR, `${refDomain}.log`);
//     fs.appendFileSync(domainLogPath, `${new Date().toISOString()} - IP: ${ip} - Valid\n`);
    


//     // console.log(`✅ CAPTCHA passed for IP: ${ip} from ${refDomain}`);
//   }

//   res.json({ valid });
// });


// app.post("/submit-form", express.json(), (req, res) => {
//   const { email, captchaId, validatedCaptcha, botCheck } = req.body;

//   if (botCheck && botCheck.trim() !== "") {
//     stats.bots++;
//     saveStats();
//     return res.status(400).json({ success: false, error: "Bot detected." });
//   }

//   if (!captchaId || validatedCaptcha !== captchaId) {
//     return res.status(400).json({ success: false, error: "CAPTCHA failed or not completed." });
//   }

//   const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//   if (!email || !emailRegex.test(email)) {
//     return res.status(400).json({ success: false, error: "Invalid email address." });
//   }

//   return res.redirect(302, "/");
// });

// app.get("/stats", (req, res) => {
//   res.json(stats);
// });

// app.get("/", (req, res) => {
//   res.sendFile(path.join(__dirname, "public/index.html"));
// });

// function getClientIp(req) {
//   const forwarded = req.headers["x-forwarded-for"];
//   const cfConnectingIp = req.headers["cf-connecting-ip"];
//   const rawIp =
//     cfConnectingIp?.split(",")[0].trim() ||
//     forwarded?.split(",")[0].trim() ||
//     req.ip;

//   // Normalize IPv6-mapped IPv4 addresses like ::ffff:127.0.0.1
//   return rawIp.replace(/^::ffff:/, "");
// }


// app.listen(PORT, () => {
//   console.log(`Secure CAPTCHA API running at http://localhost:${PORT}`);
// });




// server.js (merged with Passport.js auth)
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const cors = require("cors");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");
const RedisStore = require("rate-limit-redis").default;
const redis = require("redis").createClient();
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = Buffer.from(process.env.CAPTCHA_SECRET, "hex");
const CAPTCHA_TTL = 5 * 60 * 1000;
const BOT_TRACK_FILE = path.join(__dirname, "botCount.json");
const LOG_DIR = path.join(__dirname, "site-logs");
const dashboardRoutes = require("./dashboard");

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "password";

// Create site-logs directory if it doesn't exist
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR);
}

// Session + Passport setup
app.use(session({
  secret: process.env.SESSION_SECRET || "keyboard cat",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 3600000 }
}));
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy((username, password, done) => {
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    return done(null, { username });
  } else {
    return done(null, false, { message: "Invalid credentials" });
  }
}));
passport.serializeUser((user, done) => done(null, user.username));
passport.deserializeUser((username, done) => done(null, { username }));

function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/admin/login");
}

let stats = { bots: 0, successfulValidations: 0 };
function loadStats() {
  try {
    const data = fs.readFileSync(BOT_TRACK_FILE, "utf8");
    const parsed = JSON.parse(data);
    stats.bots = parsed.bots || 0;
    stats.successfulValidations = parsed.successfulValidations || 0;
    console.log("Stats loaded:", stats);
  } catch {
    console.warn("No botCount.json found, starting fresh.");
  }
}
function saveStats() {
  try {
    fs.writeFileSync(BOT_TRACK_FILE, JSON.stringify(stats, null, 2));
  } catch (err) {
    console.error("Failed to save stats:", err);
  }
}
loadStats();

redis.connect().catch(console.error);
const globalLimiter = rateLimit({
  store: new RedisStore({ sendCommand: (...args) => redis.sendCommand(args) }),
  windowMs: 60 * 1000,
  max: 100,
  message: { error: "Too many requests. Please slow down." },
});
app.use(globalLimiter);

app.use((req, res, next) => {
  const referer = req.get("Referer") || "";
  const host = req.get("Host") || "";
  const allowedDomains = ["localhost", "127.0.0.1", "captchatool.com"];
  if (!allowedDomains.some(domain => referer.includes(domain) || host.includes(domain))) {
    console.warn("Blocked request - invalid referer/host:", referer, host);
    return res.status(403).json({ error: "Access denied" });
  }
  next();
});

app.use(cors({ origin: (origin, callback) => callback(null, origin), credentials: true }));
app.use(express.json());
app.set("trust proxy", 1);

// Auth routes
app.get("/admin/login", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Admin Login</title>
      <style>
        body { font-family: sans-serif; background: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; }
        form { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        input { display: block; width: 100%; margin-bottom: 1rem; padding: 0.5rem; font-size: 1rem; }
        button { padding: 0.5rem 1rem; font-size: 1rem; background: #2563eb; color: white; border: none; border-radius: 4px; cursor: pointer; }
      </style>
    </head>
    <body>
      <form method="POST" action="/admin/login">
        <h2 style="margin-top: 0;">Admin Login</h2>
        <input name="username" placeholder="Username" required>
        <input name="password" type="password" placeholder="Password" required>
        <button type="submit">Login</button>
      </form>
    </body>
    </html>
  `);
});

app.post("/admin/login",
  passport.authenticate("local", {
    successRedirect: "/admin",
    failureRedirect: "/admin/login"
  })
);

app.get("/admin/logout", (req, res) => {
  req.logout(() => res.redirect("/admin/login"));
});

app.use("/admin", requireAuth, express.static(path.join(__dirname, "admin")));
app.use("/admin", requireAuth, dashboardRoutes);

const ipRequestTimestamps = new Map();

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", SECRET_KEY, iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

function decrypt(encrypted) {
  const [ivHex, encryptedHex] = encrypted.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const encryptedText = Buffer.from(encryptedHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", SECRET_KEY, iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

function generateToken() {
  const timestamp = Date.now();
  const payload = `checkbox:${timestamp}`;
  return encrypt(payload);
}

async function validateToken(token, answer) {
  try {
    const tokenUsed = await redis.get(`used:${token}`);
    if (tokenUsed) return false;

    const decrypted = decrypt(token);
    const [type, timestamp] = decrypted.split(":");

    if (type !== "checkbox") return false;
    if (Date.now() - parseInt(timestamp) > CAPTCHA_TTL) return false;
    if (answer !== "checkbox") return false;

    await redis.set(`used:${token}`, "1", { EX: CAPTCHA_TTL / 1000 });
    return true;
  } catch (err) {
    console.error("validateToken error:", err);
    return false;
  }
}

app.post("/generate", (req, res) => {
  const token = generateToken();
  res.json({ captchaId: token, question: "Please check the box to verify you're human." });
});

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

app.post("/validate", async (req, res) => {
  await delay(Math.floor(300 + Math.random() * 700));

  const { captchaId, answer, botCheck } = req.body;
  const ip = getClientIp(req);
  const now = Date.now();
  const referer = req.get("Referer") || "unknown";

  if (botCheck && botCheck.trim() !== "") {
    stats.bots++;
    saveStats();
    return res.status(400).json({ valid: false, error: "Bot detected via honeypot." });
  }

  const lastRequestTime = ipRequestTimestamps.get(ip);
  ipRequestTimestamps.set(ip, now);
  const MIN_INTERVAL = 4000;
  if (lastRequestTime && now - lastRequestTime < MIN_INTERVAL) {
    stats.bots++;
    saveStats();
    return res.status(429).json({ valid: false, error: "Too many CAPTCHA attempts too quickly. Please wait." });
  }

  const valid = await validateToken(captchaId, answer);
  if (valid) {
    stats.successfulValidations++;
    saveStats();
    const refDomain = (new URL(referer).hostname).replace(/^www\./, '');
    const domainLogPath = path.join(LOG_DIR, `${refDomain}.log`);
    fs.appendFileSync(domainLogPath, `${new Date().toISOString()} - IP: ${ip} - Valid\n`);
  }

  res.json({ valid });
});

app.post("/submit-form", express.json(), (req, res) => {
  const { email, captchaId, validatedCaptcha, botCheck } = req.body;
  if (botCheck && botCheck.trim() !== "") {
    stats.bots++;
    saveStats();
    return res.status(400).json({ success: false, error: "Bot detected." });
  }
  if (!captchaId || validatedCaptcha !== captchaId) {
    return res.status(400).json({ success: false, error: "CAPTCHA failed or not completed." });
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email)) {
    return res.status(400).json({ success: false, error: "Invalid email address." });
  }
  return res.redirect(302, "/");
});

app.get("/stats", (req, res) => {
  res.json(stats);
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// Serve public widget and form
app.use(express.static(path.join(__dirname, "public")));


function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  const cfConnectingIp = req.headers["cf-connecting-ip"];
  const rawIp = cfConnectingIp?.split(",")[0].trim() || forwarded?.split(",")[0].trim() || req.ip;
  return rawIp.replace(/^::ffff:/, "");
}

app.listen(PORT, () => {
  console.log(`Secure CAPTCHA + Admin Dashboard running at http://localhost:${PORT}`);
});
