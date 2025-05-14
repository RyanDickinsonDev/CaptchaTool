const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.CAPTCHA_SECRET;
const CAPTCHA_TTL = 5 * 60 * 1000; // 5 minutes
const usedTokens = new Set();
const path = require("path");

app.use(
  cors({
    origin: "*",
  })
);

app.use(express.json());

app.set('trust proxy', '127.0.0.1'); // For nginx reverse proxy on localhost

// Rate limiting
app.use(
  "/validate",
  rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: { error: "Too many requests, try again later." },
  })
);

app.use(express.static("public"));

function signCaptcha(data) {
  return crypto.createHmac("sha256", SECRET_KEY).update(data).digest("hex");
}

function generateToken() {
  const timestamp = Date.now();
  const payload = `checkbox:${timestamp}`;
  const signature = signCaptcha(payload);

  return Buffer.from(`${payload}:${signature}`).toString("base64");
}

function validateToken(token, answer) {
  try {
    if (usedTokens.has(token)) return false;

    const decoded = Buffer.from(token, "base64").toString("utf8");
    const [type, timestamp, signature] = decoded.split(":");

    if (type !== "checkbox") return false;

    const expectedSig = signCaptcha(`${type}:${timestamp}`);

    if (expectedSig !== signature) return false;
    if (Date.now() - parseInt(timestamp) > CAPTCHA_TTL) return false;

    if (answer !== "checkbox") return false;

    usedTokens.add(token);
    return true;
  } catch (err) {
    console.error("validateToken error:", err);
    return false;
  }
}

// /generate endpoint
app.post("/generate", (req, res) => {
  const token = generateToken();
  res.json({
    captchaId: token,
    question: "Please check the box to verify you're human.",
  });
});

// /validate endpoint
app.post("/validate", (req, res) => {
  const { captchaId, answer, botCheck } = req.body;
  const ip = getClientIp(req);
  console.log(`[${new Date().toISOString()}] Validation Attempt - IP: ${ip}`);


  if (botCheck && botCheck.trim() !== "") {
    console.warn(`Bot detected - IP: ${ip}`);
    return res.status(400).json({ valid: false, error: "Bot detected" });
  }

  const valid = validateToken(captchaId, answer);

  res.json({ valid });
});


app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

app.post("/submit-form", express.json(), (req, res) => {
  const { email, captchaId, validatedCaptcha, botCheck } = req.body;

  if (botCheck && botCheck.trim() !== "") {
    return res.status(400).json({ success: false, error: "Bot detected." });
  }

  if (!captchaId || validatedCaptcha !== captchaId) {
    return res.status(400).json({ success: false, error: "CAPTCHA failed or not completed." });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email)) {
    return res.status(400).json({ success: false, error: "Invalid email address." });
  }

  return res.redirect(302, '/');
});



app.listen(PORT, () => {
  console.log(`Secure CAPTCHA API running at http://localhost:${PORT}`);
});

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const cfConnectingIp = req.headers['cf-connecting-ip'];

  return (
    (cfConnectingIp && cfConnectingIp.split(',')[0].trim()) ||
    (forwarded && forwarded.split(',')[0].trim()) ||
    req.ip
  );
}
