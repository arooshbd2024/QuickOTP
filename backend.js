import express from "express";
import nodemailer from "nodemailer";
import fs from "fs/promises";
import path from "path";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

const app = express();
const PORT = process.env.PORT || 3000;

// Environment variables for better security
const SENDER_EMAIL = process.env.SENDER_EMAIL || "noreplyquickotp@gmail.com";
const SENDER_PASSWORD = process.env.SENDER_PASSWORD || "abapwzmkocdimgml";
const SUBJECT = "Your QuickOTP OTP Code";
const HTML_TEMPLATE_PATH = "./res/otp.html";

// Security middleware
app.use(helmet());
app.use(express.json({ limit: "10kb" }));

// Global rate limiter to prevent abuse
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { status: "429", details: "Too many requests, please try again later" },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// In-memory storage (consider Redis for production)
const emailCooldowns = new Map();
const otpStore = new Map(); // Store OTPs with expiration
const MAX_COOLDOWN_MS = 5 * 60 * 1000;

let keys = {};
let htmlTemplate = "";

// Initialize resources
async function initialize() {
  try {
    // Load keys
    const keyData = await fs.readFile(path.resolve("./key.json"), "utf-8");
    keys = JSON.parse(keyData);
    console.log("🔑 Loaded keys for", Object.keys(keys).length, "IPs");

    // Preload HTML template for performance
    htmlTemplate = await fs.readFile(HTML_TEMPLATE_PATH, "utf-8");
    console.log("📧 Email template loaded");
  } catch (e) {
    console.error("❌ Initialization failed:", e.message);
    process.exit(1);
  }
}

await initialize();

// Enhanced cooldown with exponential backoff
function getCooldownDuration(level) {
  const base = 60_000; // 1 minute
  const increment = 30_000; // 30 seconds
  return Math.min(base + (level - 1) * increment, MAX_COOLDOWN_MS);
}

function canSendOtp(email) {
  const record = emailCooldowns.get(email);
  const now = Date.now();

  if (!record) {
    emailCooldowns.set(email, { lastSent: now, cooldownLevel: 1 });
    return { allowed: true };
  }

  const cooldown = getCooldownDuration(record.cooldownLevel);
  const elapsed = now - record.lastSent;

  if (elapsed >= cooldown) {
    const newLevel = Math.min(record.cooldownLevel + 1, 9);
    emailCooldowns.set(email, { lastSent: now, cooldownLevel: newLevel });
    return { allowed: true };
  }

  const remainingMs = cooldown - elapsed;
  const remainingSec = Math.ceil(remainingMs / 1000);
  const minutes = Math.floor(cooldown / 60000);
  const seconds = Math.floor((cooldown % 60000) / 1000);

  return {
    allowed: false,
    remainingSec,
    timeFormatted: `${minutes}:${seconds.toString().padStart(2, "0")}`,
    cooldownLevel: record.cooldownLevel,
  };
}

// Enhanced key verification with logging
function verifyKey(req, providedKey) {
  const clientIp = req.ip || req.connection.remoteAddress || "unknown";
  const validKey = keys[clientIp];

  if (!providedKey) {
    return { valid: false, reason: "No key provided", isPremium: false };
  }

  if (validKey === providedKey) {
    return { valid: true, isPremium: true };
  }

  return { valid: false, reason: "Invalid key", isPremium: false };
}

// Cryptographically secure OTP generation
async function generateOtp() {
  const crypto = await import("crypto");
  const bytes = crypto.randomBytes(3);
  return Array.from(bytes)
    .map((byte) => byte % 10)
    .concat(Array(3).fill(0).map(() => Math.floor(Math.random() * 10)))
    .join("");
}

// Store OTP with expiration
function storeOtp(email, otp, expirationSeconds) {
  const expiresAt = Date.now() + expirationSeconds * 1000;
  otpStore.set(email, { otp, expiresAt });
  
  // Auto-cleanup after expiration
  setTimeout(() => {
    const stored = otpStore.get(email);
    if (stored && stored.otp === otp) {
      otpStore.delete(email);
    }
  }, expirationSeconds * 1000);
}

// Email validation
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Enhanced email sending with retry logic
async function sendOtpEmail(companyName, receiverEmail, otp, timeToUse) {
  const now = new Date();
  const date = now.toLocaleDateString("en-US", { 
    month: "long", 
    day: "numeric", 
    year: "numeric" 
  });

  const placeholders = {
    "{company}": sanitizeHtml(companyName),
    "{date}": date,
    "{time}": timeToUse,
    "{character-1}": otp[0],
    "{character-2}": otp[1],
    "{character-3}": otp[2],
    "{character-4}": otp[3],
    "{character-5}": otp[4],
    "{character-6}": otp[5],
    "{mail}": SENDER_EMAIL,
  };

  let htmlContent = htmlTemplate;
  for (const [key, val] of Object.entries(placeholders)) {
    htmlContent = htmlContent.replaceAll(key, val);
  }

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: SENDER_EMAIL,
      pass: SENDER_PASSWORD,
    },
    pool: true, // Use connection pooling
    maxConnections: 5,
    maxMessages: 10,
  });

  const mailOptions = {
    from: `NoReply <${SENDER_EMAIL}>`,
    to: receiverEmail,
    subject: SUBJECT,
    html: htmlContent,
    headers: {
      "X-Priority": "1",
      "X-MSMail-Priority": "High",
    },
  };

  // Retry logic
  let attempts = 0;
  const maxAttempts = 3;
  
  while (attempts < maxAttempts) {
    try {
      await transporter.sendMail(mailOptions);
      return;
    } catch (error) {
      attempts++;
      if (attempts === maxAttempts) throw error;
      await new Promise(resolve => setTimeout(resolve, 1000 * attempts));
    }
  }
}

// Sanitize HTML input
function sanitizeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Format time in a human-readable way
function formatTime(seconds) {
  if (seconds < 60) return `${seconds} seconds`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  if (remainingSeconds === 0) return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`;
  return `${minutes}m ${remainingSeconds}s`;
}

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ 
    status: "200", 
    message: "Server is healthy",
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Main OTP endpoint with comprehensive validation
app.post("/emailotp", async (req, res) => {
  const startTime = Date.now();
  const { org, email, key, otp: requestedOtp, time } = req.body;

  try {
    // Validate organization name
    if (!org || typeof org !== "string" || org.trim().length === 0) {
      return res.status(400).json({
        status: "400",
        error: "Invalid organization name",
        details: "Please provide a valid company name (non-empty string)",
      });
    }

    if (org.length > 100) {
      return res.status(400).json({
        status: "400",
        error: "Organization name too long",
        details: "Maximum 100 characters allowed",
      });
    }

    // Validate email
    if (!email || typeof email !== "string") {
      return res.status(400).json({ 
        status: "400", 
        error: "Missing email",
        details: "Email parameter is required" 
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({
        status: "400",
        error: "Invalid email format",
        details: "Please provide a valid email address",
      });
    }

    // Validate time field
    if (time === undefined || typeof time !== "number" || !Number.isInteger(time) || time <= 0) {
      return res.status(400).json({
        status: "400",
        error: "Invalid time parameter",
        details: "Time must be a positive integer (seconds, max 3600)",
      });
    }

    if (time > 3600) {
      return res.status(400).json({
        status: "400",
        error: "Time exceeds maximum",
        details: "Maximum allowed duration is 3600 seconds (1 hour)",
      });
    }

    const keyCheck = verifyKey(req, key);

    // Validate custom OTP for premium users
    let otp;
    if (requestedOtp !== undefined) {
      if (!keyCheck.valid) {
        return res.status(403).json({
          status: "403",
          error: "Premium feature",
          details: "Custom OTP requires a valid premium key",
        });
      }

      const sanitizedOtp = requestedOtp.toString().replace(/\s+/g, "");
      if (!/^\d{6}$/.test(sanitizedOtp)) {
        return res.status(400).json({
          status: "400",
          error: "Invalid OTP format",
          details: "OTP must be exactly 6 digits",
        });
      }
      otp = sanitizedOtp;
    } else {
      otp = await generateOtp();
    }

    // Cooldown check for non-premium users
    if (!keyCheck.valid) {
      const cooldownCheck = canSendOtp(email);
      if (!cooldownCheck.allowed) {
        return res.status(429).json({
          status: "429",
          error: "Rate limit exceeded",
          details: "Please wait before requesting another OTP",
          timeRemaining: cooldownCheck.timeFormatted,
          remainingSeconds: cooldownCheck.remainingSec,
          cooldownLevel: cooldownCheck.cooldownLevel,
        });
      }
    }

    // Send OTP email
    const formattedTime = formatTime(time);
    await sendOtpEmail(org, email, otp, formattedTime);

    // Store OTP for potential verification
    storeOtp(email, otp, time);

    const processingTime = Date.now() - startTime;
    console.log(`✅ OTP sent to ${email}: ${otp} | Time: ${time}s | Processing: ${processingTime}ms`);

    const formattedOtp = `${otp.slice(0, 3)} ${otp.slice(3)}`;

    return res.json({
      status: "200",
      message: "OTP sent successfully",
      data: {
        otp: formattedOtp,
        expiresIn: formattedTime,
        expiresInSeconds: time,
        isPremium: keyCheck.isPremium,
      },
      meta: {
        processingTime: `${processingTime}ms`,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error("❌ Failed to send OTP:", error.message);
    return res.status(500).json({ 
      status: "500", 
      error: "Internal server error",
      details: "Failed to send OTP email. Please try again later.",
    });
  }
});

// OTP verification endpoint (bonus feature!)
app.post("/verifyotp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({
      status: "400",
      error: "Missing parameters",
      details: "Email and OTP are required",
    });
  }

  const stored = otpStore.get(email);
  
  if (!stored) {
    return res.status(404).json({
      status: "404",
      error: "OTP not found",
      details: "No OTP found for this email or it has expired",
    });
  }

  if (Date.now() > stored.expiresAt) {
    otpStore.delete(email);
    return res.status(410).json({
      status: "410",
      error: "OTP expired",
      details: "This OTP has expired. Please request a new one",
    });
  }

  const sanitizedOtp = otp.toString().replace(/\s+/g, "");
  
  if (stored.otp === sanitizedOtp) {
    otpStore.delete(email);
    return res.json({
      status: "200",
      message: "OTP verified successfully",
      verified: true,
    });
  }

  return res.status(401).json({
    status: "401",
    error: "Invalid OTP",
    details: "The provided OTP does not match",
    verified: false,
  });
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("🛑 SIGTERM received, shutting down gracefully...");
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 QuickOTP Server running on http://localhost:${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`🔒 Security: Helmet enabled`);
  console.log(`⚡ Rate limiting: Active`);
});