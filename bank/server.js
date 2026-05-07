const express = require("express");
const session = require("express-session");
const path = require("path");
const crypto = require("crypto");
const { state: db, resetDB } = require("./data/db");

const app = express();
const PORT = 3000;

const BANK_ORIGIN = "http://localhost:3000";
const ATTACKER_ORIGINS = [
  "http://localhost:4000",
  "http://127.0.0.1:4000"
];

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "csrf-demo-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      sameSite: false
    }
  })
);

app.use(syncDynamicCookieAttributes);
app.use(applyHighLevelSecurityHeaders);

function getCookieValue(cookieHeader, name) {
  if (!cookieHeader) return "";

  const match = cookieHeader.match(
    new RegExp("(?:^|;\\s*)" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=([^;]+)")
  );

  return match ? decodeURIComponent(match[1]) : "";
}

function shortValue(value, left = 8, right = 6) {
  if (!value) return "MISSING";
  if (value.length <= left + right + 3) return value;
  return `${value.slice(0, left)}...${value.slice(-right)}`;
}

function getRequestType(req) {
  if (req.path === "/transfer") return "TRANSFER";
  if (req.path === "/seed-xss-open") return "STORED XSS SEED";
  if (req.path === "/partner-dom-lab") return "DOM LAB";
  if (req.path === "/dom-attack-neutralized") return "DOM NEUTRALIZED";
  if (req.path === "/reward-attack-reconcile") return "RECONCILE";
  if (req.path.startsWith("/set-")) return "CONFIG";
  if (req.path === "/dashboard") return "DASHBOARD";
  if (req.path === "/login") return "LOGIN";
  return "REQUEST";
}

app.use((req, res, next) => {
  const cookieHeader = req.headers.cookie || "";
  const sessionCookie = getCookieValue(cookieHeader, "connect.sid");
  const xsrfCookie = getCookieValue(cookieHeader, "XSRF-TOKEN");

  const origin = req.headers.origin || "none";
  const referer = req.headers.referer || "none";
  const requestType = getRequestType(req);

  const isImportant =
    req.path === "/transfer" ||
    req.path === "/QUANAP" ||
    req.path === "/seed-xss-open" ||
    req.path === "/partner-dom-lab" ||
    req.path === "/dom-attack-neutralized" ||
    req.path === "/reward-attack-reconcile";
    req.path.startsWith("/set-");

  if (isImportant) {
    console.log("");
    console.log("┌─ BANK REQUEST ─────────────────────────────────────");
    console.log(`│ Type    : ${requestType}`);
    console.log(`│ Time    : ${new Date().toISOString()}`);
    console.log(`│ Method  : ${req.method}`);
    console.log(`│ Path    : ${req.path}`);
    console.log(`│ Origin  : ${origin}`);
    console.log(`│ Referer : ${referer}`);
    console.log(`│ Session : ${sessionCookie ? "YES" : "NO"}`);
    console.log(`│ XSRF    : ${shortValue(xsrfCookie)}`);
    console.log("└───────────────────────────────────────────────────");
  }

  next();
});

function applyHighLevelSecurityHeaders(req, res, next) {
  res.locals.cspNonce = crypto.randomBytes(16).toString("base64");

  if (req.session && req.session.securityLevel === "high") {
    const nonce = res.locals.cspNonce;

    const csp = [
      "default-src 'self'",
      `script-src 'nonce-${nonce}'`,
      "script-src-attr 'none'",
      "object-src 'none'",
      "base-uri 'self'",
      "connect-src 'self'",
      "img-src 'self' data:",
      "style-src 'self' 'unsafe-inline'",
      "frame-ancestors 'self'",
      "require-trusted-types-for 'script'",
      "trusted-types bankPolicy"
    ].join("; ");

    res.setHeader("Content-Security-Policy", csp);
  }

  next();
}

function syncDynamicCookieAttributes(req, res, next) {
  if (req.session && req.session.cookie) {
    const mode = req.session.sameSiteMode || "unset";

    if (mode === "lax") {
      req.session.cookie.sameSite = "lax";
      req.session.cookie.secure = false;
    } else if (mode === "strict") {
      req.session.cookie.sameSite = "strict";
      req.session.cookie.secure = false;
    } else if (mode === "none") {
      req.session.cookie.sameSite = "none";
      req.session.cookie.secure = true;
    } else {
      req.session.cookie.sameSite = false;
      req.session.cookie.secure = false;
    }
  }

  next();
}

function getEffectiveAttackerOrigin(req) {
  const mode = req.session?.sameSiteMode || "unset";

  if (mode === "unset" || mode === "none") {
    return "http://localhost:4000";
  }

  return "http://127.0.0.1:4000";
}

function requireLogin(req, res, next) {
  if (!req.session.username) {
    return res.redirect("/");
  }
  next();
}

function ensureSecurityDefaults(req) {
  if (!req.session.username) return;

  if (!req.session.securityLevel) {
    req.session.securityLevel = "low";
  }

  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomUUID();
  }

  if (!req.session.sameSiteMode) {
    req.session.sameSiteMode = "unset";
  }

  if (!req.session.csrfLabMode) {
    req.session.csrfLabMode = "off";
  }

  if (!req.session.xsrfToken) {
    req.session.xsrfToken = crypto.randomUUID();
  }
}

function ensureAttackMonitor() {
  if (!Array.isArray(db.attackMonitor)) {
    db.attackMonitor = [];
  }
  return db.attackMonitor;
}

function getAttackMonitor(attackId) {
  return ensureAttackMonitor().find((item) => item.attackId === attackId);
}

function createAttackMonitor(attackId, attackType = "stored-xss") {
  const list = ensureAttackMonitor();

  const record = {
    attackId,
    attackType,
    status: "planted",
    message:
      attackType === "dom-xss"
        ? "DOM XSS link armed. Waiting for victim to open the malicious bank URL."
        : "Payload planted. Waiting for victim refresh.",
    createdAt: Date.now(),
    updatedAt: Date.now(),
    from: null,
    to: "mallory",
    amount: 200
  };

  list.push(record);
  return record;
}

function updateAttackMonitor(attackId, status, patch = {}) {
  const record = getAttackMonitor(attackId);
  if (!record) return null;

  record.status = status;
  record.updatedAt = Date.now();
  Object.assign(record, patch);

  return record;
}

function setCorsForAttacker(req, res) {
  const origin = req.headers.origin || "";
  if (ATTACKER_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Vary", "Origin");
}

function isTrustedSource(req) {
  const origin = req.headers.origin || "";
  const referer = req.headers.referer || "";

  return origin === BANK_ORIGIN || referer.startsWith(BANK_ORIGIN);
}

function detectAttackVector(req) {
  if (req.body.attackVector === "stored-xss-csrf") {
    return "Stored XSS + CSRF";
  }

  if (req.body.attackVector === "dom-postmessage-xss-csrf") {
    return "DOM XSS + CSRF";
  }

  const origin = req.headers.origin || "";
  const referer = req.headers.referer || "";

  if (
    req.body.attackVector === "external-csrf" ||
    ATTACKER_ORIGINS.some((attackerOrigin) =>
      origin.startsWith(attackerOrigin) || referer.startsWith(attackerOrigin)
    )
  ) {
    return "External CSRF";
  }

  return "Legitimate Form";
}
function isPayloadLike(content = "") {
  return (
    content.includes("<script") ||
    content.includes("fetch(") ||
    content.includes("attackVector") ||
    content.includes("stored_xss_payload_") ||
    content.includes("attackId")
  );
}

function buildRiskMeta(status, attackVector, level) {
  if (attackVector === "External CSRF" && status === "SUCCESS") {
    return { riskFlag: "CRITICAL", riskScore: 95 };
  }

  if (attackVector === "External CSRF" && status === "BLOCKED") {
    return { riskFlag: "HIGH", riskScore: 78 };
  }

  if (attackVector === "Stored XSS + CSRF" && status === "SUCCESS") {
    return { riskFlag: "CRITICAL", riskScore: 100 };
  }

  if (attackVector === "Stored XSS + CSRF" && status === "BLOCKED") {
    return { riskFlag: "HIGH", riskScore: 86 };
  }

  if (attackVector === "DOM XSS + CSRF" && status === "SUCCESS") {
    return { riskFlag: "CRITICAL", riskScore: 100 };
  }

  if (attackVector === "DOM XSS + CSRF" && status === "BLOCKED") {
    return { riskFlag: "HIGH", riskScore: 88 };
  }

  if (status === "FAILED") {
    return { riskFlag: "MEDIUM", riskScore: 35 };
  }

  if (level === "high") {
    return { riskFlag: "LOW", riskScore: 8 };
  }

  if (level === "medium") {
    return { riskFlag: "LOW", riskScore: 12 };
  }

  return { riskFlag: "LOW", riskScore: 18 };
}

function logEvent({
  req,
  from,
  to,
  amount,
  status,
  level,
  reason = "",
  attackVector,
  attemptId = null
}) {
  const meta = buildRiskMeta(status, attackVector, level);

  db.events.push({
    id: db.events.length + 1,
    time: new Date().toLocaleString(),
    timeMs: Date.now(),
    from,
    to,
    amount,
    status,
    level: level.toUpperCase(),
    reason,
    attackVector,
    riskFlag: meta.riskFlag,
    riskScore: meta.riskScore,
    origin: req?.headers?.origin || "none",
    referer: req?.headers?.referer || "none",
    attemptId
  });
}

function validateTransfer(from, to, amount) {
  if (!db.users[to]) {
    return "Recipient does not exist.";
  }

  if (!Number.isFinite(amount) || amount <= 0) {
    return "Invalid amount.";
  }

  if (db.users[from].balance < amount) {
    return "Insufficient balance.";
  }

  return null;
}

function validateDoubleSubmitCookie(req) {
  const cookieHeader = req.headers.cookie || "";
  const xsrfCookieMatch = cookieHeader.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/);
  const xsrfCookie = xsrfCookieMatch ? decodeURIComponent(xsrfCookieMatch[1]) : "";
  const xsrfBody = req.body.xsrfToken || "";
  const xsrfSession = req.session?.xsrfToken || "";

  console.log("");
  console.log("┌─ DOUBLE-SUBMIT CHECK ──────────────────────────────");
  console.log(`│ Cookie XSRF-TOKEN : ${shortValue(xsrfCookie)}`);
  console.log(`│ Body xsrfToken    : ${shortValue(xsrfBody)}`);
  console.log(`│ Session xsrfToken : ${shortValue(xsrfSession)}`);
  console.log(`│ Cookie == Body    : ${xsrfCookie && xsrfBody ? xsrfCookie === xsrfBody : false}`);
  console.log(`│ Body == Session   : ${xsrfBody && xsrfSession ? xsrfBody === xsrfSession : false}`);
  console.log("└───────────────────────────────────────────────────");

  if (!xsrfCookie || !xsrfBody || !xsrfSession) {
    return false;
  }

  return xsrfCookie === xsrfBody && xsrfBody === xsrfSession;
}

function issueXsrfCookie(res, req) {
  if (!req.session?.xsrfToken) return;

  const mode = req.session.sameSiteMode || "unset";

  const cookieOptions = {
    httpOnly: false,
    secure: mode === "none",
    path: "/"
  };

  if (mode === "lax") {
    cookieOptions.sameSite = "lax";
  } else if (mode === "strict") {
    cookieOptions.sameSite = "strict";
  } else if (mode === "none") {
    cookieOptions.sameSite = "none";
  }

  res.cookie("XSRF-TOKEN", req.session.xsrfToken, cookieOptions);
}

function buildStoredXssPayload(attackId) {
  return `
<div class="notice-bank-card">
  <div class="notice-bank-kicker">Rewards Center</div>
  <strong>Cashback reward verification in progress</strong>
  <p>Your cashback eligibility is currently being verified and synced to your SecureBank account.</p>
</div>
<script>
(function () {
  const attackId = "${attackId}";
  const markerKey = "stored_xss_payload_" + attackId;

  if (localStorage.getItem(markerKey) === "done") return;
  localStorage.setItem(markerKey, "done");

  setTimeout(function () {
    const csrfToken =
      document.getElementById("globalCsrfToken")?.value ||
      document.querySelector('input[name="csrfToken"]')?.value ||
      "";

    const xsrfToken =
      document.getElementById("globalXsrfToken")?.value ||
      document.querySelector('input[name="xsrfToken"]')?.value ||
      "";

    const body = new URLSearchParams({
      to: "mallory",
      amount: "200",
      csrfToken: csrfToken,
      xsrfToken: xsrfToken,
      attackVector: "stored-xss-csrf",
      attackId: attackId
    });

    fetch("/transfer", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      credentials: "include",
      body: body.toString()
    }).then(function () {
      window.location.reload();
    }).catch(function (err) {
      console.error("Stored XSS demo request failed:", err);
    });
  }, 1000);
})();
</script>
`;
}

function markPendingStoredXssAsNeutralized(req, securityLevel) {
  if (securityLevel !== "high") return;

  const username = req.session?.username || "unknown";
  const list = ensureAttackMonitor();

  for (const item of list) {
    if (item.attackType === "stored-xss" && item.status === "planted") {
      item.status = "neutralized";
      item.updatedAt = Date.now();
      item.message =
        "Victim refreshed the dashboard in High mode. Payload was neutralized before execution.";

      logEvent({
        req,
        from: username,
        to: item.to || "mallory",
        amount: Number.isFinite(item.amount) ? item.amount : 200,
        status: "BLOCKED",
        level: "high",
        reason:
          "High mode neutralized the Stored XSS payload before execution, so no forged transfer request was allowed.",
        attackVector: "Stored XSS + CSRF",
        attemptId: item.attackId || null
      });
    }
  }
}

function buildDashboardData(req) {
  const username = req.session.username;
  const securityLevel = req.session.securityLevel || "low";
  const sameSiteMode = req.session.sameSiteMode || "unset";
  const csrfLabMode = req.session.csrfLabMode || "off";

  markPendingStoredXssAsNeutralized(req, securityLevel);

  const accountList = Object.keys(db.users).map((name) => ({
    username: name,
    balance: db.users[name].balance
  }));

  const blockedEvents = db.events.filter((e) => e.status === "BLOCKED").length;
  const criticalEvents = db.events.filter((e) => e.riskFlag === "CRITICAL").length;
  const maliciousNotificationCount = db.comments.filter((c) =>
    isPayloadLike(c.content)
  ).length;

  let latestInsight = "No security events yet.";
  if (db.events.length > 0) {
    const latest = db.events[db.events.length - 1];
    latestInsight = `${latest.attackVector} | ${latest.status} | Risk ${latest.riskScore}/100`;
  }

  let labNotice = "";
  if (sameSiteMode === "none") {
    labNotice =
      "SameSite=None requires Secure and usually HTTPS. In local HTTP demo mode, some browsers may reject this cookie.";
  } else if (sameSiteMode === "strict") {
    labNotice =
      "SameSite=Strict only sends cookies in same-site requests, so cross-site CSRF is strongly reduced.";
  } else if (sameSiteMode === "lax") {
    labNotice =
      "SameSite=Lax restricts cookies in many cross-site cases, especially attacker-driven POST flows.";
  }

  if (csrfLabMode === "double-submit") {
    labNotice = labNotice
      ? `${labNotice} Double-submit cookie mode is active.`
      : "Double-submit cookie mode is active.";
  }

  let sameSiteInfo = {
    cookieAttribute: "SameSite=Unset",
    summary: "Lab mode keeps the cookie permissive to approximate legacy behavior.",
    demoHint: "External CSRF is more likely to succeed in Low mode."
  };

  if (sameSiteMode === "lax") {
    sameSiteInfo = {
      cookieAttribute: "SameSite=Lax",
      summary: "Cookies are restricted in many cross-site cases, especially POST-based attack flows.",
      demoHint: "External CSRF will often fail or lose the authenticated session."
    };
  } else if (sameSiteMode === "strict") {
    sameSiteInfo = {
      cookieAttribute: "SameSite=Strict",
      summary: "Cookies are only sent in same-site requests.",
      demoHint: "External CSRF is strongly blocked by browser cookie policy."
    };
  } else if (sameSiteMode === "none") {
    sameSiteInfo = {
      cookieAttribute: "SameSite=None; Secure",
      summary: "Cross-site cookie sending is allowed, but modern browsers usually require HTTPS.",
      demoHint: "Useful for explanation, but local HTTP browsers may reject it."
    };
  }

  const cookieState = {
    rawHeaderPresent: Boolean(req.headers.cookie),
    rawHeader: req.headers.cookie || ""
  };

  return {
    username,
    csrfToken: req.session.csrfToken,
    xsrfToken: req.session.xsrfToken,
    securityLevel,
    sameSiteMode,
    csrfLabMode,
    labNotice,
    sameSiteInfo,
    cookieState,
    cspNonce: req.res.locals.cspNonce,
    myBalance: db.users[username].balance,
    users: Object.keys(db.users).filter((u) => u !== username),
    allAccounts: accountList,
    comments: [...db.comments].reverse(),
    events: [...db.events].reverse(),
    sessionMonitor: {
      sessionUser: username,
      sessionActive: Boolean(req.session.username),
      cookiePresent: Boolean(req.headers.cookie),
      cookieHeaderPreview: req.headers.cookie
        ? req.headers.cookie.slice(0, 90) + (req.headers.cookie.length > 90 ? "..." : "")
        : "No cookie header",
      csrfTokenPreview: req.session.csrfToken
        ? req.session.csrfToken.slice(0, 12) + "..."
        : "N/A",
      xsrfTokenPreview: req.session.xsrfToken
        ? req.session.xsrfToken.slice(0, 12) + "..."
        : "N/A"
    },
    metrics: {
      totalRequests: db.events.length,
      blockedEvents,
      criticalEvents,
      maliciousNotificationCount,
      neutralizedNotificationCount:
        securityLevel === "high"
          ? ensureAttackMonitor().filter((item) => item.status === "neutralized").length
          : 0,
      latestInsight
    }
  };
}

app.get("/", (req, res) => {
  if (req.session.username) {
    return res.redirect("/dashboard");
  }
  res.render("login", { error: null });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = db.users[username];

  if (!user || user.password !== password) {
    return res.render("login", { error: "Invalid username or password." });
  }

  req.session.username = username;
  req.session.securityLevel = "low";
  req.session.csrfToken = crypto.randomUUID();
  req.session.sameSiteMode = "unset";
  req.session.csrfLabMode = "off";
  req.session.xsrfToken = crypto.randomUUID();

  res.redirect("/dashboard");
});

app.get("/dashboard", requireLogin, (req, res) => {
  ensureSecurityDefaults(req);
  issueXsrfCookie(res, req);
  res.render("dashboard", buildDashboardData(req));
});

app.get("/partner-reward", requireLogin, (req, res) => {
  ensureSecurityDefaults(req);
  issueXsrfCookie(res, req);

  const rewardAttemptId = crypto.randomUUID();
  req.session.rewardAttemptId = rewardAttemptId;

  res.render("partner_redirect", {
    cspNonce: res.locals.cspNonce,
    rewardAttemptId,
    attackerOrigin: getEffectiveAttackerOrigin(req)
  });
});

app.get("/partner-dom-lab", requireLogin, (req, res) => {
  ensureSecurityDefaults(req);
  issueXsrfCookie(res, req);

  const domAttemptId = crypto.randomUUID();

  res.render("partner_dom_lab", {
    cspNonce: res.locals.cspNonce,
    domAttemptId,
    attackerOrigin: getEffectiveAttackerOrigin(req),
    securityLevel: req.session.securityLevel || "low",
    csrfToken: req.session.csrfToken,
    xsrfToken: req.session.xsrfToken
  });
});

app.post("/dom-attack-neutralized", requireLogin, (req, res) => {
  ensureSecurityDefaults(req);

  const attemptId = req.body.attemptId || crypto.randomUUID();

  logEvent({
    req,
    from: req.session.username,
    to: "mallory",
    amount: 200,
    status: "BLOCKED",
    level: req.session.securityLevel || "high",
    reason:
      "High mode neutralized the DOM XSS payload delivered via partner postMessage before execution.",
    attackVector: "DOM XSS + CSRF",
    attemptId
  });

  res.status(204).end();
});

app.post("/set-level", requireLogin, (req, res) => {
  const { securityLevel } = req.body;

  if (["low", "medium", "high"].includes(securityLevel)) {
    req.session.securityLevel = securityLevel;
    req.session.csrfToken = crypto.randomUUID();
    req.session.xsrfToken = crypto.randomUUID();
  }

  res.redirect("/dashboard");
});

app.post("/set-cookie-mode", requireLogin, (req, res) => {
  ensureSecurityDefaults(req);

  const { sameSiteMode } = req.body;
  if (["unset", "lax", "strict", "none"].includes(sameSiteMode)) {
    req.session.sameSiteMode = sameSiteMode;
  }

  res.redirect("/dashboard");
});

app.post("/set-csrf-lab-mode", requireLogin, (req, res) => {
  ensureSecurityDefaults(req);

  const { csrfLabMode } = req.body;
  if (["off", "double-submit"].includes(csrfLabMode)) {
    req.session.csrfLabMode = csrfLabMode;
    req.session.csrfToken = crypto.randomUUID();
    req.session.xsrfToken = crypto.randomUUID();
  }

  res.redirect("/dashboard");
});

app.post("/reward-attack-reconcile", requireLogin, (req, res) => {
  ensureSecurityDefaults(req);

  const username = req.session.username;
  const level = req.session.securityLevel || "low";
  const sameSiteMode = req.session.sameSiteMode || "unset";
  const csrfLabMode = req.session.csrfLabMode || "off";
  const attemptId = req.body.attemptId || req.session.rewardAttemptId || null;

  if (!attemptId) {
    return res.status(204).end();
  }

  const existing = db.events.find(
    (e) => e.attemptId === attemptId && e.attackVector === "External CSRF"
  );

  if (!existing) {
    let reason =
      "External CSRF attempt did not complete. The browser or security controls stopped the forged request before any state change.";

    if (level === "medium" || level === "high") {
      reason =
        "Reward-click CSRF attempt was detected during the partner reward flow and blocked before any state change.";
    } else if (sameSiteMode === "lax" || sameSiteMode === "strict") {
      reason =
        `Browser cookie policy likely blocked the authenticated cross-site request (SameSite=${sameSiteMode.toUpperCase()}). No valid authenticated state was sent with the forged transfer request.`;
    } else if (csrfLabMode === "double-submit") {
      reason =
        "External attacker could not satisfy the Double-Submit Cookie requirement, so the forged request did not complete.";
    }

    logEvent({
      req,
      from: username,
      to: "mallory",
      amount: 200,
      status: "BLOCKED",
      level,
      reason,
      attackVector: "External CSRF",
      attemptId
    });
  }

  req.session.rewardAttemptId = null;
  res.status(204).end();
});

app.get("/attack-status", (req, res) => {
  setCorsForAttacker(req, res);

  const attackId = req.query.attackId || "";
  const record = getAttackMonitor(attackId);

  if (!record) {
    return res.json({
      attackId,
      status: "not_found",
      message: "No attack record found."
    });
  }

  return res.json({
    attackId: record.attackId,
    status: record.status,
    message: record.message,
    updatedAt: record.updatedAt,
    from: record.from,
    to: record.to,
    amount: record.amount
  });
});


app.post("/transfer", requireLogin, (req, res) => {
  ensureSecurityDefaults(req);

  const from = req.session.username;
  const to = req.body.to;
  const amount = Number(req.body.amount);
  const level = req.session.securityLevel || "low";
  const attackVector = detectAttackVector(req);
  const attemptId = req.body.attemptId || null;
  const attackId = req.body.attackId || null;
  const csrfLabMode = req.session.csrfLabMode || "off";
  const isScriptInjectionAttack =
    attackVector === "Stored XSS + CSRF" || attackVector === "DOM XSS + CSRF";

  if (level === "medium" || level === "high") {
    if (attackVector === "External CSRF") {
      if (!isTrustedSource(req)) {
        logEvent({
          req,
          from,
          to: to || "unknown",
          amount: Number.isFinite(amount) ? amount : 0,
          status: "BLOCKED",
          level,
          reason: "External request blocked by Origin / Referer validation.",
          attackVector,
          attemptId
        });

        return res.status(403).render("result", {
          type: "blocked",
          title: "Request Blocked",
          message: "The request was blocked because it came from an external attacker page.",
          detail:
            "Medium and High block the reward-click attacker flow by checking request origin."
        });
      }

      if (!req.body.csrfToken || req.body.csrfToken !== req.session.csrfToken) {
        logEvent({
          req,
          from,
          to: to || "unknown",
          amount: Number.isFinite(amount) ? amount : 0,
          status: "BLOCKED",
          level,
          reason: "External request blocked by invalid CSRF token.",
          attackVector,
          attemptId
        });

        return res.status(403).render("result", {
          type: "blocked",
          title: "Request Blocked",
          message: "The request was blocked because the CSRF token is missing or invalid.",
          detail:
            "This stops the reward-click flow but does not stop Stored XSS if script runs inside the bank page."
        });
      }
    }
  }

  if (csrfLabMode === "double-submit") {
    const doubleSubmitValid = validateDoubleSubmitCookie(req);

    if (!doubleSubmitValid) {
      logEvent({
        req,
        from,
        to: to || "unknown",
        amount: Number.isFinite(amount) ? amount : 0,
        status: "BLOCKED",
        level,
        reason: "Double-submit cookie validation failed.",
        attackVector,
        attemptId
      });

      if (attackId && isScriptInjectionAttack) {
        updateAttackMonitor(attackId, "failed", {
          message: `${attackVector} request failed because the double-submit token was missing/invalid.`,
          from,
          to: to || "unknown",
          amount: Number.isFinite(amount) ? amount : 0
        });
      }

      return res.status(403).render("result", {
        type: "blocked",
        title: "Request Blocked",
        message: "Double-submit cookie validation failed.",
        detail:
          "The XSRF-TOKEN cookie and xsrfToken form field did not match the expected value."
      });
    }
  }

  const validationError = validateTransfer(from, to, amount);
  if (validationError) {
    logEvent({
      req,
      from,
      to: to || "unknown",
      amount: Number.isFinite(amount) ? amount : 0,
      status: "FAILED",
      level,
      reason: validationError,
      attackVector,
      attemptId
    });

    if (attackId && isScriptInjectionAttack) {
      updateAttackMonitor(attackId, "failed", {
        message: `Payload executed but failed: ${validationError}`,
        from,
        to: to || "unknown",
        amount: Number.isFinite(amount) ? amount : 0
      });
    }

    return res.status(400).render("result", {
      type: "error",
      title: "Transfer Failed",
      message: validationError,
      detail: "The request reached the bank, but the transaction data was invalid."
    });
  }

  db.users[from].balance -= amount;
  db.users[to].balance += amount;

  let reason = "Transfer completed successfully.";

  if (attackVector === "External CSRF" && level === "low") {
    if (csrfLabMode === "double-submit") {
      reason =
        "External CSRF was blocked unless it could satisfy the double-submit cookie requirement.";
    } else {
      reason = "Cross-site forged request succeeded because no protection was enabled.";
    }
  } else if (
    attackVector === "Stored XSS + CSRF" &&
    (level === "low" || level === "medium")
  ) {
    if (csrfLabMode === "double-submit") {
      reason =
        "Stored malicious script executed inside the bank page, read the anti-CSRF values from the DOM, and bypassed double-submit cookie protection.";
    } else {
      reason =
        "Stored malicious script executed inside the bank page and sent a forged transfer request.";
    }
  } else if (
    attackVector === "DOM XSS + CSRF" &&
    (level === "low" || level === "medium")
  ) {
    if (csrfLabMode === "double-submit") {
      reason =
        "DOM-based XSS executed inside the bank page, read the anti-CSRF values from the DOM, and bypassed double-submit cookie protection.";
    } else {
      reason =
        "DOM-based XSS executed inside the bank page and sent a forged transfer request.";
    }
  } else if (level === "medium" || level === "high") {
    reason = "Transfer succeeded through a legitimate in-app action.";
  }

  logEvent({
    req,
    from,
    to,
    amount,
    status: "SUCCESS",
    level,
    reason,
    attackVector,
    attemptId
  });

  if (attackId && isScriptInjectionAttack) {
    updateAttackMonitor(attackId, "succeeded", {
      message: `Attack succeeded. $${amount} transferred from ${from} to ${to}.`,
      from,
      to,
      amount
    });
  }

  res.render("result", {
    type: "success",
    title: "Transfer Successful",
    message: `${from} transferred $${amount} to ${to}.`,
    detail: `Remaining balance: $${db.users[from].balance}`
  });
});

app.post("/comments", requireLogin, (req, res) => {
  const content = req.body.content || "";

  db.comments.push({
    id: db.comments.length + 1,
    author: req.session.username,
    createdAt: new Date().toLocaleString(),
    content
  });

  res.redirect("/dashboard");
});

app.post("/seed-xss-open", (req, res) => {
  const attackId = req.body.attackId || crypto.randomUUID();

  createAttackMonitor(attackId, "stored-xss");

  db.comments.push({
    id: db.comments.length + 1,
    author: "partner-notice",
    createdAt: new Date().toLocaleString(),
    content: buildStoredXssPayload(attackId)
  });

  res.status(204).end();
});

app.post("/arm-dom-xss", (req, res) => {
  const attackId = req.body.attackId || crypto.randomUUID();
  createAttackMonitor(attackId, "dom-xss");
  res.status(204).end();
});

app.post("/dom-attack-neutralized", requireLogin, (req, res) => {
  ensureSecurityDefaults(req);

  const attackId = req.body.attackId || "";
  const record = getAttackMonitor(attackId);

  if (!record || record.status !== "planted") {
    return res.status(204).end();
  }

  updateAttackMonitor(attackId, "neutralized", {
    message:
      "Victim opened the malicious bank URL in High mode. DOM-based payload was neutralized before execution.",
    from: req.session.username,
    to: record.to || "mallory",
    amount: record.amount || 200
  });

  logEvent({
    req,
    from: req.session.username,
    to: record.to || "mallory",
    amount: record.amount || 200,
    status: "BLOCKED",
    level: req.session.securityLevel || "high",
    reason:
      "High mode neutralized the DOM XSS payload before execution, so no forged transfer request was allowed.",
    attackVector: "DOM XSS + CSRF",
    attemptId: attackId
  });

  res.status(204).end();
});

app.get("/reset", requireLogin, (req, res) => {
  resetDB();
  db.attackMonitor = [];
  req.session.securityLevel = "low";
  req.session.csrfToken = crypto.randomUUID();
  req.session.sameSiteMode = "unset";
  req.session.csrfLabMode = "off";
  req.session.xsrfToken = crypto.randomUUID();
  req.session.rewardAttemptId = null;
  res.redirect("/dashboard");
});

app.get("/logout", (req, res) => {
  res.clearCookie("XSRF-TOKEN", { path: "/" });
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.listen(PORT, () => {
  console.log(`Bank running at http://localhost:${PORT}`);
});