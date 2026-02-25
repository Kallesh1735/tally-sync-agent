// main.js
// Electron main process
// - Creates app window
// - Handles Firebase login + token persistence
// - Fetches Sales Vouchers (Invoices) from Tally on Sync
console.log("USING MAIN.JS FROM:", __filename);

const { XMLParser } = require("fast-xml-parser");

// Production Vercel API URL (HTTPS)
const BACKEND_SYNC_URL =
  "https://giro-pie-frontend.vercel.app/api/sync-tally";
const DEFAULT_BACKEND_BASE_URL = "https://giro-pie-frontend.vercel.app";

function parseBooleanEnv(value, defaultValue = false) {
  if (value === undefined || value === null || value === "") {
    return defaultValue;
    return defaultValue;
  }
  const normalized = String(value).trim().toLowerCase();
  return ["1", "true", "yes", "on"].includes(normalized);
}

function deriveUrlOrigin(urlString) {
  try {
    const u = new URL(urlString);
    return `${u.protocol}//${u.host}`;
  } catch (err) {
    return "";
  }
}

const BACKEND_BASE_URL = (
  process.env.BACKEND_BASE_URL ||
  DEFAULT_BACKEND_BASE_URL ||
  deriveUrlOrigin(BACKEND_SYNC_URL)
).replace(/\/+$/, "");

const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("path");
const fs = require("fs");
const http = require("http");
const https = require("https");
const querystring = require("querystring");
 
// -----------------------------
// Firebase (compat SDK)
// -----------------------------
const firebase = require("firebase/compat/app");
require("firebase/compat/auth");

const firebaseConfig = {
  apiKey: "AIzaSyAhlqL23gyo4x-4Omm_qjwTJG3kF7RnxQ4",
  authDomain: "giropie-frontend.firebaseapp.com",
  projectId: "giropie-frontend",
  storageBucket: "giropie-frontend.firebasestorage.app",
  messagingSenderId: "579042795176",
  appId: "1:579042795176:web:2c30905a9ef33f460b6c9d",
};

// Initialize Firebase ONCE
if (!firebase.apps.length) {
  firebase.initializeApp(firebaseConfig);
  console.log("Firebase initialized in main process");
}

// -----------------------------
// Auth state
// -----------------------------
const tokenFilePath = path.join(app.getPath("userData"), "auth.json");
let currentIdToken = null;
let currentRefreshToken = null;
let currentTokenExpiry = null;
let currentCompanyId = null;
let currentUserUid = null;
let currentUserEmail = null;

const SYNC_LOG_PREFIX = "sync-";
const TALLY_REQUEST_TIMEOUT_MS = Number(process.env.TALLY_TIMEOUT_MS || 45000);
const BACKEND_REQUEST_TIMEOUT_MS = Number(process.env.BACKEND_TIMEOUT_MS || 30000);
const TALLY_REQUEST_RETRIES = Number(process.env.TALLY_RETRY_COUNT || 1);
const TALLY_RETRY_DELAY_MS = Number(process.env.TALLY_RETRY_DELAY_MS || 1500);
const SYNC_MODE = (process.env.SYNC_MODE || "incremental").toLowerCase();
const SYNC_LOOKBACK_DAYS = Number(process.env.SYNC_LOOKBACK_DAYS || 30);
const SYNC_OVERLAP_DAYS = Number(process.env.SYNC_OVERLAP_DAYS || 1);
const SYNC_FULL_LOOKBACK_DAYS = Number(process.env.SYNC_FULL_LOOKBACK_DAYS || 365);
const SYNC_FUTURE_BUFFER_DAYS = Number(process.env.SYNC_FUTURE_BUFFER_DAYS || 0);
const lastSyncFilePath = path.join(app.getPath("userData"), "lastSync.json");
const ENABLE_PDF_WORKER = parseBooleanEnv(process.env.ENABLE_PDF_WORKER, false);
const PDF_WORKER_POLL_MS = Number(process.env.PDF_WORKER_POLL_MS || 3000);
const PDF_JOB_REQUEST_TIMEOUT_MS = Number(
  process.env.PDF_JOB_REQUEST_TIMEOUT_MS || BACKEND_REQUEST_TIMEOUT_MS
);
const PDF_JOB_CLAIM_PATH =
  process.env.PDF_JOB_CLAIM_PATH || "/api/agent/pdf-jobs/claim";
const PDF_JOB_COMPLETE_PATH =
  process.env.PDF_JOB_COMPLETE_PATH || "/api/agent/pdf-jobs/:jobId/complete";
const PDF_JOB_FAIL_PATH =
  process.env.PDF_JOB_FAIL_PATH || "/api/agent/pdf-jobs/:jobId/fail";
const PDF_TALLY_REQUEST_TIMEOUT_MS = Number(
  process.env.PDF_TALLY_TIMEOUT_MS || TALLY_REQUEST_TIMEOUT_MS
);
const PDF_HTML_RENDER_TIMEOUT_MS = Number(
  process.env.PDF_HTML_RENDER_TIMEOUT_MS || 30000
);
const PDF_STRICT_TALLY_LAYOUT = parseBooleanEnv(
  process.env.PDF_STRICT_TALLY_LAYOUT,
  true
);

let pdfWorkerTimer = null;
let pdfWorkerRunning = false;
let pdfWorkerBusy = false;

console.log(
  "Timeouts:",
  `TALLY_TIMEOUT_MS=${TALLY_REQUEST_TIMEOUT_MS}`,
  `BACKEND_TIMEOUT_MS=${BACKEND_REQUEST_TIMEOUT_MS}`,
  `TALLY_RETRY_COUNT=${TALLY_REQUEST_RETRIES}`,
  `TALLY_RETRY_DELAY_MS=${TALLY_RETRY_DELAY_MS}`
);
console.log(
  "Sync window:",
  `SYNC_MODE=${SYNC_MODE}`,
  `SYNC_LOOKBACK_DAYS=${SYNC_LOOKBACK_DAYS}`,
  `SYNC_OVERLAP_DAYS=${SYNC_OVERLAP_DAYS}`,
  `SYNC_FULL_LOOKBACK_DAYS=${SYNC_FULL_LOOKBACK_DAYS}`,
  `SYNC_FUTURE_BUFFER_DAYS=${SYNC_FUTURE_BUFFER_DAYS}`
);
console.log(
  "PDF worker:",
  `BACKEND_BASE_URL=${BACKEND_BASE_URL}`,
  `ENABLE_PDF_WORKER=${ENABLE_PDF_WORKER}`,
  `PDF_WORKER_POLL_MS=${PDF_WORKER_POLL_MS}`,
  `PDF_JOB_CLAIM_PATH=${PDF_JOB_CLAIM_PATH}`,
  `PDF_TALLY_TIMEOUT_MS=${PDF_TALLY_REQUEST_TIMEOUT_MS}`,
  `PDF_STRICT_TALLY_LAYOUT=${PDF_STRICT_TALLY_LAYOUT}`
);

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function formatYMDDate(d) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}${m}${day}`;
}

function normalizeCompanyName(value) {
  if (!value || typeof value !== "string") return null;
  const normalized = value.trim().replace(/\s+/g, " ");
  return normalized.length ? normalized : null;
}

function lastSyncKey(uid, companyName) {
  const user = uid || "anonymous";
  const company = (normalizeCompanyName(companyName) || "AUTO").toUpperCase();
  return `${user}::${company}`;
}

function normalizeLastSyncStore(raw) {
  if (!raw || typeof raw !== "object") {
    return { version: 2, byKey: {}, lastCompanyByUid: {} };
  }

  if (raw.version === 2 && raw.byKey && typeof raw.byKey === "object") {
    return {
      version: 2,
      byKey: raw.byKey,
      lastCompanyByUid:
        raw.lastCompanyByUid && typeof raw.lastCompanyByUid === "object"
          ? raw.lastCompanyByUid
          : {},
    };
  }

  // Backward compatibility with older single-entry format
  if (raw.lastSyncAt) {
    const key = lastSyncKey(raw.uid || null, raw.companyName || null);
    return {
      version: 2,
      byKey: {
        [key]: {
          lastSyncAt: raw.lastSyncAt,
          savedAt: raw.savedAt || null,
          companyName: normalizeCompanyName(raw.companyName),
        },
      },
      lastCompanyByUid: {},
    };
  }

  return { version: 2, byKey: {}, lastCompanyByUid: {} };
}

function loadLastSyncStore() {
  try {
    if (!fs.existsSync(lastSyncFilePath)) {
      return normalizeLastSyncStore(null);
    }
    const raw = fs.readFileSync(lastSyncFilePath, "utf-8");
    return normalizeLastSyncStore(JSON.parse(raw));
  } catch (err) {
    return normalizeLastSyncStore(null);
  }
}

function saveLastSyncStore(store) {
  try {
    fs.writeFileSync(
      lastSyncFilePath,
      JSON.stringify(store, null, 2),
      "utf-8"
    );
  } catch (err) {
    console.error("Failed to save last sync store:", err.message);
  }
}

function resolveTallyCompanyHint() {
  const envCompany = normalizeCompanyName(process.env.TALLY_COMPANY || "");
  if (envCompany) return envCompany;

  const store = loadLastSyncStore();
  const uid = currentUserUid || null;
  if (!uid) return null;
  return normalizeCompanyName(store.lastCompanyByUid[uid] || null);
}

function saveLastSyncAt(isoString, options = {}) {
  const companyName = normalizeCompanyName(options.companyName || null);
  const store = loadLastSyncStore();
  const uid = currentUserUid || null;
  const key = lastSyncKey(uid, companyName);
  store.byKey[key] = {
    lastSyncAt: isoString,
    savedAt: new Date().toISOString(),
    companyName,
  };
  if (uid && companyName) {
    store.lastCompanyByUid[uid] = companyName;
  }
  saveLastSyncStore(store);
}

function computeSyncWindow(options = {}) {
  const modeOverride = options.modeOverride || null;
  const companyName = normalizeCompanyName(options.companyName || null);
  const now = new Date();
  if (SYNC_FUTURE_BUFFER_DAYS > 0) {
    now.setDate(now.getDate() + SYNC_FUTURE_BUFFER_DAYS);
  }

  const store = loadLastSyncStore();
  const key = lastSyncKey(currentUserUid || null, companyName);
  const entry = store.byKey[key] || null;
  const lastSyncAt = entry && entry.lastSyncAt ? new Date(entry.lastSyncAt) : null;

  if (modeOverride === "full") {
    const fromDate = new Date(now);
    fromDate.setDate(fromDate.getDate() - SYNC_FULL_LOOKBACK_DAYS);
    return {
      mode: "full",
      fromDate,
      toDate: now,
      lookbackDays: SYNC_FULL_LOOKBACK_DAYS,
      lastSyncAt: entry ? entry.lastSyncAt : null,
      checkpointKey: key,
      checkpointCompany: companyName || "AUTO",
    };
  }

  if (SYNC_MODE === "incremental" && lastSyncAt && !isNaN(lastSyncAt.getTime())) {
    const fromDate = new Date(lastSyncAt);
    fromDate.setDate(fromDate.getDate() - SYNC_OVERLAP_DAYS);
    return {
      mode: "incremental",
      fromDate,
      toDate: now,
      lastSyncAt: entry.lastSyncAt,
      overlapDays: SYNC_OVERLAP_DAYS,
      checkpointKey: key,
      checkpointCompany: companyName || "AUTO",
    };
  }

  const fromDate = new Date(now);
  fromDate.setDate(fromDate.getDate() - SYNC_LOOKBACK_DAYS);
  return {
    mode: SYNC_MODE,
    fromDate,
    toDate: now,
    lookbackDays: SYNC_LOOKBACK_DAYS,
    lastSyncAt: entry ? entry.lastSyncAt : null,
    checkpointKey: key,
    checkpointCompany: companyName || "AUTO",
  };
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function detectCompanyNameFromTallyXml(xml) {
  if (!xml || typeof xml !== "string") return null;
  const patterns = [
    /<SVCURRENTCOMPANY>([^<]+)<\/SVCURRENTCOMPANY>/i,
    /<COMPANYNAME>([^<]+)<\/COMPANYNAME>/i,
    /<CMPNAME>([^<]+)<\/CMPNAME>/i,
  ];
  for (const pattern of patterns) {
    const match = xml.match(pattern);
    if (match && match[1]) {
      return normalizeCompanyName(match[1]);
    }
  }
  return null;
}

function getSyncWindowPreview(options = {}) {
  const isFullSync = Boolean(options.forceFullSync);
  const companyHint = resolveTallyCompanyHint();
  const syncWindow = computeSyncWindow({
    modeOverride: isFullSync ? "full" : null,
    companyName: companyHint,
  });
  return {
    mode: syncWindow.mode,
    fromDate: formatYMDDate(syncWindow.fromDate),
    toDate: formatYMDDate(syncWindow.toDate),
    lastSyncAt: syncWindow.lastSyncAt || null,
    checkpointCompany: syncWindow.checkpointCompany || null,
    lookbackDays: syncWindow.lookbackDays || null,
    overlapDays: syncWindow.overlapDays || null,
    futureBufferDays: SYNC_FUTURE_BUFFER_DAYS,
    companyHint: companyHint || null,
  };
}

function decodeJwtPayload(token) {
  try {
    if (!token || typeof token !== "string") return null;
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const pad = "=".repeat((4 - (base64.length % 4)) % 4);
    const json = Buffer.from(base64 + pad, "base64").toString("utf8");
    return JSON.parse(json);
  } catch (err) {
    return null;
  }
}

function getTokenExpiryMs(token) {
  const claims = decodeJwtPayload(token);
  const exp = claims && claims.exp ? Number(claims.exp) : null;
  return exp ? exp * 1000 : null;
}

function extractCompanyIdFromClaims(claims) {
  if (!claims || typeof claims !== "object") return null;
  return (
    claims.companyId ||
    claims.company_id ||
    claims.orgId ||
    claims.org_id ||
    claims.tenantId ||
    claims.tenant_id ||
    null
  );
}

function loadAuthFromDisk() {
  try {
    if (!fs.existsSync(tokenFilePath)) return;
    const raw = fs.readFileSync(tokenFilePath, "utf-8");
    const data = JSON.parse(raw);
    currentIdToken = data?.idToken || null;
    currentRefreshToken = data?.refreshToken || null;
    currentTokenExpiry = data?.expiresAt || data?.expiresAtMs || null;
    currentCompanyId = data?.companyId || null;
    currentUserUid = data?.uid || null;
    currentUserEmail = data?.email || null;

    if (!currentTokenExpiry && currentIdToken) {
      currentTokenExpiry = getTokenExpiryMs(currentIdToken);
    }

    if (!currentCompanyId && currentIdToken) {
      const claims = decodeJwtPayload(currentIdToken);
      currentCompanyId = extractCompanyIdFromClaims(claims);
    }

    if (currentIdToken) {
      console.log("Auth token loaded from disk");
    }
  } catch (err) {
    console.error("Failed to load auth token:", err.message);
  }
}

function saveAuthToDisk() {
  try {
    const data = {
      idToken: currentIdToken || null,
      refreshToken: currentRefreshToken || null,
      expiresAt: currentTokenExpiry || null,
      companyId: currentCompanyId || null,
      uid: currentUserUid || null,
      email: currentUserEmail || null,
      savedAt: new Date().toISOString(),
    };
    fs.writeFileSync(tokenFilePath, JSON.stringify(data, null, 2), "utf-8");
  } catch (err) {
    console.error("Failed to save auth token:", err.message);
  }
}

function isTokenExpiringSoon(expiryMs, leewayMs = 60_000) {
  if (!expiryMs) return true;
  return expiryMs - Date.now() <= leewayMs;
}

function refreshIdTokenWithRefreshToken(refreshToken) {
  return new Promise((resolve, reject) => {
    const apiKey = firebaseConfig.apiKey;
    const postData = querystring.stringify({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });

    const req = https.request(
      {
        hostname: "securetoken.googleapis.com",
        path: `/v1/token?key=${apiKey}`,
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": Buffer.byteLength(postData),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c.toString()));
        res.on("end", () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            return reject(
              new Error(`Token refresh failed (${res.statusCode}): ${data}`)
            );
          }
          let json;
          try {
            json = JSON.parse(data);
          } catch (err) {
            return reject(new Error("Failed to parse token refresh response"));
          }

          const idToken = json.id_token || json.access_token || null;
          const newRefreshToken = json.refresh_token || refreshToken;
          const expiresIn = Number(json.expires_in || 0);
          const expiresAt = expiresIn
            ? Date.now() + expiresIn * 1000
            : getTokenExpiryMs(idToken);

          if (!idToken) {
            return reject(new Error("Token refresh response missing id_token"));
          }

          resolve({
            idToken,
            refreshToken: newRefreshToken,
            expiresAt,
          });
        });
      }
    );

    req.on("error", reject);
    req.write(postData);
    req.end();
  });
}

async function ensureFreshIdToken() {
  if (!currentIdToken && !currentRefreshToken && !firebase.auth().currentUser) {
    throw new Error("Not logged in");
  }

  if (currentIdToken && !isTokenExpiringSoon(currentTokenExpiry)) {
    return currentIdToken;
  }

  const user = firebase.auth().currentUser;
  if (user) {
    const idToken = await user.getIdToken(true);
    currentIdToken = idToken;
    currentTokenExpiry = getTokenExpiryMs(idToken);
    const claims = decodeJwtPayload(idToken);
    if (!currentCompanyId) currentCompanyId = extractCompanyIdFromClaims(claims);
    saveAuthToDisk();
    return currentIdToken;
  }

  if (currentRefreshToken) {
    const refreshed = await refreshIdTokenWithRefreshToken(currentRefreshToken);
    currentIdToken = refreshed.idToken;
    currentRefreshToken = refreshed.refreshToken || currentRefreshToken;
    currentTokenExpiry = refreshed.expiresAt;
    const claims = decodeJwtPayload(currentIdToken);
    if (!currentCompanyId) currentCompanyId = extractCompanyIdFromClaims(claims);
    saveAuthToDisk();
    return currentIdToken;
  }

  throw new Error("Session expired. Please login again.");
}

function resolveCompanyId() {
  const env =
    process.env.GIROPIE_COMPANY_ID ||
    process.env.COMPANY_ID ||
    null;
  if (env) return env;
  if (currentCompanyId) return currentCompanyId;
  const claims = decodeJwtPayload(currentIdToken);
  const fromClaims = extractCompanyIdFromClaims(claims);
  if (fromClaims) {
    currentCompanyId = fromClaims;
    saveAuthToDisk();
    return fromClaims;
  }
  return null;
}

function getSyncLogPath() {
  const logsDir = path.join(app.getPath("userData"), "logs");
  try {
    fs.mkdirSync(logsDir, { recursive: true });
  } catch (err) {
    // ignore log dir creation failures
  }
  const date = new Date().toISOString().slice(0, 10);
  return path.join(logsDir, `${SYNC_LOG_PREFIX}${date}.log`);
}

function writeSyncLog(entry) {
  try {
    const line = JSON.stringify(entry);
    fs.appendFileSync(getSyncLogPath(), line + "\n", "utf-8");
  } catch (err) {
    console.error("Failed to write sync log:", err.message);
  }
}

function createSyncId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function computeInvoiceDiagnostics(invoices) {
  const diag = {
    invoiceCount: invoices.length,
    totalAmountSum: 0,
    emptyItemsCount: 0,
    missingInvoiceNo: 0,
    missingInvoiceDate: 0,
    missingCustomerName: 0,
    zeroTotalAmount: 0,
  };

  for (const inv of invoices) {
    const total = Number(inv.totalAmount || 0);
    diag.totalAmountSum += total;
    if (!inv.invoiceNo) diag.missingInvoiceNo += 1;
    if (!inv.invoiceDate) diag.missingInvoiceDate += 1;
    if (!inv.customerName) diag.missingCustomerName += 1;
    if (!inv.items || inv.items.length === 0) diag.emptyItemsCount += 1;
    if (total === 0) diag.zeroTotalAmount += 1;
  }

  return diag;
}

function getAuthStatusSnapshot() {
  const companyId = resolveCompanyId();
  const hasCompanyId = Boolean(companyId);
  return {
    loggedIn: Boolean(currentIdToken || firebase.auth().currentUser),
    hasCompanyId,
    companyId: companyId || null,
    email: currentUserEmail || null,
    uid: currentUserUid || null,
  };
}

function readLastSyncSummary() {
  const logsDir = path.join(app.getPath("userData"), "logs");
  if (!fs.existsSync(logsDir)) {
    return { available: false };
  }

  const files = fs
    .readdirSync(logsDir)
    .filter((f) => f.startsWith(SYNC_LOG_PREFIX) && f.endsWith(".log"))
    .sort()
    .reverse();

  if (files.length === 0) {
    return { available: false };
  }

  const latestFile = path.join(logsDir, files[0]);
  let content = "";
  try {
    content = fs.readFileSync(latestFile, "utf-8");
  } catch (err) {
    return { available: false };
  }

  const lines = content.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) return { available: false };

  const parsed = [];
  for (const line of lines) {
    try {
      parsed.push(JSON.parse(line));
    } catch (err) {
      // skip malformed log line
    }
  }

  if (parsed.length === 0) return { available: false };

  const lastTerminal = [...parsed]
    .reverse()
    .find((e) => e.event === "backend_success" || e.event === "sync_error");

  if (!lastTerminal) return { available: false };

  const syncId = lastTerminal.syncId;
  const lastExtract = [...parsed]
    .reverse()
    .find((e) => e.event === "invoice_extract" && e.syncId === syncId);

  return {
    available: true,
    syncId,
    lastEvent: lastTerminal.event,
    lastAt: lastTerminal.ts || null,
    invoiceCount: lastTerminal.invoiceCount ?? null,
    previewCount: lastExtract?.invoiceCount ?? null,
    totalAmountSum: lastExtract?.totalAmountSum ?? null,
    emptyItemsCount: lastExtract?.emptyItemsCount ?? null,
    missingCustomerName: lastExtract?.missingCustomerName ?? null,
    error: lastTerminal.error || null,
  };
}

// -----------------------------
// Create Window
// -----------------------------
function createWindow() {
  const win = new BrowserWindow({
    width: 900,
    height: 600,
    title: "GIROPie Tally Sync Agent",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  win.loadFile(path.join(__dirname, "index.html"));
}

// -----------------------------
// App Ready
// -----------------------------
app.whenReady().then(() => {
  // Load token from disk (auto-login)
  loadAuthFromDisk();

  createWindow();
  if (currentIdToken) {
    startPdfWorker("app_ready_with_saved_session");
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

app.on("before-quit", () => {
  stopPdfWorker("app_quit");
});

// -----------------------------
// Firebase Login Helper
// -----------------------------
async function signInWithEmailPassword(email, password) {
  const auth = firebase.auth();
  const userCredential = await auth.signInWithEmailAndPassword(email, password);
  const user = userCredential.user;
  const idTokenResult = await user.getIdTokenResult();
  const idToken = idTokenResult.token;
  const expiresAt =
    Date.parse(idTokenResult.expirationTime) || getTokenExpiryMs(idToken);
  const companyId = extractCompanyIdFromClaims(idTokenResult.claims);

  return {
    idToken,
    refreshToken: user.refreshToken || null,
    expiresAt,
    uid: user.uid || null,
    email: user.email || email,
    companyId: companyId || null,
  };
}

// -----------------------------
// IPC: LOGIN
// -----------------------------
ipcMain.handle("login", async (event, creds) => {
  const { email, password } = creds || {};

  if (!email || !password) {
    return { status: "error", message: "Email and password required" };
  }

  try {
    const authData = await signInWithEmailPassword(email, password);
    currentIdToken = authData.idToken;
    currentRefreshToken = authData.refreshToken;
    currentTokenExpiry = authData.expiresAt;
    currentCompanyId = authData.companyId;
    currentUserUid = authData.uid;
    currentUserEmail = authData.email;

    saveAuthToDisk();
    startPdfWorker("login_success");

    console.log("Login successful: Firebase user authenticated");
    return { status: "ok" };
  } catch (err) {
    console.error("Login failed:", err.message);
    return { status: "error", message: err.message };
  }
});

// -----------------------------
// Fetch Sales Vouchers (Invoices) from Tally
// -----------------------------
function fetchSalesVouchersFromTally(options = {}) {
  return new Promise((resolve, reject) => {
    // Build a reasonable default date range (last 30 days) to avoid empty future ranges
    const formatYMD = (d) => {
      const y = d.getFullYear();
      const m = String(d.getMonth() + 1).padStart(2, "0");
      const day = String(d.getDate()).padStart(2, "0");
      return `${y}${m}${day}`;
    };

    const companyHint = normalizeCompanyName(options.companyHint || null);
    const envCompany = normalizeCompanyName(process.env.TALLY_COMPANY || null);
    const companyName = envCompany || companyHint || null;

    const syncWindow = computeSyncWindow({
      modeOverride: options.modeOverride || null,
      companyName,
    });
    const SVFROMDATE = formatYMD(syncWindow.fromDate);
    const SVTODATE = formatYMD(syncWindow.toDate);

    const buildXml = (reportName, requestCompany) => {
      const companyXml = requestCompany
        ? `\n          <SVCURRENTCOMPANY>${escapeXml(requestCompany)}</SVCURRENTCOMPANY>`
        : "";
      return `
<ENVELOPE>
  <HEADER>
    <TALLYREQUEST>Export Data</TALLYREQUEST>
  </HEADER>
  <BODY>
    <EXPORTDATA>
      <REQUESTDESC>
        <REPORTNAME>${reportName}</REPORTNAME>
        <STATICVARIABLES>
${companyXml}
          <SVFROMDATE>${SVFROMDATE}</SVFROMDATE>
          <SVTODATE>${SVTODATE}</SVTODATE>
          <SVEXPORTFORMAT>$$SysName:XML</SVEXPORTFORMAT>
          <EXPLODEFLAG>Yes</EXPLODEFLAG>
        </STATICVARIABLES>
      </REQUESTDESC>
    </EXPORTDATA>
  </BODY>
</ENVELOPE>
`;
    };

    const tryReports = [
      "Voucher Register",
      "Vouchers",
      "Voucher Register (Sales)",
      "Day Book",
    ];

    const metaBase = {
      fromDate: SVFROMDATE,
      toDate: SVTODATE,
      companyName,
      triedReports: [...tryReports],
      requestMode: companyName ? "explicit_company" : "active_company",
      syncMode: syncWindow.mode,
      lastSyncAt: syncWindow.lastSyncAt || null,
      lookbackDays: syncWindow.lookbackDays || null,
      overlapDays: syncWindow.overlapDays || null,
      checkpointCompany: syncWindow.checkpointCompany || null,
      checkpointKey: syncWindow.checkpointKey || null,
      futureBufferDays: SYNC_FUTURE_BUFFER_DAYS,
    };

    const optionsBase = {
      hostname: "127.0.0.1",
      port: 9000,
      method: "POST",
      headers: {
        "Content-Type": "text/xml",
      },
    };

    const sendXml = (xml) =>
      new Promise((resOut, rejOut) => {
        const opts = Object.assign({}, optionsBase, {
          headers: Object.assign({}, optionsBase.headers, {
            "Content-Length": Buffer.byteLength(xml),
          }),
        });

        const req = http.request(opts, (res) => {
          let data = "";
          res.on('data', (c) => (data += c.toString()));
          res.on('end', () => {
            clearTimeout(timeoutHandle);
            resOut({
              data,
              statusCode: res.statusCode,
              headers: res.headers,
            });
          });
        });

        const timeoutHandle = setTimeout(() => {
          req.destroy(
            new Error(`Tally request timed out after ${TALLY_REQUEST_TIMEOUT_MS}ms`)
          );
        }, TALLY_REQUEST_TIMEOUT_MS);

        req.on('error', (err) => {
          clearTimeout(timeoutHandle);
          rejOut(err);
        });
        req.write(xml);
        req.end();
      });

    const sendXmlWithRetry = async (xml, reportName) => {
      let lastErr = null;
      const totalAttempts = Math.max(0, TALLY_REQUEST_RETRIES) + 1;
      for (let attempt = 1; attempt <= totalAttempts; attempt += 1) {
        try {
          return await sendXml(xml);
        } catch (err) {
          lastErr = err;
          console.error(
            `Tally request failed for report ${reportName} (attempt ${attempt}/${totalAttempts}):`,
            err && err.message
          );
          if (attempt < totalAttempts) {
            await delay(TALLY_RETRY_DELAY_MS * attempt);
          }
        }
      }
      throw lastErr || new Error("Tally request failed");
    };

    (async () => {
      let lastResponse = null;
      let lastReport = null;

      const requestCompanies = envCompany
        ? [envCompany]
        : companyHint
        ? [companyHint, null]
        : [null];

      for (const requestCompany of requestCompanies) {
        for (const r of tryReports) {
          try {
            const xml = buildXml(r, requestCompany);
            const resp = await sendXmlWithRetry(xml, r);
            lastResponse = resp;
            lastReport = r;
            // quick heuristic: check if response contains <VOUCHER
            const hasVoucher = resp && resp.data && resp.data.includes("<VOUCHER");
            if (hasVoucher) {
              return resolve({
                xml: resp.data,
                meta: {
                  ...metaBase,
                  requestedCompany: requestCompany || null,
                  detectedCompany:
                    detectCompanyNameFromTallyXml(resp.data) ||
                    requestCompany ||
                    null,
                  selectedReport: r,
                  responseStatus: resp.statusCode,
                  responseBytes: Buffer.byteLength(resp.data || ""),
                  responseHasVoucher: true,
                },
              });
            }
          } catch (err) {
            console.error(
              "Tally request failed for report",
              r,
              err && err.message
            );
          }
        }
      }

      // If none returned vouchers, send the last response (or an empty string)
      try {
        if (lastResponse) {
          return resolve({
            xml: lastResponse.data || "",
            meta: {
              ...metaBase,
              requestedCompany: requestCompanies[0] || null,
              detectedCompany:
                detectCompanyNameFromTallyXml(lastResponse.data || "") ||
                requestCompanies[0] ||
                null,
              selectedReport: lastReport || tryReports[0],
              responseStatus: lastResponse.statusCode,
              responseBytes: Buffer.byteLength(lastResponse.data || ""),
              responseHasVoucher: false,
            },
          });
        }

        const last = buildXml(tryReports[0], requestCompanies[0] || null);
        const fallback = await sendXmlWithRetry(last, tryReports[0]);
        return resolve({
          xml: fallback.data || "",
          meta: {
            ...metaBase,
            requestedCompany: requestCompanies[0] || null,
            detectedCompany:
              detectCompanyNameFromTallyXml(fallback.data || "") ||
              requestCompanies[0] ||
              null,
            selectedReport: tryReports[0],
            responseStatus: fallback.statusCode,
            responseBytes: Buffer.byteLength(fallback.data || ""),
            responseHasVoucher: fallback.data
              ? fallback.data.includes("<VOUCHER")
              : false,
          },
        });
      } catch (e) {
        return reject(e);
      }
    })();
  });
}

// -----------------------------
// IPC: SYNC FROM TALLY (Invoices)
// -----------------------------
ipcMain.handle("sync-from-tally", async () => {
  console.log("IPC received: sync-from-tally");

  const syncId = createSyncId();
  writeSyncLog({
    ts: new Date().toISOString(),
    level: "info",
    event: "sync_start",
    syncId,
    method: "LEGACY",
  });

  try {
    await ensureFreshIdToken();
    const companyId = resolveCompanyId();
    const companyHint = resolveTallyCompanyHint();

    const tallyResult = await fetchSalesVouchersFromTally({
      companyHint,
    });
    const xml = tallyResult.xml || "";
    const meta = tallyResult.meta || {};
    writeSyncLog({
      ts: new Date().toISOString(),
      level: "info",
      event: "tally_fetch_complete",
      syncId,
      ...meta,
    });

    const { invoices, stats } = extractInvoicesFromTallyXML(xml, {
      withStats: true,
    });
    const diagnostics = computeInvoiceDiagnostics(invoices);
    writeSyncLog({
      ts: new Date().toISOString(),
      level: "info",
      event: "invoice_extract",
      syncId,
      ...stats,
      ...diagnostics,
    });

    await sendInvoicesToBackend(invoices, { companyId, syncId });
    writeSyncLog({
      ts: new Date().toISOString(),
      level: "info",
      event: "backend_success",
      syncId,
      invoiceCount: invoices.length,
    });
    const checkpointCompany =
      normalizeCompanyName(meta.detectedCompany) ||
      normalizeCompanyName(meta.requestedCompany) ||
      companyHint ||
      null;
    saveLastSyncAt(new Date().toISOString(), { companyName: checkpointCompany });
    return { status: "ok", count: invoices.length };
  } catch (err) {
    console.error("TALLY ERROR:", err.message);
    writeSyncLog({
      ts: new Date().toISOString(),
      level: "error",
      event: "sync_error",
      syncId,
      error: err.message,
    });
    return { status: "error", message: err.message };
  }
});

function sendInvoicesToBackend(invoices, options = {}) {
  return new Promise((resolve, reject) => {
    const { companyId, syncId } = options;
    if (!Array.isArray(invoices)) {
      return reject(new Error("Invalid invoices payload"));
    }
    const payload = { invoices };
    if (companyId) payload.companyId = companyId;
    const body = JSON.stringify(payload);

    const headers = {
      "Content-Type": "application/json",
      Authorization: `Bearer ${currentIdToken}`,
      "Content-Length": Buffer.byteLength(body),
    };

    if (syncId) headers["X-Sync-Id"] = syncId;

    const req = https.request(
      BACKEND_SYNC_URL,
      {
        method: "POST",
        headers,
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c.toString()));
        res.on("end", () => {
          clearTimeout(timeoutHandle);
          if (res.statusCode < 200 || res.statusCode >= 300) {
            return reject(
              new Error(`Backend sync failed (${res.statusCode}): ${data}`)
            );
          }
          resolve({ statusCode: res.statusCode, body: data });
        });
      }
    );

    const timeoutHandle = setTimeout(() => {
      req.destroy(
        new Error(
          `Backend request timed out after ${BACKEND_REQUEST_TIMEOUT_MS}ms`
        )
      );
    }, BACKEND_REQUEST_TIMEOUT_MS);

    req.on("error", (err) => {
      clearTimeout(timeoutHandle);
      reject(err);
    });
    req.write(body);
    req.end();
  });
}

function buildBackendUrl(apiPath) {
  if (!BACKEND_BASE_URL) {
    throw new Error("BACKEND_BASE_URL is not configured");
  }
  const normalizedPath = String(apiPath || "").startsWith("/")
    ? String(apiPath)
    : `/${String(apiPath || "")}`;
  return `${BACKEND_BASE_URL}${normalizedPath}`;
}

function resolvePathWithJobId(pathTemplate, jobId) {
  const encoded = encodeURIComponent(String(jobId || "").trim());
  if (!encoded) {
    throw new Error("Missing PDF job id");
  }
  if (pathTemplate.includes(":jobId")) {
    return pathTemplate.replace(":jobId", encoded);
  }
  const cleaned = pathTemplate.replace(/\/+$/, "");
  return `${cleaned}/${encoded}`;
}

function parseMaybeJson(input) {
  if (!input || !String(input).trim()) return null;
  try {
    return JSON.parse(input);
  } catch (err) {
    return null;
  }
}

function summarizeResponseBody(body, maxLen = 500) {
  if (!body) return "";
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  return raw.length > maxLen ? `${raw.slice(0, maxLen)}...` : raw;
}

function buildStageError(stagePrefix, err) {
  const statusCode =
    err && typeof err.statusCode === "number" ? err.statusCode : null;
  const responseRaw =
    (err && (err.responseBody || err.rawBody)) ||
    (err && err.responseJson ? JSON.stringify(err.responseJson) : "");
  const message =
    err && err.message ? err.message : typeof err === "string" ? err : "Unknown error";
  const bodyPart = responseRaw
    ? ` | body=${summarizeResponseBody(responseRaw, 700)}`
    : "";
  if (statusCode) {
    return `${stagePrefix}_${statusCode}: ${message}${bodyPart}`;
  }
  return `${stagePrefix}: ${message}${bodyPart}`;
}

async function requestBackendJson(url, options = {}) {
  const retried401 = Boolean(options.__retried401);
  await ensureFreshIdToken();

  const runRequest = () =>
    new Promise((resolve, reject) => {
      const payload =
        options.payload === undefined ? null : JSON.stringify(options.payload);
      const headers = {
        "Content-Type": "application/json",
        Authorization: `Bearer ${currentIdToken}`,
        ...(options.headers || {}),
      };
      if (payload !== null) {
        headers["Content-Length"] = Buffer.byteLength(payload);
      }

      const req = https.request(
        url,
        {
          method: options.method || "GET",
          headers,
        },
        (res) => {
          let data = "";
          res.on("data", (c) => (data += c.toString()));
          res.on("end", () => {
            clearTimeout(timeoutHandle);
            const parsed = parseMaybeJson(data);
            if (res.statusCode < 200 || res.statusCode >= 300) {
              const errorMessage =
                (parsed && (parsed.error || parsed.message)) ||
                `Request failed (${res.statusCode}): ${data}`;
              const err = new Error(errorMessage);
              err.statusCode = res.statusCode;
              err.responseBody = data;
              err.responseJson = parsed;
              err.rawBody = data;
              return reject(err);
            }
            resolve({
              statusCode: res.statusCode,
              body: parsed || null,
              rawBody: data,
            });
          });
        }
      );

      const timeoutMs = Number(options.timeoutMs || PDF_JOB_REQUEST_TIMEOUT_MS);
      const timeoutHandle = setTimeout(() => {
        req.destroy(new Error(`Backend request timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      req.on("error", (err) => {
        clearTimeout(timeoutHandle);
        reject(err);
      });
      if (payload !== null) {
        req.write(payload);
      }
      req.end();
    });

  try {
    return await runRequest();
  } catch (err) {
    if (err && err.statusCode === 401 && !retried401) {
      writeSyncLog({
        ts: new Date().toISOString(),
        level: "warn",
        event: "pdf_backend_401_retry",
        url,
      });
      await ensureFreshIdToken();
      return requestBackendJson(url, {
        ...options,
        __retried401: true,
      });
    }
    throw err;
  }
}

async function claimNextPdfJob() {
  const companyId = resolveCompanyId();
  writeSyncLog({
    ts: new Date().toISOString(),
    level: "info",
    event: "pdf_claim_request",
    companyId: companyId || null,
    path: PDF_JOB_CLAIM_PATH,
  });
  const res = await requestBackendJson(buildBackendUrl(PDF_JOB_CLAIM_PATH), {
    method: "POST",
    payload: {
      companyId: companyId || null,
      agent: {
        name: "giropie-tally-agent",
        version: app.getVersion(),
        platform: process.platform,
      },
    },
    timeoutMs: PDF_JOB_REQUEST_TIMEOUT_MS,
  });
  writeSyncLog({
    ts: new Date().toISOString(),
    level: "info",
    event: "pdf_claim_response",
    statusCode: res.statusCode,
    body: summarizeResponseBody(res.body || res.rawBody),
  });

  if (res.statusCode === 204 || !res.body) return null;
  const body = res.body;
  if (body.status === "empty" || body.job === null) return null;
  if (body.job && typeof body.job === "object") return body.job;
  if (body.id || body.jobId) return body;
  return null;
}

async function markPdfJobComplete(jobId, payload) {
  const pathWithId = resolvePathWithJobId(PDF_JOB_COMPLETE_PATH, jobId);
  writeSyncLog({
    ts: new Date().toISOString(),
    level: "info",
    event: "pdf_complete_request",
    jobId,
    path: pathWithId,
    payloadInfo: {
      fileName: payload && payload.fileName ? payload.fileName : null,
      mimeType: payload && payload.mimeType ? payload.mimeType : null,
      pdfBase64Bytes: payload && payload.pdfBase64
        ? Buffer.byteLength(String(payload.pdfBase64), "utf8")
        : 0,
    },
  });
  const res = await requestBackendJson(buildBackendUrl(pathWithId), {
    method: "POST",
    payload,
    timeoutMs: PDF_JOB_REQUEST_TIMEOUT_MS,
  });
  writeSyncLog({
    ts: new Date().toISOString(),
    level: "info",
    event: "pdf_complete_response",
    jobId,
    statusCode: res.statusCode,
    body: summarizeResponseBody(res.body || res.rawBody),
  });
  return res;
}

async function markPdfJobFailed(jobId, errorMessage) {
  const pathWithId = resolvePathWithJobId(PDF_JOB_FAIL_PATH, jobId);
  const payload = { error: String(errorMessage || "Unknown PDF generation error") };
  writeSyncLog({
    ts: new Date().toISOString(),
    level: "error",
    event: "pdf_fail_request",
    jobId,
    path: pathWithId,
    payload,
  });
  const res = await requestBackendJson(buildBackendUrl(pathWithId), {
    method: "POST",
    payload,
    timeoutMs: PDF_JOB_REQUEST_TIMEOUT_MS,
  });
  writeSyncLog({
    ts: new Date().toISOString(),
    level: "info",
    event: "pdf_fail_response",
    jobId,
    statusCode: res.statusCode,
    body: summarizeResponseBody(res.body || res.rawBody),
  });
  return res;
}

function readPdfFromLocalPath(localPdfPath) {
  const absPath = path.resolve(localPdfPath);
  const bytes = fs.readFileSync(absPath);
  const fileName = path.basename(absPath);
  return {
    fileName,
    mimeType: "application/pdf",
    pdfBase64: bytes.toString("base64"),
  };
}

function getJobField(job, ...keys) {
  if (!job || typeof job !== "object") return null;
  for (const key of keys) {
    if (!key) continue;
    const value = job[key];
    if (value !== undefined && value !== null && String(value).trim() !== "") {
      return value;
    }
    if (job.invoice && job.invoice[key] !== undefined && job.invoice[key] !== null) {
      const nested = job.invoice[key];
      if (String(nested).trim() !== "") return nested;
    }
  }
  return null;
}

function normalizeDateToYmd(input) {
  if (!input) return null;
  const str = String(input).trim();
  if (/^\d{8}$/.test(str)) return str;

  const onlyDigits = str.replace(/[^\d]/g, "");
  if (onlyDigits.length === 8) return onlyDigits;

  const parsed = new Date(str);
  if (!isNaN(parsed.getTime())) {
    return formatYMDDate(parsed);
  }
  return null;
}

function ymdToDdMmYyyy(ymd) {
  if (!ymd || !/^\d{8}$/.test(String(ymd))) return null;
  const raw = String(ymd);
  return `${raw.slice(6, 8)}-${raw.slice(4, 6)}-${raw.slice(0, 4)}`;
}

function buildTallyDateVariants(rawDate) {
  const ymd = normalizeDateToYmd(rawDate);
  if (!ymd) return [];
  const variants = [ymd];
  const ddmmyyyy = ymdToDdMmYyyy(ymd);
  if (ddmmyyyy) variants.push(ddmmyyyy);
  return [...new Set(variants.filter(Boolean))];
}

function parseIdentityKey(identityKey) {
  if (!identityKey) return {};
  const raw = String(identityKey).trim();
  if (!raw) return {};

  const sepIndex = raw.indexOf(":");
  const suffix = sepIndex >= 0 ? raw.slice(sepIndex + 1).trim() : raw;
  if (!suffix) return {};

  if (suffix.includes("|")) {
    const [invoiceNoPart, invoiceDatePart] = suffix.split("|");
    return {
      invoiceNo: invoiceNoPart ? String(invoiceNoPart).trim() : null,
      invoiceDate: invoiceDatePart ? String(invoiceDatePart).trim() : null,
    };
  }

  return { sourceId: suffix };
}

function isUsableCompanyName(name) {
  if (!name) return false;
  const raw = String(name).trim();
  if (!raw) return false;
  // Email/user identifiers are not valid Tally company names and should not be forced
  if (raw.includes("@")) return false;
  const upper = raw.toUpperCase();
  const invalid = new Set(["AUTO", "AUTO_ACTIVE", "UNKNOWN", "N/A", "NULL"]);
  return !invalid.has(upper);
}

function resolvePdfIdentity(job) {
  const fromIdentityKey = parseIdentityKey(getJobField(job, "identityKey"));
  const sourceId = String(
    getJobField(
      job,
      "sourceId",
      "remoteId",
      "remoteID",
      "guid",
      "voucherGuid",
      "masterId",
      "alterId"
    ) ||
      fromIdentityKey.sourceId ||
      ""
  ).trim() || null;
  const invoiceNo = String(
    getJobField(job, "invoiceNo", "voucherNumber", "number") ||
      fromIdentityKey.invoiceNo ||
      ""
  ).trim() || null;
  const invoiceDateRaw =
    getJobField(job, "invoiceDate", "invoiceDateISO", "date") ||
    fromIdentityKey.invoiceDate ||
    null;
  const invoiceDateYmd = normalizeDateToYmd(invoiceDateRaw);
  const voucherTypeName = String(
    getJobField(job, "voucherTypeName", "voucherType", "vchType") || "Sales"
  ).trim() || "Sales";

  const companyNameRaw = normalizeCompanyName(
    getJobField(job, "companyName", "tallyCompanyName")
  );
  const companyName = isUsableCompanyName(companyNameRaw) ? companyNameRaw : null;

  return {
    sourceId,
    identityKey: getJobField(job, "identityKey") || null,
    invoiceNo,
    invoiceDateRaw,
    invoiceDateYmd,
    dateVariants: buildTallyDateVariants(invoiceDateRaw),
    voucherTypeName,
    companyName,
    strategy: sourceId ? "sourceId" : "invoiceNoDate",
  };
}

function computePdfWindowFromJob(job, overrideDateYmd = null) {
  const invoiceDateYmd =
    overrideDateYmd ||
    normalizeDateToYmd(getJobField(job, "invoiceDate", "invoiceDateISO", "date"));
  if (!invoiceDateYmd) {
    const now = new Date();
    const fromDate = new Date(now);
    fromDate.setDate(fromDate.getDate() - 90);
    return {
      fromDateYmd: formatYMDDate(fromDate),
      toDateYmd: formatYMDDate(now),
      invoiceDateYmd: null,
    };
  }

  const y = Number(invoiceDateYmd.slice(0, 4));
  const m = Number(invoiceDateYmd.slice(4, 6)) - 1;
  const d = Number(invoiceDateYmd.slice(6, 8));
  const center = new Date(y, m, d);
  const fromDate = new Date(center);
  fromDate.setDate(fromDate.getDate() - 7);
  const toDate = new Date(center);
  toDate.setDate(toDate.getDate() + 7);
  return {
    fromDateYmd: formatYMDDate(fromDate),
    toDateYmd: formatYMDDate(toDate),
    invoiceDateYmd,
  };
}

function extractTallyLineError(raw) {
  if (!raw || typeof raw !== "string") return null;
  const match = raw.match(/<LINEERROR>([\s\S]*?)<\/LINEERROR>/i);
  if (!match || !match[1]) return null;
  return decodeXmlEntities(match[1]).trim();
}

function decodeXmlEntities(input) {
  if (!input) return input;
  return String(input)
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

function extractHtmlFromTallyPayload(raw) {
  if (!raw || typeof raw !== "string") return null;
  const directHtmlMatch = raw.match(/<!doctype[\s\S]*<\/html>/i) || raw.match(/<html[\s\S]*<\/html>/i);
  if (directHtmlMatch) return directHtmlMatch[0];

  const wrappedHtmlMatch =
    raw.match(/<HTML>([\s\S]*?)<\/HTML>/i) ||
    raw.match(/<REPORTHTML>([\s\S]*?)<\/REPORTHTML>/i);
  if (wrappedHtmlMatch && wrappedHtmlMatch[1]) {
    const decoded = decodeXmlEntities(wrappedHtmlMatch[1]);
    const nestedMatch =
      decoded.match(/<!doctype[\s\S]*<\/html>/i) ||
      decoded.match(/<html[\s\S]*<\/html>/i);
    return nestedMatch ? nestedMatch[0] : decoded;
  }
  return null;
}

function buildStaticVariablesXml(entries) {
  const lines = [];
  for (const [key, value] of Object.entries(entries)) {
    if (value === null || value === undefined || String(value).trim() === "") continue;
    lines.push(`          <${key}>${escapeXml(value)}</${key}>`);
  }
  return lines.join("\n");
}

function requestTallyRaw(xml, timeoutMs = PDF_TALLY_REQUEST_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: 9000,
        method: "POST",
        headers: {
          "Content-Type": "text/xml",
          "Content-Length": Buffer.byteLength(xml),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c.toString()));
        res.on("end", () => {
          clearTimeout(timeoutHandle);
          resolve({
            statusCode: res.statusCode,
            body: data,
          });
        });
      }
    );

    const timeoutHandle = setTimeout(() => {
      req.destroy(new Error(`Tally PDF request timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    req.on("error", (err) => {
      clearTimeout(timeoutHandle);
      reject(err);
    });
    req.write(xml);
    req.end();
  });
}

async function fetchInvoicePrintHtmlFromTally(job) {
  const jobId = job.jobId || job.id || null;
  const identity = resolvePdfIdentity(job);

  if (!identity.sourceId && !identity.invoiceNo) {
    throw new Error(
      "TALLY_FETCH: Missing invoice identity in PDF job (need sourceId/identityKey or invoiceNo)"
    );
  }

  writeSyncLog({
    ts: new Date().toISOString(),
    level: "info",
    event: "pdf_identity_payload",
    jobId,
    strategy: identity.strategy,
    sourceId: identity.sourceId || null,
    identityKey: identity.identityKey || null,
    invoiceNo: identity.invoiceNo || null,
    invoiceDateRaw: identity.invoiceDateRaw || null,
    invoiceDateYmd: identity.invoiceDateYmd || null,
    dateVariants: identity.dateVariants,
    voucherTypeName: identity.voucherTypeName,
    companyName: identity.companyName || null,
  });

  const window = computePdfWindowFromJob(job, identity.invoiceDateYmd);
  const reportNames = [
    "Voucher Printing",
    "Voucher",
    "Sales Invoice",
    "Invoice",
  ];
  const dateVariants =
    identity.dateVariants.length > 0 ? identity.dateVariants : [null];

  const identityVarSets = [];
  if (identity.sourceId) {
    identityVarSets.push({
      name: "source_id",
      vars: {
        SVGUID: identity.sourceId,
        GUID: identity.sourceId,
        REMOTEID: identity.sourceId,
        SVREMOTEID: identity.sourceId,
      },
    });
  }
  if (identity.invoiceNo) {
    identityVarSets.push({
      name: "invoice_no",
      vars: {
        SVVOUCHERNUMBER: identity.invoiceNo,
        VOUCHERNUMBER: identity.invoiceNo,
      },
    });
  }
  if (identityVarSets.length === 0) {
    identityVarSets.push({ name: "none", vars: {} });
  }

  const attempts = [];
  for (const reportName of reportNames) {
    for (const identitySet of identityVarSets) {
      for (const dateVariant of dateVariants) {
        const baseVars = {
          SVEXPORTFORMAT: "$$SysName:HTML",
          SVFROMDATE: window.fromDateYmd,
          SVTODATE: window.toDateYmd,
          SVVIEWNAME: "Invoice Voucher View",
          EXPLODEFLAG: "Yes",
          SVVOUCHERTYPENAME: identity.voucherTypeName || "Sales",
          SVPRINTTYPE: "Invoice",
          ...(identity.companyName
            ? { SVCURRENTCOMPANY: identity.companyName }
            : {}),
          ...identitySet.vars,
        };
        if (dateVariant) {
          baseVars.SVOUCHERDATE = dateVariant;
          baseVars.SVVOUCHERDATE = dateVariant;
          baseVars.SVDATE = dateVariant;
          baseVars.DATE = dateVariant;
        }
        attempts.push({
          shape: "export_data",
          reportName,
          identitySetName: identitySet.name,
          dateVariant: dateVariant || "none",
          vars: baseVars,
        });
        attempts.push({
          shape: "export",
          reportName,
          identitySetName: identitySet.name,
          dateVariant: dateVariant || "none",
          vars: baseVars,
        });
      }
    }
  }

  const failures = [];

  for (let i = 0; i < attempts.length; i += 1) {
    const attempt = attempts[i];
    const staticVarsXml = buildStaticVariablesXml(attempt.vars);
    const xml =
      attempt.shape === "export"
        ? `
<ENVELOPE>
  <HEADER>
    <VERSION>1</VERSION>
    <TALLYREQUEST>Export</TALLYREQUEST>
    <TYPE>Data</TYPE>
    <ID>${escapeXml(attempt.reportName)}</ID>
  </HEADER>
  <BODY>
    <DESC>
      <STATICVARIABLES>
${staticVarsXml}
      </STATICVARIABLES>
    </DESC>
  </BODY>
</ENVELOPE>
`
        : `
<ENVELOPE>
  <HEADER>
    <TALLYREQUEST>Export Data</TALLYREQUEST>
  </HEADER>
  <BODY>
    <EXPORTDATA>
      <REQUESTDESC>
        <REPORTNAME>${escapeXml(attempt.reportName)}</REPORTNAME>
        <STATICVARIABLES>
${staticVarsXml}
        </STATICVARIABLES>
      </REQUESTDESC>
    </EXPORTDATA>
  </BODY>
</ENVELOPE>
`;

    writeSyncLog({
      ts: new Date().toISOString(),
      level: "info",
      event: "pdf_tally_variant_attempt",
      jobId,
      attemptNo: i + 1,
      totalAttempts: attempts.length,
      shape: attempt.shape,
      reportName: attempt.reportName,
      identitySet: attempt.identitySetName,
      dateVariant: attempt.dateVariant,
      forcedCompany: identity.companyName || null,
    });

    try {
      const resp = await requestTallyRaw(xml);
      const html = extractHtmlFromTallyPayload(resp.body);
      const lineError = extractTallyLineError(resp.body);
      if (html && html.length > 100) {
        writeSyncLog({
          ts: new Date().toISOString(),
          level: "info",
          event: "pdf_tally_html_found",
          jobId,
          reportName: attempt.reportName,
          shape: attempt.shape,
          identitySet: attempt.identitySetName,
          dateVariant: attempt.dateVariant,
          statusCode: resp.statusCode,
        });
        return {
          html,
          reportName: attempt.reportName,
          shape: attempt.shape,
          identitySet: attempt.identitySetName,
          dateVariant: attempt.dateVariant,
        };
      }

      failures.push(
        `#${i + 1} ${attempt.shape}/${attempt.reportName}/${attempt.identitySetName}/${attempt.dateVariant}: status=${resp.statusCode}${
          lineError ? ` lineError=${lineError}` : ""
        }`
      );
    } catch (err) {
      failures.push(
        `#${i + 1} ${attempt.shape}/${attempt.reportName}/${attempt.identitySetName}/${attempt.dateVariant}: error=${
          err && err.message ? err.message : String(err)
        }`
      );
    }
  }

  const detail = failures.slice(0, 6).join(" || ");
  throw new Error(
    `TALLY_FETCH: Unable to export printable HTML from Tally for invoice ${
      identity.invoiceNo || "unknown"
    }. Attempts=${attempts.length}. Details=${detail || "none"}`
  );
}

async function renderHtmlToPdfBase64(html) {
  const win = new BrowserWindow({
    show: false,
    webPreferences: {
      contextIsolation: true,
      sandbox: true,
    },
  });
  try {
    const dataUrl = `data:text/html;base64,${Buffer.from(html, "utf-8").toString("base64")}`;
    await win.loadURL(dataUrl);
    const pdfBuffer = await Promise.race([
      win.webContents.printToPDF({
        printBackground: true,
        pageSize: "A4",
        margins: {
          top: 0,
          bottom: 0,
          left: 0,
          right: 0,
        },
      }),
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error(`HTML render timed out after ${PDF_HTML_RENDER_TIMEOUT_MS}ms`)),
          PDF_HTML_RENDER_TIMEOUT_MS
        )
      ),
    ]);
    return pdfBuffer.toString("base64");
  } finally {
    if (!win.isDestroyed()) {
      win.destroy();
    }
  }
}

function buildFallbackInvoiceHtml(job) {
  const invoiceNo = getJobField(job, "invoiceNo", "voucherNumber", "number") || "-";
  const customerName = getJobField(job, "customerName", "partyName") || "-";
  const invoiceDate =
    getJobField(job, "invoiceDate", "invoiceDateISO", "date") || "-";
  const totalAmount =
    getJobField(job, "totalAmount", "amount", "invoiceAmount") || "-";
  const companyName = getJobField(job, "companyName", "tallyCompanyName") || "Company";

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; color: #111; }
    h1 { font-size: 24px; margin: 0 0 12px; }
    .meta { margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { border: 1px solid #333; padding: 8px; text-align: left; }
    .right { text-align: right; }
  </style>
</head>
<body>
  <h1>INVOICE</h1>
  <div class="meta"><strong>${escapeXml(String(companyName))}</strong></div>
  <table>
    <tr><th>Invoice No</th><td>${escapeXml(String(invoiceNo))}</td></tr>
    <tr><th>Invoice Date</th><td>${escapeXml(String(invoiceDate))}</td></tr>
    <tr><th>Customer</th><td>${escapeXml(String(customerName))}</td></tr>
    <tr><th>Total Amount</th><td class="right">${escapeXml(String(totalAmount))}</td></tr>
  </table>
</body>
</html>`;
}

async function generateInvoicePdfFromTally(job) {
  if (job && typeof job.pdfBase64 === "string" && job.pdfBase64.length > 0) {
    return {
      fileName: job.fileName || `invoice-${job.jobId || Date.now()}.pdf`,
      mimeType: "application/pdf",
      pdfBase64: job.pdfBase64,
    };
  }
  if (job && typeof job.localPdfPath === "string" && job.localPdfPath.length > 0) {
    return readPdfFromLocalPath(job.localPdfPath);
  }

  if (job && typeof job.tallyPrintHtml === "string" && job.tallyPrintHtml.length > 0) {
    let pdfBase64;
    try {
      pdfBase64 = await renderHtmlToPdfBase64(job.tallyPrintHtml);
    } catch (err) {
      throw new Error(buildStageError("PDF_RENDER", err));
    }
    return {
      fileName: job.fileName || `invoice-${job.jobId || Date.now()}.pdf`,
      mimeType: "application/pdf",
      pdfBase64,
    };
  }

  let htmlResult = null;
  let htmlFetchError = null;
  try {
    htmlResult = await fetchInvoicePrintHtmlFromTally(job);
  } catch (err) {
    htmlFetchError = err;
    writeSyncLog({
      ts: new Date().toISOString(),
      level: "error",
      event: "pdf_tally_html_fetch_failed",
      jobId: job.jobId || job.id || null,
      error: err && err.message ? err.message : String(err),
    });
  }

  if (htmlResult && htmlResult.html) {
    let pdfBase64;
    try {
      pdfBase64 = await renderHtmlToPdfBase64(htmlResult.html);
    } catch (err) {
      throw new Error(buildStageError("PDF_RENDER", err));
    }
    return {
      fileName:
        job.fileName ||
        `invoice-${String(getJobField(job, "invoiceNo", "voucherNumber") || job.jobId || Date.now())}.pdf`,
      mimeType: "application/pdf",
      pdfBase64,
    };
  }

  if (!PDF_STRICT_TALLY_LAYOUT) {
    const fallbackHtml = buildFallbackInvoiceHtml(job);
    let pdfBase64;
    try {
      pdfBase64 = await renderHtmlToPdfBase64(fallbackHtml);
    } catch (err) {
      throw new Error(buildStageError("PDF_RENDER", err));
    }
    writeSyncLog({
      ts: new Date().toISOString(),
      level: "warn",
      event: "pdf_fallback_used",
      jobId: job.jobId || job.id || null,
      reason: htmlFetchError ? htmlFetchError.message : "no_tally_html",
    });
    return {
      fileName: job.fileName || `invoice-${job.jobId || Date.now()}.pdf`,
      mimeType: "application/pdf",
      pdfBase64,
    };
  }

  if (htmlFetchError) throw htmlFetchError;
  throw new Error("Failed to generate exact Tally invoice PDF");
}

async function processOnePdfJob() {
  const job = await claimNextPdfJob();
  if (!job) return { status: "idle" };

  const jobId = job.jobId || job.id;
  if (!jobId) {
    throw new Error("Received PDF job without jobId");
  }

  writeSyncLog({
    ts: new Date().toISOString(),
    level: "info",
    event: "pdf_job_claimed",
    jobId,
    invoiceId: job.invoiceId || null,
  });

  let result = null;
  let processingError = null;
  try {
    let pdfResult;
    try {
      pdfResult = await generateInvoicePdfFromTally(job);
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      if (msg.startsWith("TALLY_FETCH:") || msg.startsWith("PDF_RENDER:")) {
        throw err;
      }
      throw new Error(buildStageError("PDF_GENERATE", err));
    }

    try {
      await markPdfJobComplete(jobId, {
        fileName: pdfResult.fileName,
        mimeType: pdfResult.mimeType || "application/pdf",
        pdfBase64: pdfResult.pdfBase64,
        agentMeta: {
          version: app.getVersion(),
          platform: process.platform,
          processedAt: new Date().toISOString(),
        },
      });
    } catch (err) {
      throw new Error(buildStageError("COMPLETE_API", err));
    }

    result = { status: "done", jobId };
  } catch (err) {
    processingError = err;
  } finally {
    if (!result) {
      const msg =
        processingError && processingError.message
          ? processingError.message
          : "PDF_PIPELINE: Unknown PDF job error";
      try {
        await markPdfJobFailed(jobId, msg);
        result = { status: "failed", jobId, error: msg };
      } catch (failErr) {
        const firstFailMsg =
          failErr && failErr.message ? failErr.message : String(failErr);
        writeSyncLog({
          ts: new Date().toISOString(),
          level: "error",
          event: "pdf_job_fail_callback_error",
          jobId,
          attempt: 1,
          error: firstFailMsg,
        });
        try {
          await delay(300);
          await markPdfJobFailed(
            jobId,
            `${msg} | FAIL_API_RETRY_AFTER_ERROR: ${firstFailMsg}`
          );
          result = { status: "failed", jobId, error: msg };
        } catch (retryErr) {
          writeSyncLog({
            ts: new Date().toISOString(),
            level: "error",
            event: "pdf_job_fail_callback_error",
            jobId,
            attempt: 2,
            error:
              retryErr && retryErr.message
                ? retryErr.message
                : String(retryErr),
          });
        }
      }
    }
  }

  if (result && result.status === "done") {
    writeSyncLog({
      ts: new Date().toISOString(),
      level: "info",
      event: "pdf_job_completed",
      jobId,
      invoiceId: job.invoiceId || null,
    });
    return result;
  }

  writeSyncLog({
    ts: new Date().toISOString(),
    level: "error",
    event: "pdf_job_failed",
    jobId,
    error: result && result.error ? result.error : "Failed to finalize PDF job",
  });
  return result || { status: "error", jobId, error: "Failed to finalize PDF job" };
}

async function runPdfWorkerTick() {
  if (!pdfWorkerRunning || pdfWorkerBusy) return;
  pdfWorkerBusy = true;
  try {
    await processOnePdfJob();
  } catch (err) {
    writeSyncLog({
      ts: new Date().toISOString(),
      level: "error",
      event: "pdf_worker_tick_error",
      error: err && err.message ? err.message : String(err),
    });
  } finally {
    pdfWorkerBusy = false;
    if (pdfWorkerRunning) {
      pdfWorkerTimer = setTimeout(runPdfWorkerTick, PDF_WORKER_POLL_MS);
    }
  }
}

function startPdfWorker(reason = "manual") {
  if (!ENABLE_PDF_WORKER || pdfWorkerRunning) return;
  pdfWorkerRunning = true;
  writeSyncLog({
    ts: new Date().toISOString(),
    level: "info",
    event: "pdf_worker_start",
    reason,
    pollMs: PDF_WORKER_POLL_MS,
  });
  pdfWorkerTimer = setTimeout(runPdfWorkerTick, PDF_WORKER_POLL_MS);
}

function stopPdfWorker(reason = "manual") {
  if (!pdfWorkerRunning && !pdfWorkerTimer) return;
  pdfWorkerRunning = false;
  if (pdfWorkerTimer) {
    clearTimeout(pdfWorkerTimer);
    pdfWorkerTimer = null;
  }
  writeSyncLog({
    ts: new Date().toISOString(),
    level: "info",
    event: "pdf_worker_stop",
    reason,
  });
}

function getPdfWorkerStatus() {
  return {
    enabled: ENABLE_PDF_WORKER,
    running: pdfWorkerRunning,
    busy: pdfWorkerBusy,
    pollMs: PDF_WORKER_POLL_MS,
    claimPath: PDF_JOB_CLAIM_PATH,
    backendBaseUrl: BACKEND_BASE_URL,
    hasIdToken: Boolean(currentIdToken),
    userUid: currentUserUid || null,
    companyId: resolveCompanyId() || null,
  };
}
function extractInvoicesFromTallyXML(xml, options = {}) {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@_",
    parseTagValue: true,
    trimValues: true,
  });
  const emptyStats = {
    voucherCount: 0,
    salesVoucherCount: 0,
    skippedNoCustomer: 0,
  };

  let json;
  try {
    json = parser.parse(xml);
  } catch (err) {
    console.error("Failed to parse Tally XML:", err.message);
    return options.withStats ? { invoices: [], stats: emptyStats } : [];
  }

  const body = json?.ENVELOPE?.BODY;
  if (!body) {
    return options.withStats ? { invoices: [], stats: emptyStats } : [];
  }

  // -----------------------------
  // Collect all VOUCHER nodes
  // -----------------------------
  const vouchers = [];

  const collect = (node) => {
    if (!node || typeof node !== "object") return;

    if (node.VOUCHER) {
      if (Array.isArray(node.VOUCHER)) vouchers.push(...node.VOUCHER);
      else vouchers.push(node.VOUCHER);
    }

    for (const key of Object.keys(node)) {
      const child = node[key];
      if (Array.isArray(child)) child.forEach(collect);
      else if (typeof child === "object") collect(child);
    }
  };

  collect(body);

  const stats = {
    voucherCount: vouchers.length,
    salesVoucherCount: 0,
    skippedNoCustomer: 0,
  };

  const invoices = [];

  const getVal = (obj, name) => {
    if (!obj) return null;
    if (obj[name] !== undefined) return obj[name];
    if (obj[`@_${name}`] !== undefined) return obj[`@_${name}`];
    if (obj["#text"] !== undefined) return obj["#text"];
    return null;
  };

  const toArray = (value) => {
    if (!value) return [];
    return Array.isArray(value) ? value : [value];
  };

  const parseAmountValue = (value) => {
    if (value === null || value === undefined || value === "") return 0;
    if (typeof value === "number") return Number.isFinite(value) ? value : 0;

    const raw = String(value).trim();
    if (!raw) return 0;

    const upper = raw.toUpperCase();
    const isCr = /\bCR\b/.test(upper);
    const isDr = /\bDR\b/.test(upper);
    const hasParens = raw.includes("(") && raw.includes(")");

    const numeric = raw
      .replace(/[(),]/g, "")
      .replace(/\bDR\b/gi, "")
      .replace(/\bCR\b/gi, "")
      .replace(/[^\d+-.]/g, "")
      .trim();

    const parsed = Number(numeric);
    if (!Number.isFinite(parsed)) return 0;

    if (hasParens || isCr) return -Math.abs(parsed);
    if (isDr) return Math.abs(parsed);
    return parsed;
  };

  const round2 = (num) => Math.round((Number(num) + Number.EPSILON) * 100) / 100;

  const parseCreditPeriodDays = (value) => {
    if (value === null || value === undefined) return null;
    const raw = String(value).trim();
    if (!raw) return null;

    const dayMatch = raw.match(/(-?\d+(?:\.\d+)?)\s*day/i);
    if (dayMatch) {
      const parsed = Number(dayMatch[1]);
      return Number.isFinite(parsed) ? Math.max(0, Math.round(parsed)) : null;
    }

    const plainNum = Number(raw);
    if (Number.isFinite(plainNum)) {
      return Math.max(0, Math.round(plainNum));
    }
    return null;
  };

  const parseDueDateYmd = (value) => {
    if (value === null || value === undefined) return null;
    const raw = String(value)
      .replace(/[()]/g, " ")
      .replace(/\s+/g, " ")
      .trim();
    if (!raw) return null;

    const ymd = normalizeDateToYmd(raw);
    if (ymd) return ymd;
    const m = raw.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})$/);
    if (m) {
      const dd = Number(m[1]);
      const mm = Number(m[2]);
      let yyyy = Number(m[3]);
      if (yyyy < 100) {
        yyyy += yyyy >= 70 ? 1900 : 2000;
      }
      if (!dd || !mm || !yyyy) return null;
      const d = new Date(yyyy, mm - 1, dd);
      if (isNaN(d.getTime())) return null;
      return formatYMDDate(d);
    }

    const monthMatch = raw.match(
      /^(\d{1,2})[-/. ]([A-Za-z]{3,9})[-/. ](\d{2,4})$/
    );
    if (monthMatch) {
      const dd = Number(monthMatch[1]);
      const monthRaw = monthMatch[2].toLowerCase();
      let yyyy = Number(monthMatch[3]);
      if (yyyy < 100) {
        yyyy += yyyy >= 70 ? 1900 : 2000;
      }
      const months = {
        jan: 0,
        january: 0,
        feb: 1,
        february: 1,
        mar: 2,
        march: 2,
        apr: 3,
        april: 3,
        may: 4,
        jun: 5,
        june: 5,
        jul: 6,
        july: 6,
        aug: 7,
        august: 7,
        sep: 8,
        sept: 8,
        september: 8,
        oct: 9,
        october: 9,
        nov: 10,
        november: 10,
        dec: 11,
        december: 11,
      };
      const mm = months[monthRaw];
      if (!dd || mm === undefined || !yyyy) return null;
      const d = new Date(yyyy, mm, dd);
      if (isNaN(d.getTime())) return null;
      return formatYMDDate(d);
    }

    return null;
  };

  const addDaysToYmd = (ymd, days) => {
    if (!ymd || !Number.isFinite(days)) return null;
    const y = Number(String(ymd).slice(0, 4));
    const m = Number(String(ymd).slice(4, 6)) - 1;
    const d = Number(String(ymd).slice(6, 8));
    const dt = new Date(y, m, d);
    if (isNaN(dt.getTime())) return null;
    dt.setDate(dt.getDate() + Math.round(days));
    return formatYMDDate(dt);
  };

  const extractBillTermsDeep = (node) => {
    const terms = {
      creditPeriodDays: null,
      dueDate: null,
    };

    const visit = (obj) => {
      if (!obj || typeof obj !== "object") return;

      if (terms.creditPeriodDays === null) {
        terms.creditPeriodDays = parseCreditPeriodDays(
          getVal(obj, "BILLCREDITPERIOD") ||
            getVal(obj, "CREDITPERIOD") ||
            getVal(obj, "BILLCREDITDAYS") ||
            getVal(obj, "CREDITDAYS")
        );
      }

      if (!terms.dueDate) {
        terms.dueDate = parseDueDateYmd(
          getVal(obj, "DUEDATE") ||
            getVal(obj, "BILLDUEDATE") ||
            getVal(obj, "EFFECTIVEDUEDATE")
        );
      }

      if (terms.creditPeriodDays !== null && terms.dueDate) return;

      for (const key of Object.keys(obj)) {
        const child = obj[key];
        if (Array.isArray(child)) {
          for (const c of child) visit(c);
        } else if (child && typeof child === "object") {
          visit(child);
        }
      }
    };

    visit(node);
    return terms;
  };

  // -----------------------------
  // Process each voucher
  // -----------------------------
  for (const v of vouchers) {
    const voucherType = String(
      getVal(v, "VOUCHERTYPENAME") || getVal(v, "VCHTYPE") || ""
    ).toUpperCase();

    // Accept only Sales, SALES GST, etc.
    if (!voucherType.includes("SALE")) continue;
    stats.salesVoucherCount += 1;

    const invoiceNo = getVal(v, "VOUCHERNUMBER")
      ? String(getVal(v, "VOUCHERNUMBER"))
      : null;

    const invoiceDate = getVal(v, "DATE")
      ? String(getVal(v, "DATE"))
      : null;

    const sourceId = getVal(v, "REMOTEID") || null;

    // Prefer explicit party fields from voucher.
    let customerName =
      getVal(v, "PARTYLEDGERNAME") ||
      getVal(v, "PARTYNAME") ||
      null;

    const ledgerRaw = v["ALLLEDGERENTRIES.LIST"];
    const ledgerEntries = Array.isArray(ledgerRaw)
      ? ledgerRaw
      : ledgerRaw
      ? [ledgerRaw]
      : [];

    let totalAmount = 0;
    let outstandingAmount = 0;
    let tdsAmount = 0;
    let tcsAmount = 0;
    let creditPeriodDays = null;
    let dueDate = null;
    let partyLedgerAmountAbs = 0;
    let partyOutstandingAmountAbs = 0;
    let fallbackNegativeTotal = 0;
    // -----------------------------
    // Fallback: detect party ledger ONLY if missing
    // -----------------------------
    // Customer may be set from ISPARTYLEDGER entry while iterating ledgers below.

    // -----------------------------
    // Totals & taxes
    // -----------------------------
    for (const e of ledgerEntries) {
      const ledgerName = getVal(e, "LEDGERNAME");
      const amount = parseAmountValue(getVal(e, "AMOUNT"));
      const upper = String(ledgerName || "").toUpperCase();
      const normalizedCustomerName = customerName
        ? String(customerName).trim().toUpperCase()
        : "";
      const isPartyFlag =
        String(getVal(e, "ISPARTYLEDGER") || "").toLowerCase() === "yes";
      const isPartyByName =
        normalizedCustomerName &&
        String(ledgerName || "")
          .trim()
          .toUpperCase() === normalizedCustomerName;
      const isPartyEntry = isPartyFlag || isPartyByName;

      if (!customerName && isPartyFlag && ledgerName) {
        customerName = ledgerName;
      }

      if (amount < 0) fallbackNegativeTotal += Math.abs(amount);
      if (isPartyEntry) {
        partyLedgerAmountAbs = Math.max(partyLedgerAmountAbs, Math.abs(amount));
      }
      if (upper.includes("TDS")) tdsAmount += Math.abs(amount);
      if (upper.includes("TCS")) tcsAmount += Math.abs(amount);

      const billAllocEntries = toArray(
        e["BILLALLOCATIONS.LIST"] || e.BILLALLOCATIONS
      );
      for (const b of billAllocEntries) {
        if (creditPeriodDays === null) {
          creditPeriodDays = parseCreditPeriodDays(
            getVal(b, "BILLCREDITPERIOD") ||
              getVal(b, "CREDITPERIOD") ||
              getVal(b, "BILLCREDITDAYS")
          );
        }
        if (!dueDate) {
          dueDate = parseDueDateYmd(
            getVal(b, "DUEDATE") ||
              getVal(b, "BILLDUEDATE") ||
              getVal(b, "DATE")
          );
        }

        if (isPartyEntry) {
          const billAmount = parseAmountValue(
            getVal(b, "AMOUNT") ||
              getVal(b, "BILLAMOUNT") ||
              getVal(b, "BILLCLOSING")
          );
          partyOutstandingAmountAbs += Math.abs(billAmount);
        }
      }

      const accountingAllocEntries = toArray(
        e["ACCOUNTINGALLOCATIONS.LIST"] || e.ACCOUNTINGALLOCATIONS
      );
      for (const a of accountingAllocEntries) {
        if (creditPeriodDays === null) {
          creditPeriodDays = parseCreditPeriodDays(
            getVal(a, "BILLCREDITPERIOD") ||
              getVal(a, "CREDITPERIOD") ||
              getVal(a, "BILLCREDITDAYS") ||
              getVal(a, "CREDITDAYS")
          );
        }
        if (!dueDate) {
          dueDate = parseDueDateYmd(
            getVal(a, "DUEDATE") ||
              getVal(a, "BILLDUEDATE") ||
              getVal(a, "EFFECTIVEDUEDATE")
          );
        }

        const nestedBillAlloc = toArray(
          a["BILLALLOCATIONS.LIST"] || a.BILLALLOCATIONS
        );
        for (const b of nestedBillAlloc) {
          if (creditPeriodDays === null) {
            creditPeriodDays = parseCreditPeriodDays(
              getVal(b, "BILLCREDITPERIOD") ||
                getVal(b, "CREDITPERIOD") ||
                getVal(b, "BILLCREDITDAYS") ||
                getVal(b, "CREDITDAYS")
            );
          }
          if (!dueDate) {
            dueDate = parseDueDateYmd(
              getVal(b, "DUEDATE") ||
                getVal(b, "BILLDUEDATE") ||
                getVal(b, "EFFECTIVEDUEDATE")
            );
          }

          if (isPartyEntry) {
            const billAmount = parseAmountValue(
              getVal(b, "AMOUNT") ||
                getVal(b, "BILLAMOUNT") ||
                getVal(b, "BILLCLOSING")
            );
            partyOutstandingAmountAbs += Math.abs(billAmount);
          }
        }
      }
    }

    if (creditPeriodDays === null) {
      creditPeriodDays = parseCreditPeriodDays(
        getVal(v, "BILLCREDITPERIOD") ||
          getVal(v, "CREDITPERIOD") ||
          getVal(v, "BILLCREDITDAYS")
      );
    }

    if (!dueDate) {
      dueDate = parseDueDateYmd(
        getVal(v, "DUEDATE") ||
          getVal(v, "BILLDUEDATE")
      );
    }

    if (creditPeriodDays === null || !dueDate) {
      const deepTerms = extractBillTermsDeep(v);
      if (creditPeriodDays === null) {
        creditPeriodDays = deepTerms.creditPeriodDays;
      }
      if (!dueDate) {
        dueDate = deepTerms.dueDate;
      }
    }

    if (!dueDate && creditPeriodDays !== null && invoiceDate) {
      dueDate = addDaysToYmd(invoiceDate, creditPeriodDays);
    }

    if (!customerName) {
      stats.skippedNoCustomer += 1;
      console.warn(
        "Skipping voucher (no PARTYLEDGERNAME):",
        invoiceNo
      );
      continue;
    }

    // -----------------------------
    // Inventory items
    // -----------------------------
    const invRaw = v["ALLINVENTORYENTRIES.LIST"];
    const inventoryEntries = Array.isArray(invRaw)
      ? invRaw
      : invRaw
      ? [invRaw]
      : [];

    const items = inventoryEntries.map((i) => ({
      itemName: getVal(i, "STOCKITEMNAME") || null,
      quantity: getVal(i, "BILLEDQTY") || null,
      rate: getVal(i, "RATE") || null,
      amount: parseAmountValue(getVal(i, "AMOUNT")),
    }));

    const itemsTotalAbs = round2(
      items.reduce((sum, item) => sum + Math.abs(parseAmountValue(item.amount)), 0)
    );
    const voucherTotalAbs = Math.abs(
      parseAmountValue(
        getVal(v, "VOUCHERTOTAL") ||
          getVal(v, "NETAMOUNT") ||
          getVal(v, "AMOUNT")
      )
    );

    if (partyLedgerAmountAbs > 0) {
      totalAmount = partyLedgerAmountAbs;
    } else if (voucherTotalAbs > 0) {
      totalAmount = voucherTotalAbs;
    } else if (itemsTotalAbs > 0) {
      totalAmount = itemsTotalAbs;
    } else {
      totalAmount = fallbackNegativeTotal;
    }

    if (partyOutstandingAmountAbs > 0) {
      outstandingAmount = partyOutstandingAmountAbs;
    } else if (partyLedgerAmountAbs > 0) {
      outstandingAmount = partyLedgerAmountAbs;
    } else {
      // Conservative fallback when Tally doesn't provide bill allocations.
      outstandingAmount = totalAmount;
    }

    totalAmount = round2(totalAmount);
    outstandingAmount = round2(outstandingAmount);
    tdsAmount = round2(tdsAmount);
    tcsAmount = round2(tcsAmount);

    if (Math.abs(totalAmount) < 0.01) totalAmount = 0;
    if (Math.abs(outstandingAmount) < 0.01) outstandingAmount = 0;

    const invoiceStatus =
      outstandingAmount <= 0
        ? "PAID"
        : totalAmount > 0 && outstandingAmount < totalAmount
        ? "PARTIALLY_PAID"

        : "UNPAID";

    invoices.push({
      source: "TALLY",
      sourceId,
      invoiceNo,
      invoiceDate,
      customerName,
      totalAmount,
      outstandingAmount,
      tdsAmount: tdsAmount || null,
      tcsAmount: tcsAmount || null,
      creditPeriodDays: creditPeriodDays !== null ? creditPeriodDays : null,
      dueDate: dueDate || null,
      invoiceStatus,
      items,
      lastSyncedAt: new Date().toISOString(),
    });
  }

  return options.withStats ? { invoices, stats } : invoices;
}
// -----------------------------
// Multi-method sync: LIVE | FOLDER
// -----------------------------
const SYNC_METHODS = { LIVE: 'LIVE', FOLDER: 'FOLDER' };
let selectedSyncMethod = null;

ipcMain.handle('set-sync-method', async (event, data) => {
  const m = (data?.method || '').toString().toUpperCase();
  if (!Object.values(SYNC_METHODS).includes(m)) {
    return { status: 'error', message: 'Invalid sync method' };
  }
  selectedSyncMethod = m;
  return { status: 'ok', method: selectedSyncMethod };
});

ipcMain.handle('start-sync', async (event, data) => {
  if (!selectedSyncMethod) return { status: 'error', message: 'No sync method selected' };

  if (selectedSyncMethod === SYNC_METHODS.LIVE) {
    const isFullSync = Boolean(data && data.forceFullSync);
    const syncId = createSyncId();
    writeSyncLog({
      ts: new Date().toISOString(),
      level: "info",
      event: "sync_start",
      syncId,
      method: "LIVE",
      mode: isFullSync ? "full" : "incremental",
    });

    try {
      await ensureFreshIdToken();
      const companyId = resolveCompanyId();
      const companyHint = resolveTallyCompanyHint();

      const tallyResult = await fetchSalesVouchersFromTally({
        modeOverride: isFullSync ? "full" : null,
        companyHint,
      });
      const xml = tallyResult.xml || "";
      const meta = tallyResult.meta || {};
      const { invoices, stats } = extractInvoicesFromTallyXML(xml, {
        withStats: true,
      });
      const diagnostics = computeInvoiceDiagnostics(invoices);
      writeSyncLog({
        ts: new Date().toISOString(),
        level: "info",
        event: "tally_fetch_complete",
        syncId,
        ...meta,
      });
      writeSyncLog({
        ts: new Date().toISOString(),
        level: "info",
        event: "invoice_extract",
        syncId,
        ...stats,
        ...diagnostics,
      });
      
      if (invoices.length === 0) {
        return { status: 'warning', message: 'No Sales invoices found', count: 0 };
      }
      
      await sendInvoicesToBackend(invoices, { companyId, syncId });
      writeSyncLog({
        ts: new Date().toISOString(),
        level: "info",
        event: "backend_success",
        syncId,
        invoiceCount: invoices.length,
      });
      const checkpointCompany =
        normalizeCompanyName(meta.detectedCompany) ||
        normalizeCompanyName(meta.requestedCompany) ||
        companyHint ||
        null;
      saveLastSyncAt(new Date().toISOString(), { companyName: checkpointCompany });
      return { status: 'ok', method: SYNC_METHODS.LIVE, count: invoices.length };
    } catch (err) {
      console.error('LIVE sync error:', err && err.message);
      writeSyncLog({
        ts: new Date().toISOString(),
        level: "error",
        event: "sync_error",
        syncId: syncId || null,
        error: err && err.message,
      });
      
      // User-friendly errors
      let msg = err && err.message;
      if (msg && msg.includes('ECONNREFUSED')) {
        msg = 'Cannot connect to Tally. Is Tally Prime running?';
      } else if (msg && msg.toLowerCase().includes('timed out')) {
        msg = 'Tally did not respond in time. Please try again.';
      }
      return { status: 'error', message: msg };
    }
  }

  if (selectedSyncMethod === SYNC_METHODS.FOLDER) {
    return { status: 'ok', method: SYNC_METHODS.FOLDER, message: 'Folder watching started. Drop XML files in C:\\Giropie\\Imports' };
  }

  return { status: 'error', message: 'Unsupported sync method' };
});

ipcMain.handle('stop-folder-import', async () => {
  return { status: 'ok', stopped: true };
});

// -----------------------------
// IPC: UI helpers (safe read-only)
// -----------------------------
ipcMain.handle("get-auth-status", async () => {
  return getAuthStatusSnapshot();
});

ipcMain.handle("get-last-sync-summary", async () => {
  return readLastSyncSummary();
});

ipcMain.handle("get-sync-window-preview", async (event, data) => {
  try {
    return { status: "ok", preview: getSyncWindowPreview(data || {}) };
  } catch (err) {
    return { status: "error", message: err.message };
  }
});

ipcMain.handle("get-pdf-worker-status", async () => {
  return { status: "ok", worker: getPdfWorkerStatus() };
});

ipcMain.handle("run-pdf-worker-once", async () => {
  try {
    const result = await processOnePdfJob();
    return { status: "ok", result };
  } catch (err) {
    return { status: "error", message: err.message };
  }
});

ipcMain.handle("logout", async () => {
  try {
    stopPdfWorker("logout");
    try {
      await firebase.auth().signOut();
    } catch (e) {}

    currentIdToken = null;
    currentRefreshToken = null;
    currentTokenExpiry = null;
    currentCompanyId = null;
    currentUserUid = null;
    currentUserEmail = null;

    try {
      if (fs.existsSync(tokenFilePath)) {
        fs.unlinkSync(tokenFilePath);
      }
    } catch (err) {
      // ignore delete failures
    }

    return { status: "ok" };
  } catch (err) {
    return { status: "error", message: err.message };
  }
});
