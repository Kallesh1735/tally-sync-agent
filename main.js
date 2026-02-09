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
  `SYNC_OVERLAP_DAYS=${SYNC_OVERLAP_DAYS}`
);

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
const lastSyncFilePath = path.join(app.getPath("userData"), "lastSync.json");

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function loadLastSyncState() {
  try {
    if (!fs.existsSync(lastSyncFilePath)) return null;
    const raw = fs.readFileSync(lastSyncFilePath, "utf-8");
    const data = JSON.parse(raw);
    return data && typeof data === "object" ? data : null;
  } catch (err) {
    return null;
  }
}

function saveLastSyncAt(isoString) {
  try {
    const payload = {
      uid: currentUserUid || null,
      lastSyncAt: isoString,
      savedAt: new Date().toISOString(),
    };
    fs.writeFileSync(lastSyncFilePath, JSON.stringify(payload, null, 2), "utf-8");
  } catch (err) {
    console.error("Failed to save last sync time:", err.message);
  }
}

function computeSyncWindow() {
  const now = new Date();
  const lastSyncState = loadLastSyncState();
  const lastSyncAt =
    lastSyncState &&
    lastSyncState.lastSyncAt &&
    (!lastSyncState.uid || lastSyncState.uid === currentUserUid)
      ? new Date(lastSyncState.lastSyncAt)
      : null;

  if (SYNC_MODE === "incremental" && lastSyncAt && !isNaN(lastSyncAt.getTime())) {
    const fromDate = new Date(lastSyncAt);
    fromDate.setDate(fromDate.getDate() - SYNC_OVERLAP_DAYS);
    return {
      mode: "incremental",
      fromDate,
      toDate: now,
      lastSyncAt: lastSyncState.lastSyncAt,
      overlapDays: SYNC_OVERLAP_DAYS,
    };
  }

  const fromDate = new Date(now);
  fromDate.setDate(fromDate.getDate() - SYNC_LOOKBACK_DAYS);
  return {
    mode: SYNC_MODE,
    fromDate,
    toDate: now,
    lookbackDays: SYNC_LOOKBACK_DAYS,
    lastSyncAt: lastSyncState ? lastSyncState.lastSyncAt : null,
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
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
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
function fetchSalesVouchersFromTally() {
  return new Promise((resolve, reject) => {
    // Build a reasonable default date range (last 30 days) to avoid empty future ranges
    const formatYMD = (d) => {
      const y = d.getFullYear();
      const m = String(d.getMonth() + 1).padStart(2, "0");
      const day = String(d.getDate()).padStart(2, "0");
      return `${y}${m}${day}`;
    };

    const syncWindow = computeSyncWindow();
    const SVFROMDATE = formatYMD(syncWindow.fromDate);
    const SVTODATE = formatYMD(syncWindow.toDate);

    // Allow overriding company name via env var when debugging; default to existing value
    const companyName = process.env.TALLY_COMPANY || "Giropie Pvt and Ltd";

    console.log("Date range:", SVFROMDATE, "to", SVTODATE);
    console.log("Company:", companyName);

    const buildXml = (reportName) => `
<ENVELOPE>
  <HEADER>
    <TALLYREQUEST>Export Data</TALLYREQUEST>
  </HEADER>
  <BODY>
    <EXPORTDATA>
      <REQUESTDESC>
        <REPORTNAME>${reportName}</REPORTNAME>
        <STATICVARIABLES>
          <SVCURRENTCOMPANY>${companyName}</SVCURRENTCOMPANY>
          <SVFROMDATE>${SVFROMDATE}</SVFROMDATE>
          <SVTODATE>${SVTODATE}</SVTODATE>
          <SVEXPORTFORMAT>$$SysName:XML</SVEXPORTFORMAT>
        </STATICVARIABLES>
      </REQUESTDESC>
    </EXPORTDATA>
  </BODY>
</ENVELOPE>
`;

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
      syncMode: syncWindow.mode,
      lastSyncAt: syncWindow.lastSyncAt || null,
      lookbackDays: syncWindow.lookbackDays || null,
      overlapDays: syncWindow.overlapDays || null,
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

        console.log(
          "SENDING XML TO TALLY (len:",
          Buffer.byteLength(xml),
          "):\n",
          xml
        );

        const req = http.request(opts, (res) => {
          let data = "";
          console.log("TALLY RESPONSE STATUS:", res.statusCode);
          console.log("TALLY RESPONSE HEADERS:", res.headers);
          res.on('data', (c) => (data += c.toString()));
          res.on('end', () => {
            clearTimeout(timeoutHandle);
            console.log(
              "TALLY RESPONSE BODY (first 2000 chars):",
              data.substring(0, 2000)
            );
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

      for (const r of tryReports) {
        try {
          const xml = buildXml(r);
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
                selectedReport: r,
                responseStatus: resp.statusCode,
                responseBytes: Buffer.byteLength(resp.data || ""),
                responseHasVoucher: true,
              },
            });
          }
        } catch (err) {
          console.error("Tally request failed for report", r, err && err.message);
        }
      }

      // If none returned vouchers, send the last response (or an empty string)
      try {
        if (lastResponse) {
          return resolve({
            xml: lastResponse.data || "",
            meta: {
              ...metaBase,
              selectedReport: lastReport || tryReports[0],
              responseStatus: lastResponse.statusCode,
              responseBytes: Buffer.byteLength(lastResponse.data || ""),
              responseHasVoucher: false,
            },
          });
        }

        const last = buildXml(tryReports[0]);
        const fallback = await sendXmlWithRetry(last, tryReports[0]);
        return resolve({
          xml: fallback.data || "",
          meta: {
            ...metaBase,
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

    const tallyResult = await fetchSalesVouchersFromTally();
    const xml = tallyResult.xml || "";
    const meta = tallyResult.meta || {};
    console.log("TALLY XML RECEIVED:\n", xml.substring(0, 300));
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
    console.log("EXTRACTED INVOICES:", invoices);
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
    saveLastSyncAt(new Date().toISOString());
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




  function extractInvoicesFromTallyXML(xml, options = {}) {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@_",
    parseTagValue: true,
    trimValues: true,
  });

  let json;
  try {
    json = parser.parse(xml);
  } catch (err) {
    console.error("Failed to parse Tally XML:", err.message);
    return [];
  }

  const body = json?.ENVELOPE?.BODY;
  if (!body) return [];

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

  console.log("FOUND VOUCHERS:", vouchers.length);

  const invoices = [];

  const getVal = (obj, name) => {
    if (!obj) return null;
    if (obj[name] !== undefined) return obj[name];
    if (obj[`@_${name}`] !== undefined) return obj[`@_${name}`];
    if (obj["#text"] !== undefined) return obj["#text"];
    return null;
  };

  // -----------------------------
  // Process each voucher
  // -----------------------------
  for (const v of vouchers) {
    const voucherType =
      String(getVal(v, "VOUCHERTYPENAME") || getVal(v, "VCHTYPE") || "")
        .toUpperCase();

    // ✅ Accept Sales, SALES GST, etc.
    if (!voucherType.includes("SALE")) continue;
    stats.salesVoucherCount += 1;

    const invoiceNo = getVal(v, "VOUCHERNUMBER")
      ? String(getVal(v, "VOUCHERNUMBER"))
      : null;

    const invoiceDate = getVal(v, "DATE")
      ? String(getVal(v, "DATE"))
      : null;

    const sourceId = getVal(v, "REMOTEID") || null;

    // ✅ MOST IMPORTANT LINE (THIS FIXES ABC)
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

    // -----------------------------
    // Fallback: detect party ledger ONLY if missing
    // -----------------------------
    if (!customerName) {
      for (const e of ledgerEntries) {
        const ledgerName = getVal(e, "LEDGERNAME");
        const amount = Number(getVal(e, "AMOUNT") || 0);
        const isParty =
          String(getVal(e, "ISPARTYLEDGER") || "").toLowerCase() === "yes";

        if (isParty && ledgerName) {
          customerName = ledgerName;
          outstandingAmount = Math.abs(amount);
          break;
        }
      }
    }

    // -----------------------------
    // Totals & taxes
    // -----------------------------
    for (const e of ledgerEntries) {
      const ledgerName = getVal(e, "LEDGERNAME");
      const amount = Number(getVal(e, "AMOUNT") || 0);
      const upper = String(ledgerName || "").toUpperCase();

      if (amount < 0) totalAmount += Math.abs(amount);
      if (upper.includes("TDS")) tdsAmount += Math.abs(amount);
      if (upper.includes("TCS")) tcsAmount += Math.abs(amount);
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
      amount: Number(getVal(i, "AMOUNT") || 0),
    }));

    const invoiceStatus =
      outstandingAmount === 0
        ? "PAID"
        : outstandingAmount < totalAmount
        ? "PARTIALLY_PAID"

        : "UNPAID";
    console.log(
      "FINAL CUSTOMER:",
      customerName,
      "Invoice:",
      invoiceNo
    );

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
      invoiceStatus,
      items,
      lastSyncedAt: new Date().toISOString(),
    });
  }

  return options.withStats ? { invoices, stats } : invoices;
}


  // Print all extracted customer names for debug
  

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

ipcMain.handle('start-sync', async () => {
  if (!selectedSyncMethod) return { status: 'error', message: 'No sync method selected' };

  if (selectedSyncMethod === SYNC_METHODS.LIVE) {
    const syncId = createSyncId();
    writeSyncLog({
      ts: new Date().toISOString(),
      level: "info",
      event: "sync_start",
      syncId,
      method: "LIVE",
    });

    try {
      await ensureFreshIdToken();
      const companyId = resolveCompanyId();

      const tallyResult = await fetchSalesVouchersFromTally();
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
      saveLastSyncAt(new Date().toISOString());
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

ipcMain.handle("logout", async () => {
  try {
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
