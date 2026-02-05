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
  try {
    if (fs.existsSync(tokenFilePath)) {
      const raw = fs.readFileSync(tokenFilePath, "utf-8");
      const data = JSON.parse(raw);
      if (data?.idToken) {
        currentIdToken = data.idToken;
        console.log("Auth token loaded from disk");
      }
    }
  } catch (err) {
    console.error("Failed to load auth token:", err.message);
  }

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
  return await userCredential.user.getIdToken();
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
    const idToken = await signInWithEmailPassword(email, password);
    currentIdToken = idToken;

    fs.writeFileSync(
      tokenFilePath,
      JSON.stringify({ idToken, savedAt: new Date().toISOString() }, null, 2),
      "utf-8"
    );

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

    const toDate = new Date();
    const fromDate = new Date();
    fromDate.setDate(toDate.getDate() - 30);

    const SVFROMDATE = formatYMD(fromDate);
    const SVTODATE = formatYMD(toDate);

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
      'Voucher Register',
      'Vouchers',
      'Voucher Register (Sales)',
      'Day Book'
    ];

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
            'Content-Length': Buffer.byteLength(xml),
          }),
        });

        console.log('SENDING XML TO TALLY (len:', Buffer.byteLength(xml), '):\n', xml);

        const req = http.request(opts, (res) => {
          let data = '';
          console.log('TALLY RESPONSE STATUS:', res.statusCode);
          console.log('TALLY RESPONSE HEADERS:', res.headers);
          res.on('data', (c) => (data += c.toString()));
          res.on('end', () => {
            console.log('TALLY RESPONSE BODY (first 2000 chars):', data.substring(0, 2000));
            resOut(data);
          });
        });

        req.on('error', rejOut);
        req.write(xml);
        req.end();
      });

    (async () => {
      for (const r of tryReports) {
        try {
          const xml = buildXml(r);
          const resp = await sendXml(xml);
          // quick heuristic: check if response contains <VOUCHER
          if (resp && resp.includes('<VOUCHER')) return resolve(resp);
        } catch (err) {
          console.error('Tally request failed for report', r, err && err.message);
        }
      }

      // If none returned vouchers, send the last response (or an empty string)
      try {
        const last = buildXml(tryReports[0]);
        const fallback = await sendXml(last);
        return resolve(fallback);
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

  if (!currentIdToken) {
    return { status: "error", message: "Not logged in" };
  }

  try {
    const xml = await fetchSalesVouchersFromTally();
    console.log("TALLY XML RECEIVED:\n", xml.substring(0, 300));

    const invoices = extractInvoicesFromTallyXML(xml);
    console.log("EXTRACTED INVOICES:", invoices);

    await sendInvoicesToBackend(invoices);
    return { status: "ok", count: invoices.length };
  } catch (err) {
    console.error("TALLY ERROR:", err.message);
    return { status: "error", message: err.message };
  }
});

function sendInvoicesToBackend(invoices) {
  return new Promise((resolve, reject) => {
 const body = JSON.stringify({
  companyId: "demo-company-001", // TEMP HARDCODE
  invoices,
});
   const req = https.request(
  BACKEND_SYNC_URL,
  {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${currentIdToken}`,
      "Content-Length": Buffer.byteLength(body),
    },
  },
  (res) => {
    let data = "";
    res.on("data", (c) => (data += c.toString()));
    res.on("end", () => resolve(data));
  }
);

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}




  function extractInvoicesFromTallyXML(xml) {
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

  return invoices;
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
    if (!currentIdToken) return { status: 'error', message: 'Please login first' };
    try {
      const xml = await fetchSalesVouchersFromTally();
      const invoices = extractInvoicesFromTallyXML(xml);
      
      if (invoices.length === 0) {
        return { status: 'warning', message: 'No Sales invoices found', count: 0 };
      }
      
      await sendInvoicesToBackend(invoices);
      return { status: 'ok', method: SYNC_METHODS.LIVE, count: invoices.length };
    } catch (err) {
      console.error('LIVE sync error:', err && err.message);
      
      // User-friendly errors
      let msg = err && err.message;
      if (msg && msg.includes('ECONNREFUSED')) {
        msg = 'Cannot connect to Tally. Is Tally Prime running?';
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