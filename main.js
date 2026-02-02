 // main.js
// Electron main process
// - Creates app window
// - Handles Firebase login + token persistence
// - Fetches Sales Vouchers (Invoices) from Tally on Sync
console.log("USING MAIN.JS FROM:", __filename);

const { XMLParser } = require("fast-xml-parser");

// Production Firebase Functions URL (HTTPS)
const BACKEND_SYNC_URL =
  "https://us-central1-giropie-frontend.cloudfunctions.net/syncTally";

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
  // Use attribute prefix so attributes don't collide with child nodes
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
    console.error("Failed to parse Tally XML:", err && err.message);
    return [];
  }

  // Tally can place TALLYMESSAGE (and VOUCHER) in many nested locations.
  // Collect all VOUCHER nodes recursively under the BODY so we don't miss them.
  const body = json?.ENVELOPE?.BODY || {};

  const vouchers = [];

  const collectVouchers = (node) => {
    if (!node || typeof node !== 'object') return;

    // If this node directly contains VOUCHER or an array of VOUCHERs
    if (node.VOUCHER) {
      if (Array.isArray(node.VOUCHER)) vouchers.push(...node.VOUCHER);
      else vouchers.push(node.VOUCHER);
    }

    // If node itself is a VOUCHER entry
    if (node['VOUCHER.TALLY'] || node['VOUCHER']) {
      // handled above
    }

    // Recurse into all child properties
    for (const k of Object.keys(node)) {
      const child = node[k];
      if (Array.isArray(child)) {
        for (const c of child) collectVouchers(c);
      } else if (child && typeof child === 'object') {
        collectVouchers(child);
      }
    }
  };

  collectVouchers(body);

  console.log('FOUND VOUCHERS (after recursive search):', vouchers.length);
  if (vouchers.length === 0) return [];

  const invoices = [];

  const getVal = (obj, name) => {
    if (!obj) return null;
    if (obj[name] !== undefined) return obj[name];
    if (obj[`@_${name}`] !== undefined) return obj[`@_${name}`];
    // sometimes the value is held in '#text'
    if (obj['#text'] !== undefined) return obj['#text'];
    return null;
  };

  for (const msg of vouchers) {
    const v = msg.VOUCHER || msg;
    const vType = getVal(v, 'VOUCHERTYPENAME');
    if (!v || vType !== 'Sales') continue;

    // ---------- Core identity ----------
    const sourceId = getVal(v, 'REMOTEID') || null;
    const invoiceNo = getVal(v, 'VOUCHERNUMBER') ? String(getVal(v, 'VOUCHERNUMBER')) : null;
    const invoiceDate = getVal(v, 'DATE') ? String(getVal(v, 'DATE')) : null;

    // ---------- Ledger processing ----------
    const ledgerRaw = v["ALLLEDGERENTRIES.LIST"] || v["ALLLEDGERENTRIES.LIST"];
    const ledgerEntries = Array.isArray(ledgerRaw) ? ledgerRaw : ledgerRaw ? [ledgerRaw] : [];

    let customerName = null;
    let totalAmount = 0;
    let outstandingAmount = 0;
    let tdsAmount = 0;
    let tcsAmount = 0;

    for (const e of ledgerEntries) {
      const ledgerName = getVal(e, 'LEDGERNAME');
      const amount = Number(getVal(e, 'AMOUNT') || 0);

      // Party ledger (value can be attribute or tag)
      const isParty = String(getVal(e, 'ISPARTYLEDGER') || '').toLowerCase() === 'yes';
      if (isParty) {
        customerName = ledgerName;
        outstandingAmount = Math.abs(amount);
        continue;
      }

      if (amount > 0) totalAmount += amount;

      if (ledgerName && String(ledgerName).toUpperCase().includes('TDS')) {
        tdsAmount += Math.abs(amount);
      }

      if (ledgerName && String(ledgerName).toUpperCase().includes('TCS')) {
        tcsAmount += Math.abs(amount);
      }
    }

    // ---------- Credit & due ----------
    let creditPeriodDays = null;
    const creditRaw = getVal(v, 'CREDITPERIOD');
    if (creditRaw) {
      const match = String(creditRaw).match(/\d+/);
      if (match) creditPeriodDays = Number(match[0]);
    }

    let dueDate = null;
    if (invoiceDate && creditPeriodDays !== null) {
      const y = Number(invoiceDate.slice(0, 4));
      const m = Number(invoiceDate.slice(4, 6)) - 1;
      const d = Number(invoiceDate.slice(6, 8));
      const baseDate = new Date(y, m, d);
      baseDate.setDate(baseDate.getDate() + creditPeriodDays);
      dueDate = baseDate.toISOString().slice(0, 10);
    }

    // ---------- Status ----------
    let invoiceStatus = "UNPAID";
    if (outstandingAmount === 0) invoiceStatus = "PAID";
    else if (outstandingAmount < totalAmount)
      invoiceStatus = "PARTIALLY_PAID";

    // ---------- Items ----------
    const invRaw = v["ALLINVENTORYENTRIES.LIST"] || v["ALLINVENTORYENTRIES.LIST"];
    const inventoryEntries = Array.isArray(invRaw) ? invRaw : invRaw ? [invRaw] : [];

    const items = inventoryEntries.map((i) => ({
      itemName: getVal(i, 'STOCKITEMNAME') || null,
      quantity: getVal(i, 'BILLEDQTY') || null,
      rate: getVal(i, 'RATE') || null,
      amount: Number(getVal(i, 'AMOUNT') || 0),
    }));

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
      creditPeriodDays,
      dueDate,
      invoiceStatus,
      items,
      lastSyncedAt: new Date().toISOString(),
    });
  }

  return invoices;
}