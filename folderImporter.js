const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const DEFAULTS = {
  importsDir: 'C:\\Giropie\\Imports',
  processedDir: 'C:\\Giropie\\Processed',
  failedDir: 'C:\\Giropie\\Failed',
  stableCheckIntervalMs: 500,
  stableCheckRepeats: 2,
  fileProcessTimeoutMs: 30_000,
  concurrency: 2,
};

function ensureDir(dir) {
  return fsp.mkdir(dir, { recursive: true });
}

async function moveFileAtomic(src, dest) {
  try {
    await ensureDir(path.dirname(dest));
    await fsp.rename(src, dest);
  } catch (err) {
    // fallback copy & unlink for cross-device moves
    if (err.code === 'EXDEV' || err.code === 'EPERM' || err.code === 'EINVAL') {
      await fsp.copyFile(src, dest);
      await fsp.unlink(src);
    } else {
      throw err;
    }
  }
}

function isXmlFile(filename) {
  return typeof filename === 'string' && filename.toLowerCase().endsWith('.xml');
}

function wait(ms) {
  return new Promise((res) => setTimeout(res, ms));
}

async function waitForFileStable(filePath, opts = {}) {
  const { stableCheckIntervalMs, stableCheckRepeats, fileProcessTimeoutMs } = opts;
  const start = Date.now();
  let lastSize = -1;
  let stableCount = 0;

  while (Date.now() - start < fileProcessTimeoutMs) {
    try {
      const stats = await fsp.stat(filePath);
      const size = stats.size;
      if (size === lastSize) {
        stableCount += 1;
        if (stableCount >= stableCheckRepeats) return;
      } else {
        stableCount = 0;
        lastSize = size;
      }
    } catch (err) {
      // file might not be visible yet
      stableCount = 0;
      lastSize = -1;
    }
    await wait(stableCheckIntervalMs);
  }

  throw new Error(`timeout waiting for file to stabilize: ${filePath}`);
}

function createFolderImporter({
  extractInvoicesFromTallyXML,
  sendInvoicesToBackend,
  logger = console,
  options = {},
} = {}) {
  if (typeof extractInvoicesFromTallyXML !== 'function') {
    throw new TypeError('extractInvoicesFromTallyXML must be provided');
  }
  if (typeof sendInvoicesToBackend !== 'function') {
    throw new TypeError('sendInvoicesToBackend must be provided');
  }

  const cfg = Object.assign({}, DEFAULTS, options);
  const importsDir = path.resolve(cfg.importsDir);
  const processedDir = path.resolve(cfg.processedDir);
  const failedDir = path.resolve(cfg.failedDir);

  let watcher = null;
  const processing = new Set();
  const queue = [];
  let running = 0;
  let stopped = false;

  async function processNext() {
    if (running >= cfg.concurrency) return;
    const item = queue.shift();
    if (!item) return;
    running += 1;
    const { filePath, filename } = item;
    const destProcessed = path.join(processedDir, filename);
    const destFailed = path.join(failedDir, filename);

    try {
      await waitForFileStable(filePath, cfg);
      const xml = await fsp.readFile(filePath, 'utf8');
      const invoices = await extractInvoicesFromTallyXML(xml);
      await sendInvoicesToBackend(invoices);
      await moveFileAtomic(filePath, destProcessed);
      logger.info && logger.info('Processed and moved', filename);
    } catch (err) {
      logger.error && logger.error('Failed processing', filename, err && err.message);
      try {
        // Attempt to move to failed dir
        await moveFileAtomic(filePath, destFailed);
      } catch (moveErr) {
        logger.error && logger.error('Failed moving to failed dir', filename, moveErr && moveErr.message);
      }
    } finally {
      processing.delete(filePath);
      running -= 1;
      // Continue processing queued items
      if (!stopped) setImmediate(processNext);
    }
  }

  function enqueue(filePath) {
    if (processing.has(filePath)) return;
    processing.add(filePath);
    const filename = path.basename(filePath);
    queue.push({ filePath, filename });
    setImmediate(processNext);
  }

  async function scanExisting() {
    try {
      const entries = await fsp.readdir(importsDir);
      for (const name of entries) {
        if (!isXmlFile(name)) continue;
        const filePath = path.join(importsDir, name);
        enqueue(filePath);
      }
    } catch (err) {
      if (err.code === 'ENOENT') {
        await ensureDir(importsDir);
      } else {
        logger.error && logger.error('scanExisting error', err && err.message);
      }
    }
  }

  function start() {
    stopped = false;
    // ensure directories exist
    ensureDir(importsDir).catch(() => {});
    ensureDir(processedDir).catch(() => {});
    ensureDir(failedDir).catch(() => {});

    // initial scan
    scanExisting().catch((e) => logger.error && logger.error('initial scan failed', e && e.message));

    try {
      watcher = fs.watch(importsDir, { persistent: true }, (eventType, filename) => {
        if (!filename) return;
        if (!isXmlFile(filename)) return;
        const filePath = path.join(importsDir, filename);
        // Debounce: small delay to allow multiple events to coalesce
        setTimeout(() => {
          // check file still exists before enqueue
          fsp.stat(filePath).then(() => enqueue(filePath)).catch(() => {});
        }, 300);
      });
    } catch (err) {
      logger.error && logger.error('watcher start failed', err && err.message);
    }
  }

  function stop() {
    stopped = true;
    if (watcher) {
      try {
        watcher.close();
      } catch (e) {}
      watcher = null;
    }
  }

  return { start, stop };
}

module.exports = { createFolderImporter };
