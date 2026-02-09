// preload.js - runs in a privileged context before the renderer loads
// Exposes a minimal, secure API to the renderer via contextBridge

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Login
  login: (email, password) => ipcRenderer.invoke('login', { email, password }),
  // Set sync method (LIVE or FOLDER)
  setSyncMethod: (method) => ipcRenderer.invoke('set-sync-method', { method }),
  // Start sync (uses chosen method)
  startSync: () => ipcRenderer.invoke('start-sync'),
  // Stop folder watcher
  stopFolderImport: () => ipcRenderer.invoke('stop-folder-import'),
  // Legacy sync (still works)
  syncFromTally: () => ipcRenderer.invoke('sync-from-tally'),
  // UI helpers
  getAuthStatus: () => ipcRenderer.invoke('get-auth-status'),
  getLastSyncSummary: () => ipcRenderer.invoke('get-last-sync-summary'),
  // Logout
  logout: () => ipcRenderer.invoke('logout')
});
