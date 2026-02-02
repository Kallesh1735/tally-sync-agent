// preload.js - runs in a privileged context before the renderer loads
// Exposes a minimal, secure API to the renderer via contextBridge

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Calls the main process and returns a promise with the response
  syncFromTally: () => ipcRenderer.invoke('sync-from-tally'),
  // Send login request (email/password) to main process. Returns a promise.
  login: (email, password) => ipcRenderer.invoke('login', { email, password })
});
