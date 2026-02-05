// renderer.js - UI flow for Login -> Method Selection -> Sync

function showScreen(id) {
  ['screen-login', 'screen-method', 'screen-sync'].forEach((s) => {
    const el = document.getElementById(s);
    if (el) el.style.display = s === id ? '' : 'none';
  });
}

document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const emailInput = document.getElementById('email');
  const passInput = document.getElementById('password');
  const loginBtn = document.getElementById('loginBtn');
  const loginMsg = document.getElementById('loginMsg');

  const methodLiveBtn = document.getElementById('method-live');
  const methodFolderBtn = document.getElementById('method-folder');
  const methodBackBtn = document.getElementById('method-back-to-login');

  const selectedMethodText = document.getElementById('selectedMethodText');
  const startSyncBtn = document.getElementById('startSyncBtn');
  const changeMethodBtn = document.getElementById('changeMethodBtn');
  const syncMsg = document.getElementById('syncMsg');

  let chosenMethod = null;

  // Initial view
  showScreen('screen-login');

  // Login
  if (loginBtn) {
    loginBtn.addEventListener('click', async () => {
      const email = emailInput.value;
      const password = passInput.value;
      loginMsg.className = 'msg';
      loginMsg.textContent = 'Logging in...';
      try {
        const res = await window.electronAPI.login(email, password);
        if (res && res.status === 'ok') {
          loginMsg.className = 'msg msg-success';
          loginMsg.textContent = 'Login successful!';
          setTimeout(() => showScreen('screen-method'), 500);
        } else {
          loginMsg.className = 'msg msg-error';
          loginMsg.textContent = res && res.message ? res.message : 'Login failed';
        }
      } catch (err) {
        loginMsg.className = 'msg msg-error';
        loginMsg.textContent = 'Login error';
        console.error('Login IPC error:', err);
      }
    });
  }

  // Method selection
  if (methodLiveBtn) {
    methodLiveBtn.addEventListener('click', async () => {
      const res = await window.electronAPI.setSyncMethod('LIVE');
      if (res && res.status === 'ok') {
        chosenMethod = 'LIVE';
        selectedMethodText.textContent = '⚡ Live';
        syncMsg.textContent = '';
        syncMsg.className = 'msg';
        showScreen('screen-sync');
      } else {
        alert((res && res.message) || 'Failed to set method');
      }
    });
  }

  if (methodFolderBtn) {
    methodFolderBtn.addEventListener('click', async () => {
      const res = await window.electronAPI.setSyncMethod('FOLDER');
      if (res && res.status === 'ok') {
        chosenMethod = 'FOLDER';
        selectedMethodText.textContent = '📁 Folder';
        syncMsg.textContent = '';
        syncMsg.className = 'msg';
        showScreen('screen-sync');
      } else {
        alert((res && res.message) || 'Failed to set method');
      }
    });
  }

  if (methodBackBtn) {
    methodBackBtn.addEventListener('click', () => {
      showScreen('screen-login');
    });
  }

  // Sync screen actions
  if (startSyncBtn) {
    startSyncBtn.addEventListener('click', async () => {
      startSyncBtn.disabled = true;
      startSyncBtn.textContent = 'Syncing...';
      syncMsg.className = 'msg';
      syncMsg.textContent = 'Connecting...';
      
      try {
        const res = await window.electronAPI.startSync();
        
        if (res && res.status === 'ok') {
          syncMsg.className = 'msg msg-success';
          syncMsg.textContent = res.message || `✓ Synced ${res.count || 0} invoice(s)`;
        } else if (res && res.status === 'warning') {
          syncMsg.className = 'msg msg-warning';
          syncMsg.textContent = `⚠ ${res.message}`;
        } else {
          syncMsg.className = 'msg msg-error';
          syncMsg.textContent = `✗ ${res?.message || 'Sync failed'}`;
        }
      } catch (err) {
        syncMsg.className = 'msg msg-error';
        syncMsg.textContent = '✗ Connection error';
        console.error('startSync IPC error:', err);
      } finally {
        startSyncBtn.disabled = false;
        startSyncBtn.textContent = 'Start Sync';
      }
    });
  }

  if (changeMethodBtn) {
    changeMethodBtn.addEventListener('click', async () => {
      try {
        await window.electronAPI.stopFolderImport();
      } catch (e) {}
      chosenMethod = null;
      selectedMethodText.textContent = '';
      syncMsg.textContent = '';
      showScreen('screen-method');
    });
  }
});
