// renderer.js - Runs in the renderer process and handles UI interactions
// Logs a message when the "Sync from Tally" button is clicked

document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('syncBtn');
  if (btn) {
    btn.addEventListener('click', async () => {
      console.log('Sync button clicked: sending IPC to main process');
      try {
        const response = await window.electronAPI.syncFromTally();
        console.log('Response from main process:', response);
      } catch (err) {
        console.error('IPC error:', err);
      }
    });
  }
});

// Login form handling
document.addEventListener('DOMContentLoaded', () => {
  const loginBtn = document.getElementById('loginBtn');
  const emailInput = document.getElementById('email');
  const passInput = document.getElementById('password');
  const loginMsg = document.getElementById('loginMsg');

  if (loginBtn) {
    loginBtn.addEventListener('click', async () => {
      const email = emailInput.value;
      const password = passInput.value;
      loginMsg.textContent = 'Logging in...';
      try {
        const res = await window.electronAPI.login(email, password);
        if (res && res.status === 'ok') {
          loginMsg.style.color = 'green';
          loginMsg.textContent = 'Login successful';
          console.log('Login success:', res);
        } else {
          loginMsg.style.color = 'red';
          loginMsg.textContent = res && res.message ? res.message : 'Login failed';
          console.log('Login failed:', res);
        }
      } catch (err) {
        loginMsg.style.color = 'red';
        loginMsg.textContent = 'Login error';
        console.error('Login IPC error:', err);
      }
    });
  }
});
