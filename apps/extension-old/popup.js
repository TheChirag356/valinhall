document.addEventListener('DOMContentLoaded', () => {
  const statusDot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const extractContextBtn = document.getElementById('extractContextBtn');

  // Check connection status
  function checkStatus() {
    chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (response) => {
      if (chrome.runtime.lastError || !response) {
        setDisconnected();
        return;
      }
      
      if (response.connected) {
        setConnected();
      } else {
        setDisconnected();
      }
    });
  }

  function setConnected() {
    statusDot.className = 'status-dot connected';
    statusText.textContent = 'Connected to CLI';
  }

  function setDisconnected() {
    statusDot.className = 'status-dot disconnected';
    statusText.textContent = 'CLI Disconnected';
  }

  // Initial check
  checkStatus();
  
  // Poll status every 2 seconds
  setInterval(checkStatus, 2000);

  // Handle manual extraction
  extractContextBtn.addEventListener('click', async () => {
    extractContextBtn.textContent = 'Extracting...';
    extractContextBtn.disabled = true;

    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length === 0) {
        throw new Error('No active tab');
      }

      chrome.tabs.sendMessage(tabs[0].id, { type: 'GATHER_CONTEXT' }, (response) => {
        if (chrome.runtime.lastError) {
          console.error(chrome.runtime.lastError);
          extractContextBtn.textContent = 'Error (Reload page)';
        } else {
          console.log('Extracted context:', response);
          
          // Send to CLI if connected
          chrome.runtime.sendMessage({
            type: 'FORWARD_TO_CLI',
            payload: {
              type: 'CONTEXT_GATHERED',
              context: response
            }
          });
          
          extractContextBtn.textContent = 'Success!';
        }
        
        setTimeout(() => {
          extractContextBtn.textContent = 'Extract Page Context';
          extractContextBtn.disabled = false;
        }, 2000);
      });
    } catch (err) {
      console.error(err);
      extractContextBtn.textContent = 'Error';
      setTimeout(() => {
        extractContextBtn.textContent = 'Extract Page Context';
        extractContextBtn.disabled = false;
      }, 2000);
    }
  });
});
