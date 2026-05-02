<script>
  let connected = $state(false);
  let loading = $state(false);
  let statusMessage = $state('CLI Disconnected');
  let btnMessage = $state('Extract Page Context');

  function checkStatus() {
    chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (response) => {
      if (chrome.runtime.lastError || !response) {
        connected = false;
        statusMessage = 'CLI Disconnected';
        return;
      }
      if (response.connected) {
        connected = true;
        statusMessage = 'Connected to CLI';
      } else {
        connected = false;
        statusMessage = 'CLI Disconnected';
      }
    });
  }

  // initial check & interval
  $effect(() => {
    checkStatus();
    const interval = setInterval(checkStatus, 2000);
    return () => clearInterval(interval);
  });

  async function handleExtract() {
    loading = true;
    btnMessage = 'Extracting...';

    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length === 0) {
        throw new Error('No active tab');
      }

      chrome.tabs.sendMessage(tabs[0].id, { type: 'GATHER_CONTEXT' }, (response) => {
        if (chrome.runtime.lastError) {
          console.error(chrome.runtime.lastError);
          btnMessage = 'Error (Reload page)';
        } else {
          chrome.runtime.sendMessage({
            type: 'FORWARD_TO_CLI',
            payload: {
              type: 'CONTEXT_GATHERED',
              context: response
            }
          });
          btnMessage = 'Success!';
        }
        
        setTimeout(() => {
          btnMessage = 'Extract Page Context';
          loading = false;
        }, 2000);
      });
    } catch (err) {
      console.error(err);
      btnMessage = 'Error';
      setTimeout(() => {
        btnMessage = 'Extract Page Context';
        loading = false;
      }, 2000);
    }
  }
</script>

<div class="header">
  <h1>Valinhall LLM Testing</h1>
</div>

<div class="status-container">
  <div class="status-dot {connected ? 'connected' : 'disconnected'}"></div>
  <span>{statusMessage}</span>
</div>

<div class="section">
  <div class="section-title">Manual Actions</div>
  <button class="btn" onclick={handleExtract} disabled={loading}>{btnMessage}</button>
</div>

<style>
  :global(body) {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    width: 300px;
    padding: 16px;
    background-color: #121212;
    color: #ffffff;
    margin: 0;
  }
  .header {
    display: flex;
    align-items: center;
    margin-bottom: 16px;
    padding-bottom: 16px;
    border-bottom: 1px solid #333;
  }
  h1 {
    font-size: 18px;
    margin: 0;
    color: #00e676;
  }
  .status-container {
    display: flex;
    align-items: center;
    margin-bottom: 16px;
  }
  .status-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    margin-right: 8px;
  }
  .connected {
    background-color: #00e676;
    box-shadow: 0 0 5px #00e676;
  }
  .disconnected {
    background-color: #ff3d00;
    box-shadow: 0 0 5px #ff3d00;
  }
  .btn {
    background-color: #333;
    color: white;
    border: 1px solid #555;
    padding: 8px 16px;
    border-radius: 4px;
    cursor: pointer;
    width: 100%;
    font-weight: 500;
    transition: background-color 0.2s;
  }
  .btn:hover:not(:disabled) {
    background-color: #444;
  }
  .btn:active:not(:disabled) {
    background-color: #222;
  }
  .btn:disabled {
    opacity: 0.7;
    cursor: not-allowed;
  }
  .section {
    margin-top: 16px;
  }
  .section-title {
    font-size: 14px;
    color: #aaa;
    margin-bottom: 8px;
  }
</style>
