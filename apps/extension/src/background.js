let socket = null;
let reconnectTimer = null;

function connectToCLI() {
  if (socket && socket.readyState !== WebSocket.CLOSED) return;

  socket = new WebSocket('ws://localhost:7474/extension');

  socket.onopen = () => {
    console.log('Connected to Valinhall CLI');
    socket.send(JSON.stringify({ type: 'EXTENSION_READY' }));
    if (reconnectTimer) {
      clearInterval(reconnectTimer);
      reconnectTimer = null;
    }
  };

  socket.onmessage = async (event) => {
    try {
      const msg = JSON.parse(event.data);
      console.log('Received from CLI:', msg);
      await handleCliCommand(msg);
    } catch (e) {
      console.error('Error handling message:', e);
    }
  };

  socket.onclose = () => {
    console.log('Disconnected from Valinhall CLI, retrying in 3s...');
    if (!reconnectTimer) {
      reconnectTimer = setInterval(connectToCLI, 3000);
    }
  };

  socket.onerror = (err) => {
    console.error('WebSocket error:', err);
    socket.close();
  };
}

/**
 * Send a single DOM_MANIPULATION command to the active tab and resolve with the result.
 */
function executeOneAction(tabId, action, payload) {
  return new Promise((resolve) => {
    chrome.tabs.sendMessage(
      tabId,
      { type: 'DOM_MANIPULATION', action, payload },
      (response) => {
        if (chrome.runtime.lastError) {
          resolve({ status: 'error', message: chrome.runtime.lastError.message });
        } else {
          resolve(response || { status: 'error', message: 'No response from content script' });
        }
      }
    );
  });
}

async function handleCliCommand(msg) {
  // ── New batch protocol ─────────────────────────────────────────────────────
  if (msg.type === 'EXECUTE_BATCH') {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs.length === 0) return;
    const tabId = tabs[0].id;

    const actions = Array.isArray(msg.actions) ? msg.actions : [];
    const results = [];

    for (const step of actions) {
      const action = step.action || 'UNKNOWN';
      const payload = step.payload || {};

      // Small delay between actions so the page has time to react
      if (results.length > 0) {
        await new Promise(r => setTimeout(r, 600));
      }

      const result = await executeOneAction(tabId, action, payload);
      results.push({ action, payload, result });

      // If the agent signalled DONE, stop early
      if (action === 'DONE') break;
    }

    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({
        type: 'BATCH_RESULT',
        taskId: msg.taskId,
        results
      }));
    }

    return;
  }

  // ── Legacy single-action protocol (kept for compatibility) ─────────────────
  if (msg.type === 'EXECUTE_TEST') {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs.length === 0) return;

    chrome.tabs.sendMessage(tabs[0].id, {
      type: 'DOM_MANIPULATION',
      action: msg.action,
      payload: msg.payload
    }, (response) => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({
          type: 'TEST_RESULT',
          taskId: msg.taskId,
          result: response
        }));
      }
    });
    return;
  }

  // ── DOM context request ────────────────────────────────────────────────────
  if (msg.type === 'LLM_REQUEST') {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs.length > 0) {
      chrome.tabs.sendMessage(tabs[0].id, { type: 'GATHER_CONTEXT' }, (context) => {
        if (socket && socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({
            type: 'CONTEXT_GATHERED',
            taskId: msg.taskId,
            context: context
          }));
        }
      });
    }
  }
}

// Start connection attempt
connectToCLI();

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_STATUS') {
    sendResponse({
      connected: socket && socket.readyState === WebSocket.OPEN
    });
  } else if (message.type === 'FORWARD_TO_CLI') {
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(message.payload));
      sendResponse({ success: true });
    } else {
      sendResponse({ success: false, error: 'CLI not connected' });
    }
  }
});
