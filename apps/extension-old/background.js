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

async function handleCliCommand(msg) {
  if (msg.type === 'EXECUTE_TEST') {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs.length === 0) return;
    
    // Send command to content script to manipulate DOM
    chrome.tabs.sendMessage(tabs[0].id, {
      type: 'DOM_MANIPULATION',
      action: msg.action,
      payload: msg.payload
    }, (response) => {
      // Send result back to CLI
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({
          type: 'TEST_RESULT',
          taskId: msg.taskId,
          result: response
        }));
      }
    });
  } else if (msg.type === 'LLM_REQUEST') {
    // The extension can directly make LLM calls or rely on CLI
    // Here we can forward it to the content script if it needs page context
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs.length > 0) {
      chrome.tabs.sendMessage(tabs[0].id, {
        type: 'GATHER_CONTEXT'
      }, async (context) => {
        // Send back to CLI to let CLI do the LLM call, OR do it here if API key is in storage
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
