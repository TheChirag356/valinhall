console.log('Valinhall Security Extension Content Script Loaded.');

let overlayElement = null;
let overlayStatus = null;

function showOverlay(statusText) {
  if (!overlayElement) {
    overlayElement = document.createElement('div');
    overlayElement.id = 'valinhall-agent-overlay';
    Object.assign(overlayElement.style, {
      position: 'fixed',
      top: '0', left: '0', width: '100vw', height: '100vh',
      backgroundColor: 'rgba(15, 23, 42, 0.85)',
      backdropFilter: 'blur(8px)',
      zIndex: '2147483647',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      color: '#f8fafc',
      fontFamily: 'system-ui, sans-serif',
      pointerEvents: 'all'
    });

    overlayElement.innerHTML = `
      <div style="width: 60px; height: 60px; border: 4px solid rgba(255,255,255,0.1); border-top-color: #3b82f6; border-radius: 50%; animation: valinhall-spin 1s linear infinite;"></div>
      <h2 style="margin-top: 24px; font-weight: 600; font-size: 24px; letter-spacing: -0.025em;">Valinhall Agent Active</h2>
      <p id="valinhall-status" style="margin-top: 8px; color: #94a3b8; font-size: 15px;">Automated security testing in progress. Please wait...</p>
      <style>
        @keyframes valinhall-spin { to { transform: rotate(360deg); } }
      </style>
    `;

    document.body.appendChild(overlayElement);
  }
  overlayStatus = overlayElement.querySelector('#valinhall-status');
  if (statusText && overlayStatus) overlayStatus.textContent = statusText;
}

function updateOverlayStatus(text) {
  if (overlayStatus) overlayStatus.textContent = text;
}

function hideOverlay() {
  if (overlayElement) {
    overlayElement.remove();
    overlayElement = null;
    overlayStatus = null;
  }
}

// Listen for commands from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'DOM_MANIPULATION') {
    if (message.action === 'DONE') {
      hideOverlay();
      sendResponse({ status: 'success', message: 'Testing finished' });
      return false;
    }
    showOverlay(`Executing: ${message.action}...`);
    handleDomManipulation(message, sendResponse);
    return true; // async response
  } else if (message.type === 'GATHER_CONTEXT') {
    showOverlay('Gathering page context...');
    const context = gatherPageContext();
    sendResponse(context);
    return false;
  }
});

async function handleDomManipulation(message, sendResponse) {
  const { action, payload } = message;

  try {
    updateOverlayStatus(`Running: ${action}...`);

    // ── FILL_FORM ──────────────────────────────────────────────────────────────
    if (action === 'FILL_FORM') {
      const inputs = document.querySelectorAll('input, textarea');
      let filled = 0;
      inputs.forEach(input => {
        if (input.type !== 'hidden' && input.type !== 'submit' && input.type !== 'button') {
          input.value = payload.value || 'Valinhall LLM Probe';
          input.dispatchEvent(new Event('input', { bubbles: true }));
          input.dispatchEvent(new Event('change', { bubbles: true }));
          filled++;
        }
      });
      sendResponse({ status: 'success', filledElements: filled });
    }

    // ── SUBMIT_FORM ────────────────────────────────────────────────────────────
    else if (action === 'SUBMIT_FORM') {
      const form = document.querySelector('form');
      if (form) {
        const submitBtn = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
        if (submitBtn) {
          submitBtn.click();
        } else {
          form.submit();
        }
        // Wait briefly for the page to react
        await new Promise(r => setTimeout(r, 800));
        sendResponse({ status: 'success', message: 'Form submitted' });
      } else {
        sendResponse({ status: 'error', message: 'No form found' });
      }
    }

    // ── INJECT_PAYLOAD ─────────────────────────────────────────────────────────
    else if (action === 'INJECT_PAYLOAD') {
      const element = document.querySelector(payload.selector);
      if (element) {
        if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') {
          element.value = payload.value;
          element.dispatchEvent(new Event('input', { bubbles: true }));
          element.dispatchEvent(new Event('change', { bubbles: true }));
        } else {
          element.innerHTML = payload.value;
        }
        sendResponse({ status: 'success', injected: true });
      } else {
        sendResponse({ status: 'error', message: `Selector not found: ${payload.selector}` });
      }
    }

    // ── CLICK_ELEMENT ──────────────────────────────────────────────────────────
    else if (action === 'CLICK_ELEMENT') {
      const element = document.querySelector(payload.selector);
      if (element) {
        element.click();
        await new Promise(r => setTimeout(r, 500));
        sendResponse({ status: 'success', clicked: true });
      } else {
        sendResponse({ status: 'error', message: `Selector not found: ${payload.selector}` });
      }
    }

    // ── GET_PAGE_TEXT ──────────────────────────────────────────────────────────
    else if (action === 'GET_PAGE_TEXT') {
      sendResponse({
        status: 'success',
        pageText: document.body.innerText,
        url: window.location.href,
        title: document.title
      });
    }

    // ── NAVIGATE ───────────────────────────────────────────────────────────────
    else if (action === 'NAVIGATE') {
      const url = payload.url;
      if (url) {
        window.location.href = url;
        sendResponse({ status: 'success', navigating: true });
      } else {
        sendResponse({ status: 'error', message: 'No URL provided' });
      }
    }

    else {
      sendResponse({ status: 'error', message: `Unknown action: ${action}` });
    }
  } catch (err) {
    sendResponse({ status: 'error', message: err.toString() });
  }
}

function gatherPageContext() {
  const forms = Array.from(document.forms).map(form => ({
    action: form.action,
    method: form.method,
    inputs: Array.from(form.elements).map(el => ({
      name: el.name,
      type: el.type,
      id: el.id,
      placeholder: el.placeholder,
      tagName: el.tagName
    }))
  }));

  // Gather all clickable links and buttons for the agent to reason about
  const links = Array.from(document.querySelectorAll('a[href]'))
    .slice(0, 20)
    .map(a => ({ text: a.innerText.trim(), href: a.href }));

  const buttons = Array.from(document.querySelectorAll('button, input[type="submit"]'))
    .slice(0, 10)
    .map(b => ({ text: b.innerText?.trim() || b.value, selector: b.id ? `#${b.id}` : b.name ? `[name="${b.name}"]` : b.tagName.toLowerCase() }));

  return {
    url: window.location.href,
    title: document.title,
    forms,
    links,
    buttons,
    // Full page text so the LLM can read responses, passwords, etc.
    pageText: document.body.innerText.substring(0, 3000)
  };
}
