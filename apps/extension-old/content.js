console.log('Valinhall Security Extension Content Script Loaded.');

// Listen for commands from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'DOM_MANIPULATION') {
    handleDomManipulation(message, sendResponse);
    return true; // Indicates async response
  } else if (message.type === 'GATHER_CONTEXT') {
    const context = gatherPageContext();
    sendResponse(context);
  }
});

async function handleDomManipulation(message, sendResponse) {
  const { action, payload } = message;
  
  try {
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
    else if (action === 'SUBMIT_FORM') {
      const form = document.querySelector('form');
      if (form) {
        // Find submit button to trigger click events if needed
        const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
        if (submitBtn) {
          submitBtn.click();
        } else {
          form.submit();
        }
        sendResponse({ status: 'success', message: 'Form submitted' });
      } else {
        sendResponse({ status: 'error', message: 'No form found' });
      }
    }
    else if (action === 'INJECT_PAYLOAD') {
      // Find the specific selector and inject payload
      const element = document.querySelector(payload.selector);
      if (element) {
        if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') {
          element.value = payload.value;
          element.dispatchEvent(new Event('input', { bubbles: true }));
        } else {
          element.innerHTML = payload.value;
        }
        sendResponse({ status: 'success', injected: true });
      } else {
        sendResponse({ status: 'error', message: 'Selector not found' });
      }
    }
    else if (action === 'CLICK_ELEMENT') {
      const element = document.querySelector(payload.selector);
      if (element) {
        element.click();
        sendResponse({ status: 'success', clicked: true });
      } else {
        sendResponse({ status: 'error', message: 'Selector not found' });
      }
    }
    else {
      sendResponse({ status: 'error', message: 'Unknown action' });
    }
  } catch (err) {
    sendResponse({ status: 'error', message: err.toString() });
  }
}

function gatherPageContext() {
  // Extract useful information for the LLM to understand the page
  const forms = Array.from(document.forms).map(form => {
    return {
      action: form.action,
      method: form.method,
      inputs: Array.from(form.elements).map(el => ({
        name: el.name,
        type: el.type,
        id: el.id,
        placeholder: el.placeholder
      }))
    };
  });

  return {
    url: window.location.href,
    title: document.title,
    forms: forms,
    textSnippet: document.body.innerText.substring(0, 1000) // First 1000 chars for context
  };
}
