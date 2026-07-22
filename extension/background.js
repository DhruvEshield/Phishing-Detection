// PhishDetect Background Service Worker
// Handles API calls to bypass mixed content restrictions

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYSE_EMAIL') {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    fetch('https://prospects-tip-expressed-cds.trycloudflare.com/api/v1/emails/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message.payload),
      signal: controller.signal,
    })
      .then(res => res.json())
      .then(data => {
        console.log('[PhishDetect] API response:', JSON.stringify(data).substring(0, 200));
        sendResponse({ success: true, data });
      })
      .catch(err => {
        console.error('[PhishDetect] Fetch error:', err.message);
        sendResponse({ success: false, error: err.message });
      })
      .finally(() => clearTimeout(timeoutId));
    return true; // Keep message channel open for async response
  }
});
