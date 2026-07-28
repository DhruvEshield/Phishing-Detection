// PhishDetect Gmail Extension - Content Script
const API_BASE = 'https://prospects-tip-expressed-cds.trycloudflare.com';
const SIGNAL_LABELS = {
  header: 'Header Analysis',
  content: 'Content Analysis',
  url: 'URL Analysis',
  qrcode: 'QR Code Detection',
  threat_intel: 'Threat Intelligence',
  attachment: 'Attachment Analysis',
};

let currentEmailId = null;
let panel = null;

// ── Utility: get progress bar color class ────────────────────────────────
function getBarClass(score) {
  if (score >= 60) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

// ── Utility: get progress bar color for main score ───────────────────────
function getScoreColor(score) {
  if (score >= 70) return '#ea4335';
  if (score >= 35) return '#fbbc04';
  return '#34a853';
}

// ── Extract email data from Gmail DOM ────────────────────────────────────
function extractEmailData() {
  try {
    // Sender
    const senderEl = document.querySelector('[email]') ||
                     document.querySelector('.gD') ||
                     document.querySelector('[data-hovercard-id]');
    const sender = senderEl ? (senderEl.getAttribute('email') || senderEl.innerText) : '';

    // Subject
    const subjectEl = document.querySelector('h2.hP') ||
                      document.querySelector('[data-thread-perm-id] h2');
    const subject = subjectEl ? subjectEl.innerText : '';

    // Body
    const bodyEl = document.querySelector('.a3s.aiL') ||
                   document.querySelector('.ii.gt div');
    const bodyText = bodyEl ? bodyEl.innerText : '';

    // Auth headers (not available in DOM — we simulate based on what we can get)
    const headers = {
      'From': sender,
      'Subject': subject,
    };

    return { headers, body_text: bodyText, body_html: '', attachments: [], raw_mime: null, metadata: { source: 'gmail_extension' } };
  } catch (e) {
    console.error('[PhishDetect] Error extracting email:', e);
    return null;
  }
}

// ── Create the panel HTML ────────────────────────────────────────────────
function createPanel() {
  const div = document.createElement('div');
  div.id = 'phishdetect-panel';
  div.innerHTML = `
    <div id="phishdetect-header">
      <div id="phishdetect-logo">🛡️ PhishDetect</div>
      <span id="phishdetect-close">×</span>
    </div>
    <div id="phishdetect-loading">Analysing email...</div>
  `;
  document.body.appendChild(div);

  document.getElementById('phishdetect-close').addEventListener('click', () => {
    div.remove();
    panel = null;
    isAnalysing = false;
    lastBodyText = '';
    currentEmailId = null;
  });

  return div;
}

// ── Render result into panel ─────────────────────────────────────────────
function renderResult(data) {
  const score = data.risk_score.toFixed(1);
  const tier = data.risk_tier;
  const verdict = data.verdict;
  const signals = data.explanation.signals;
  const color = getScoreColor(data.risk_score);

  const issues = data.explanation.issues || [];
  const hasMediumOrAbove = issues.some(i => ['Critical', 'High', 'Medium'].includes(i.severity));

  const severityColors = {
    Critical: '#ea4335',
    High: '#fb7d3f',
    Medium: '#fbbc04',
    Low: '#9aa0a6',
  };

  const severityRank = { Critical: 0, High: 1, Medium: 2, Low: 3 };

  // Group issues by detector
  const issuesByDetector = {};
  for (const issue of issues) {
    if (!issuesByDetector[issue.detector]) issuesByDetector[issue.detector] = [];
    issuesByDetector[issue.detector].push(issue);
  }

  const ALL_DETECTORS = ['header', 'content', 'url', 'qrcode', 'threat_intel', 'attachment'];
  const detectorsWithIssues = Object.keys(issuesByDetector).sort((a, b) => {
    const worstA = issuesByDetector[a].reduce((w, i) => severityRank[i.severity] < severityRank[w] ? i.severity : w, issuesByDetector[a][0].severity);
    const worstB = issuesByDetector[b].reduce((w, i) => severityRank[i.severity] < severityRank[w] ? i.severity : w, issuesByDetector[b][0].severity);
    return severityRank[worstA] - severityRank[worstB];
  });
  const detectorsWithoutIssues = ALL_DETECTORS.filter(d => !issuesByDetector[d]);
  const detectorsSorted = [...detectorsWithIssues, ...detectorsWithoutIssues];

  const signalsHtml = detectorsSorted.map(detectorName => {
    const detectorIssues = issuesByDetector[detectorName];
    const label = SIGNAL_LABELS[detectorName] || detectorName;

    if (!detectorIssues) {
      return `
        <div class="phishdetect-signal">
          <div class="phishdetect-signal-header">
            <span class="phishdetect-signal-name">${label}</span>
          </div>
          <div class="phishdetect-no-issues">No issues found</div>
        </div>
      `;
    }

    const worst = detectorIssues.reduce((w, i) => severityRank[i.severity] < severityRank[w] ? i.severity : w, detectorIssues[0].severity);
    const issuesHtml = detectorIssues.map(issue => {
      const match = issue.flag.match(/^([a-zA-Z_]+)/);
      const keyword = match ? match[1].replace(/_/g, ' ') : issue.flag;
      return `
        <div class="phishdetect-issue-row">
          <span class="phishdetect-keyword-tag" style="border-color:${severityColors[issue.severity]};color:${severityColors[issue.severity]}">${keyword}</span>
          <span class="phishdetect-issue-desc">${issue.description}</span>
        </div>
      `;
    }).join('');

    return `
      <div class="phishdetect-signal">
        <div class="phishdetect-signal-header">
          <span class="phishdetect-signal-name">${label}</span>
          <span class="phishdetect-grade-badge" style="background:${severityColors[worst]}">${worst}</span>
        </div>
        ${issuesHtml}
      </div>
    `;
  }).join('');

  // Extract a short keyword from a flag string (text before the first ':' or '(')
  function flagToKeyword(flag) {
    const match = flag.match(/^([a-zA-Z_]+)/);
    if (!match) return flag;
    return match[1].replace(/_/g, ' ');
  }

  const keywordTagsHtml = issues.map(issue => {
    const issueColor = severityColors[issue.severity] || '#9aa0a6';
    return `<span class="phishdetect-keyword-tag" style="border-color:${issueColor};color:${issueColor}">${flagToKeyword(issue.flag)}</span>`;
  }).join('');

  const bannerHtml = hasMediumOrAbove
    ? `<div id="phishdetect-worth-checking">⚠️ This email is worth checking</div>`
    : '';

  document.getElementById('phishdetect-loading').outerHTML = `
    <div id="phishdetect-summary">
      ${bannerHtml}
      <div id="phishdetect-keywords">${keywordTagsHtml || '<span style="color:#999">No issues found</span>'}</div>
      <button id="phishdetect-toggle-btn">View Full Analysis ▼</button>
    </div>
    <div id="phishdetect-details">
      ${signalsHtml}
    </div>
  `;

  document.getElementById('phishdetect-toggle-btn').addEventListener('click', () => {
    const details = document.getElementById('phishdetect-details');
    const btn = document.getElementById('phishdetect-toggle-btn');
    if (details.classList.contains('visible')) {
      details.classList.remove('visible');
      btn.textContent = 'View Full Analysis ▼';
    } else {
      details.classList.add('visible');
      btn.textContent = 'Hide Analysis ▲';
    }
  });
}

// ── Render error into panel ──────────────────────────────────────────────
function renderError(msg) {
  const loading = document.getElementById('phishdetect-loading');
  if (loading) {
    loading.outerHTML = `<div id="phishdetect-error">${msg}</div>`;
  }
}

// ── Call PhishDetect API ─────────────────────────────────────────────────
async function analyseEmail(emailData) {
  try {
    chrome.runtime.sendMessage(
      { type: 'ANALYSE_EMAIL', payload: emailData },
      (response) => {
        if (chrome.runtime.lastError) {
          console.error('[PhishDetect] Runtime error:', chrome.runtime.lastError);
          renderError('Could not connect to PhishDetect API. Is it running on localhost:8000?');
          return;
        }
        if (response && response.success && response.data && response.data.success) {
          renderResult(response.data.data);
        } else {
          renderError('Analysis failed. Please try again.');
        }
      }
    );
  } catch (e) {
    console.error('[PhishDetect] API error:', e);
    renderError('Could not connect to PhishDetect API. Is it running on localhost:8000?');
  }
}

// ── Main: detect email open and trigger analysis ─────────────────────────
function onEmailOpen() {
  setTimeout(() => {
    const emailData = extractEmailData();
    if (!emailData || !emailData.body_text || emailData.body_text.trim().length < 10) return;

    // Use body text as email fingerprint to avoid re-analysing same email
    const emailFingerprint = emailData.body_text.substring(0, 100);
    if (emailFingerprint === currentEmailId) return;
    currentEmailId = emailFingerprint;

    const existing = document.getElementById('phishdetect-panel');
    if (existing) existing.remove();

    panel = createPanel();
    analyseEmail(emailData);
  }, 2000);
}

// Watch for Gmail DOM changes — works for both URL-based and preview pane navigation
let debounceTimer = null;
let lastBodyText = '';
let isAnalysing = false;

const observer = new MutationObserver(() => {
  if (isAnalysing) return;
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    const bodyEl = document.querySelector('.a3s.aiL') ||
                   document.querySelector('.ii.gt div');
    if (!bodyEl || bodyEl.innerText.trim().length < 10) return;
    const currentBodyText = bodyEl.innerText.trim().substring(0, 100);
    if (currentBodyText === lastBodyText) return;
    lastBodyText = currentBodyText;
    currentEmailId = null;
    isAnalysing = true;
    // Safety reset — if analysis takes more than 30 seconds, unlock
    setTimeout(() => { isAnalysing = false; }, 30000);
    const existing = document.getElementById('phishdetect-panel');
    if (existing) existing.remove();
    panel = createPanel();
    const emailData = extractEmailData();
    if (emailData && emailData.body_text) {
      chrome.runtime.sendMessage(
        { type: 'ANALYSE_EMAIL', payload: emailData },
        (response) => {
          isAnalysing = false;
          if (chrome.runtime.lastError || !response) {
            renderError('Could not connect to PhishDetect API. Is it running on localhost:8000?');
            return;
          }
          if (response.success && response.data && response.data.success) {
            renderResult(response.data.data);
          } else {
            renderError('Analysis failed. Please try again.');
          }
        }
      );
    } else {
      isAnalysing = false;
    }
  }, 1000);
});

observer.observe(document.body, { childList: true, subtree: true });
window.addEventListener('load', () => {
  setTimeout(() => {
    lastBodyText = '';
    currentEmailId = null;
  }, 2000);
});
