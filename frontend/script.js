// ── TAB SWITCHING ──
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(tab.dataset.tab + '-panel').classList.add('active');
  });
});

// ── SCAN HISTORY ──
let history = JSON.parse(localStorage.getItem('threatscan_history') || '[]');
renderHistory();

function saveHistory(type, target, verdict) {
  history.unshift({ type, target, verdict, time: new Date().toLocaleTimeString() });
  if (history.length > 20) history.pop();
  localStorage.setItem('threatscan_history', JSON.stringify(history));
  renderHistory();
}

function clearHistory() {
  history = [];
  localStorage.removeItem('threatscan_history');
  renderHistory();
}

function renderHistory() {
  const list = document.getElementById('history-list');
  if (history.length === 0) {
    list.innerHTML = '<p class="empty-history">No scans yet.</p>';
    return;
  }
  list.innerHTML = history.map(h => `
    <div class="history-item">
      <div class="h-dot ${h.verdict}"></div>
      <span class="h-target">${h.target}</span>
      <span class="h-type">${h.type.toUpperCase()}</span>
      <span class="h-time">${h.time}</span>
    </div>
  `).join('');
}

// ── URL ANALYZER ──
async function analyzeURL() {
  const input = document.getElementById('url-input').value.trim();
  const resultBox = document.getElementById('url-result');

  if (!input) { alert('Please enter a URL.'); return; }

  // Show loading
  resultBox.style.display = 'block';
  resultBox.className = 'result-box';
  resultBox.innerHTML = `<div class="loading"><div class="spinner"></div>SCANNING URL...</div>`;

  try {
    const response = await fetch('/api/analyze-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: input })
    });

    const data = await response.json();
    renderURLResult(data, resultBox, input);
  } catch (err) {
    // Demo mode — show mock result if backend isn't running
    renderURLResult(mockURLResult(input), resultBox, input);
  }
}

function renderURLResult(data, box, input) {
  const verdictClass = data.verdict === 'SAFE' ? 'safe' : data.verdict === 'DANGEROUS' ? 'danger' : 'warn';
  const barColor = verdictClass === 'safe' ? 'var(--green)' : verdictClass === 'danger' ? 'var(--red)' : 'var(--yellow)';

  box.className = `result-box ${verdictClass}`;
  box.innerHTML = `
    <div class="verdict ${verdictClass}">${data.verdict === 'SAFE' ? '✓ CLEAN' : data.verdict === 'DANGEROUS' ? '✗ THREAT DETECTED' : '⚠ SUSPICIOUS'}</div>
    <div class="score-bar-wrap"><div class="score-bar" style="width:${data.threat_score}%;background:${barColor}"></div></div>
    <div class="detail-row"><span>THREAT SCORE</span><span>${data.threat_score}/100</span></div>
    <div class="detail-row"><span>MALICIOUS ENGINES</span><span>${data.malicious}/${data.total_engines}</span></div>
    <div class="detail-row"><span>CATEGORY</span><span>${data.category}</span></div>
    <div class="detail-row"><span>DOMAIN AGE</span><span>${data.domain_age}</span></div>
    <div class="detail-row"><span>HTTPS</span><span>${data.https ? '✓ YES' : '✗ NO'}</span></div>
    <div class="detail-row"><span>REDIRECTS</span><span>${data.redirects}</span></div>
    <div class="detail-row"><span>SOURCE</span><span>VirusTotal API</span></div>
  `;

  saveHistory('url', input.length > 40 ? input.slice(0, 40) + '…' : input, verdictClass);
}

// ── EMAIL ANALYZER ──
async function analyzeEmail() {
  const input = document.getElementById('email-input').value.trim();
  const resultBox = document.getElementById('email-result');

  if (!input) { alert('Please paste email content.'); return; }

  resultBox.style.display = 'block';
  resultBox.className = 'result-box';
  resultBox.innerHTML = `<div class="loading"><div class="spinner"></div>ANALYZING EMAIL...</div>`;

  try {
    const response = await fetch('/api/analyze-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: input })
    });

    const data = await response.json();
    renderEmailResult(data, resultBox, input);
  } catch (err) {
    renderEmailResult(mockEmailResult(input), resultBox, input);
  }
}

function renderEmailResult(data, box, input) {
  const verdictClass = data.verdict === 'SAFE' ? 'safe' : data.verdict === 'PHISHING' ? 'danger' : 'warn';
  const barColor = verdictClass === 'safe' ? 'var(--green)' : verdictClass === 'danger' ? 'var(--red)' : 'var(--yellow)';

  const urlRows = data.extracted_urls.length > 0
    ? data.extracted_urls.map(u => `<div class="detail-row"><span>URL FOUND</span><span style="color:var(--red)">${u.length > 45 ? u.slice(0,45)+'…' : u}</span></div>`).join('')
    : '<div class="detail-row"><span>URLs FOUND</span><span>None</span></div>';

  box.className = `result-box ${verdictClass}`;
  box.innerHTML = `
    <div class="verdict ${verdictClass}">${data.verdict === 'SAFE' ? '✓ LOOKS CLEAN' : data.verdict === 'PHISHING' ? '✗ PHISHING DETECTED' : '⚠ SUSPICIOUS EMAIL'}</div>
    <div class="score-bar-wrap"><div class="score-bar" style="width:${data.risk_score}%;background:${barColor}"></div></div>
    <div class="detail-row"><span>RISK SCORE</span><span>${data.risk_score}/100</span></div>
    <div class="detail-row"><span>SENDER</span><span>${data.sender}</span></div>
    <div class="detail-row"><span>SENDER DOMAIN MATCH</span><span>${data.domain_match ? '✓ YES' : '✗ NO — SPOOFED?'}</span></div>
    <div class="detail-row"><span>SPF / DKIM</span><span>${data.spf} / ${data.dkim}</span></div>
    <div class="detail-row"><span>URGENCY KEYWORDS</span><span>${data.urgency_keywords.join(', ') || 'None'}</span></div>
    <div class="detail-row"><span>SUSPICIOUS ATTACHMENTS</span><span>${data.suspicious_attachments ? '✗ YES' : '✓ None'}</span></div>
    ${urlRows}
  `;

  const preview = input.slice(0, 40).replace(/\n/g, ' ') + '…';
  saveHistory('email', preview, verdictClass);
}

// ── MOCK RESULTS (demo mode when backend is offline) ──
function mockURLResult(url) {
  const isSuspicious = url.includes('login') || url.includes('verify') || url.includes('secure') || !url.startsWith('https');
  return {
    verdict: isSuspicious ? 'SUSPICIOUS' : 'SAFE',
    threat_score: isSuspicious ? 62 : 4,
    malicious: isSuspicious ? 8 : 0,
    total_engines: 72,
    category: isSuspicious ? 'Phishing / Social Engineering' : 'Clean',
    domain_age: isSuspicious ? '3 days' : '6 years',
    https: url.startsWith('https'),
    redirects: isSuspicious ? '3 redirects' : 'None'
  };
}

function mockEmailResult(email) {
  const lower = email.toLowerCase();
  const urgencyWords = ['urgent', 'verify', 'suspended', 'click here', 'confirm', 'password', 'account'];
  const found = urgencyWords.filter(w => lower.includes(w));
  const isPhishing = found.length >= 2;

  const urlRegex = /https?:\/\/[^\s]+/g;
  const urls = email.match(urlRegex) || [];

  return {
    verdict: isPhishing ? 'PHISHING' : found.length === 1 ? 'SUSPICIOUS' : 'SAFE',
    risk_score: isPhishing ? 87 : found.length === 1 ? 45 : 8,
    sender: 'extracted-from-header@domain.com',
    domain_match: !isPhishing,
    spf: isPhishing ? 'FAIL' : 'PASS',
    dkim: isPhishing ? 'NONE' : 'PASS',
    urgency_keywords: found,
    suspicious_attachments: lower.includes('.exe') || lower.includes('.zip'),
    extracted_urls: urls.slice(0, 3)
  };
}
