// popup.js - PhishGuard Extension (Updated for new API)

// App configuration
let API_URL = localStorage.getItem('api_url') || 'http://localhost:5002';
let API_KEY = localStorage.getItem('api_key') || 'test_key_123';

// Get current tab URL
async function getCurrentTabUrl() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab.url;

    const urlElement = document.getElementById('current-url');
    if (urlElement) {
      urlElement.innerText =
        url.length > 50 ? url.substring(0, 50) + '...' : url;
    }

    const urlInput = document.getElementById('url-input');
    if (urlInput) urlInput.value = url;

    return url;

  } catch (error) {
    console.error('Error getting current tab:', error);

    const urlElement = document.getElementById('current-url');
    if (urlElement) urlElement.innerText = 'Cannot access URL';

    return null;
  }
}

// Display result (compatible with new and old APIs)
function displayResult(data, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.style.display = 'block';
  container.className = 'result';

  // Normalize API responses
  const isPhishing = data.is_phishing || data.prediction === 'phishing';
  const probability = data.probability || (data.score ? data.score / 100 : 0);
  const confidence = data.confidence || data.score || 0;
  const riskLevel =
    data.risk_level ||
    (data.score > 70 ? 'high' : data.score > 40 ? 'medium' : 'low');

  const explanation = data.explanation || '';
  const recommendation = data.recommendation || '';

  if (isPhishing) {
    container.className += ' phishing';
    container.innerHTML = `
      <strong>🚨 WARNING! Phishing URL Detected</strong><br>
      Threat Score: ${Math.round(confidence)}%<br>
      ${explanation ? `<br>💡 ${explanation}<br>` : ''}
      ${recommendation ? `<br><strong>Recommendation:</strong> ${recommendation}` : ''}
      <br><br>⚠️ DO NOT enter any personal information!
    `;

  } else if (riskLevel === 'medium') {
    container.className += ' medium';
    container.innerHTML = `
      <strong>⚠️ Alert! Medium Risk</strong><br>
      Threat Score: ${Math.round(confidence)}%<br>
      ${explanation ? `<br>💡 ${explanation}<br>` : ''}
      ${recommendation ? `<br><strong>Recommendation:</strong> ${recommendation}` : ''}
      <br><br>⚠️ Be cautious when interacting with this site
    `;

  } else {
    container.className += ' safe';
    container.innerHTML = `
      <strong>✅ SAFE! No Risk Detected</strong><br>
      Confidence: ${Math.round(confidence)}%<br>
      ${explanation ? `<br>💡 ${explanation}<br>` : ''}
      ${recommendation ? `<br><strong>Recommendation:</strong> ${recommendation}` : ''}
      <br><br>✓ This site appears safe
    `;
  }

  // Add risk factors if available
  if (data.risk_factors && data.risk_factors.length > 0) {
    container.innerHTML += `
      <br><br>
      <small>⚠️ Risk factors: ${data.risk_factors.slice(0, 2).join(', ')}</small>
    `;
  }
}

// Check URL using API
async function checkUrl(url) {
  const resultDiv = document.getElementById('result');
  if (!resultDiv) return;

  resultDiv.style.display = 'block';
  resultDiv.className = 'result loading';
  resultDiv.innerHTML = '<div class="spinner">🔍 Analyzing...</div>';

  try {
    // Ensure URL has protocol
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }

    // Use new endpoint
    const response = await fetch(`${API_URL}/smart-check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: url })
    });

    const data = await response.json();

    if (response.ok) {
      displayResult(data, 'result');

      // Save locally
      saveToHistory(url, data);

      // Notify if phishing
      if (data.is_phishing || data.prediction === 'phishing') {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: '🚨 Phishing Alert!',
          message: `Phishing URL detected: ${url.substring(0, 50)}...\nScore: ${Math.round(data.score || data.confidence || 0)}%`,
          priority: 2
        });
      }

    } else {
      resultDiv.className = 'result';
      resultDiv.innerHTML = `❌ Error: ${data.error || 'Unexpected error'}`;
    }

  } catch (error) {
    resultDiv.className = 'result';
    resultDiv.innerHTML = `❌ Connection Error: ${error.message}<br>Make sure server is running: ${API_URL}`;
  }
}

// Save scan history locally
function saveToHistory(url, result) {
  let history = JSON.parse(localStorage.getItem('phishing_history') || '[]');

  history.unshift({
    url: url,
    is_phishing: result.is_phishing || result.prediction === 'phishing',
    probability: result.probability || (result.score ? result.score / 100 : 0),
    risk_level:
      result.risk_level ||
      (result.score > 70 ? 'high' : result.score > 40 ? 'medium' : 'low'),
    timestamp: new Date().toISOString()
  });

  // Keep only last 50 entries
  if (history.length > 50) history.pop();

  localStorage.setItem('phishing_history', JSON.stringify(history));
}

// Open settings page
function openSettings() {
  const settingsHtml = `
    <div style="padding: 15px; font-family: Arial, sans-serif;">
      <h3>⚙️ Settings</h3>

      <div style="margin: 15px 0;">
        <label>API URL:</label>
        <input type="text" id="api-url-settings" value="${API_URL}" style="width: 100%; margin-top: 5px; padding: 5px;">
        <small style="color: #666;">Default: http://localhost:5002</small>
      </div>

      <div style="margin: 15px 0;">
        <label>API Key:</label>
        <input type="password" id="api-key-settings" value="${API_KEY}" style="width: 100%; margin-top: 5px; padding: 5px;">
      </div>

      <button id="save-settings" style="margin-top: 10px; padding: 8px 15px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer;">💾 Save Settings</button>

      <button id="test-connection" style="margin-top: 10px; padding: 8px 15px; background: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer; margin-left: 10px;">🔌 Test Connection</button>
    </div>
  `;

  const settingsWindow = window.open('', '_blank', 'width=450,height=350');
  settingsWindow.document.write(settingsHtml);

  // Save settings
  settingsWindow.document.getElementById('save-settings').onclick = () => {
    const newUrl = settingsWindow.document.getElementById('api-url-settings').value;
    const newKey = settingsWindow.document.getElementById('api-key-settings').value;

    localStorage.setItem('api_url', newUrl);
    localStorage.setItem('api_key', newKey);

    API_URL = newUrl;
    API_KEY = newKey;

    settingsWindow.alert('✅ Settings saved!');
    settingsWindow.close();
  };

  // Test API connection
  settingsWindow.document.getElementById('test-connection').onclick = async () => {
    const url = settingsWindow.document.getElementById('api-url-settings').value;

    try {
      const response = await fetch(`${url}/api/stats`);

      if (response.ok) {
        const data = await response.json();
        settingsWindow.alert(`✅ Connection successful!\nTotal scans: ${data.total_scans || 0}`);
      } else {
        settingsWindow.alert('❌ Connection failed');
      }

    } catch (error) {
      settingsWindow.alert(`❌ Error: ${error.message}`);
    }
  };
}

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  const currentUrl = await getCurrentTabUrl();

  // Auto-check current URL
  if (currentUrl && currentUrl.startsWith('http')) {
    checkUrl(currentUrl);
  }

  // Check button
  const checkBtn = document.getElementById('check-btn');
  if (checkBtn) {
    checkBtn.addEventListener('click', () => {
      const urlInput = document.getElementById('url-input');
      const url = urlInput ? urlInput.value.trim() : '';

      if (!url) {
        alert('Please enter a URL to check');
        return;
      }

      checkUrl(url);
    });
  }

  // Settings button
  const settingsLink = document.getElementById('settings-link');
  if (settingsLink) {
    settingsLink.addEventListener('click', (e) => {
      e.preventDefault();
      openSettings();
    });
  }
});

console.log('🛡️ Popup.js loaded - API URL:', API_URL);