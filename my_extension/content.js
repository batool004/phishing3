// Settings
let API_URL = localStorage.getItem('api_url') || 'http://localhost:5000';
let API_KEY = localStorage.getItem('api_key') || 'test_key_123';

// Check current URL
async function checkCurrentUrl() {
  const currentUrl = window.location.href;

  try {
    const response = await fetch(`${API_URL}/api/v1/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY
      },
      body: JSON.stringify({ url: currentUrl })
    });

    const data = await response.json();

    if (data.is_phishing && data.probability > 0.7) {
      // Show warning overlay on the page
      showWarningOverlay(data);

      // Send notification to background script
      chrome.runtime.sendMessage({
        action: 'show_warning',
        probability: data.probability,
        url: currentUrl
      });
    }
  } catch (error) {
    console.error('Error checking URL:', error);
  }
}

// Show warning overlay on the page
function showWarningOverlay(data) {
  const warningDiv = document.createElement('div');
  warningDiv.id = 'phishing-warning';

  warningDiv.innerHTML = `
    <div style="
      position: fixed;
      top: 20px;
      right: 20px;
      left: 20px;
      background: linear-gradient(135deg, #eb3349, #f45c43);
      color: white;
      padding: 20px;
      border-radius: 15px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.3);
      z-index: 999999;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      text-align: center;
      animation: slideDown 0.5s ease;
    ">
      <strong style="font-size: 1.2rem;">🚨 Security Warning!</strong><br>
      This website may be a phishing attempt!<br>
      Probability: ${(data.probability * 100).toFixed(1)}%<br>
      <small>⚠️ Do NOT enter any personal information on this site</small>
      <button id="close-warning" style="
        margin-top: 10px;
        padding: 5px 15px;
        background: white;
        color: #dc3545;
        border: none;
        border-radius: 5px;
        cursor: pointer;
        font-weight: bold;
      ">Close</button>
    </div>

    <style>
      @keyframes slideDown {
        from {
          transform: translateY(-100%);
          opacity: 0;
        }
        to {
          transform: translateY(0);
          opacity: 1;
        }
      }
    </style>
  `;

  document.body.appendChild(warningDiv);

  document.getElementById('close-warning').onclick = () => {
    warningDiv.remove();
  };
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'check_url') {
    checkCurrentUrl();
  }
});

// Run check when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', checkCurrentUrl);
} else {
  checkCurrentUrl();
}