// background.js - Automatic blocking + Global Threat Network

let API_URL = 'http://localhost:5002';
let USE_SMART_API = true;

// Generate anonymous user ID for reputation system
let userId = null;

// Initialize user ID
async function getUserId() {
    if (userId) return userId;
    
    return new Promise((resolve) => {
        chrome.storage.local.get(['userId'], (result) => {
            if (result.userId) {
                userId = result.userId;
            } else {
                // Generate anonymous ID (hash of random + timestamp)
                const random = Math.random().toString(36).substring(2, 15);
                const timestamp = Date.now().toString();
                const hashBuffer = crypto.subtle.digestSync('SHA-256', new TextEncoder().encode(random + timestamp));
                userId = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 32);
                chrome.storage.local.set({ userId: userId });
            }
            resolve(userId);
        });
    });
}

// Blocked domains list (stored locally)
let blockedDomains = new Set();

// Cache for recent checks (avoid duplicate API calls)
let checkCache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// Load blocked domains from storage
chrome.storage.local.get(['blockedDomains'], (result) => {
    if (result.blockedDomains) {
        blockedDomains = new Set(result.blockedDomains);
    }
});

// Save blocked domains list
function saveBlockedDomains() {
    chrome.storage.local.set({ blockedDomains: Array.from(blockedDomains) });
}

// Add domain to blocked list
function addToBlockedList(domain) {
    blockedDomains.add(domain);
    saveBlockedDomains();
    console.log(`🚫 Added to blocked list: ${domain}`);
}

// ============= Check URL against global threat network =============
async function checkGlobalThreat(url) {
    try {
        const response = await fetch(`${API_URL}/api/v2/check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });
        return await response.json();
    } catch (error) {
        console.error('Global threat check error:', error);
        return null;
    }
}

// ============= Report phishing URL to global network =============
async function reportToGlobalNetwork(url, mlScore) {
    try {
        const uid = await getUserId();
        const response = await fetch(`${API_URL}/api/v2/report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: url,
                user_id: uid,
                ml_score: mlScore
            })
        });
        return await response.json();
    } catch (error) {
        console.error('Report error:', error);
        return null;
    }
}

// ============= Show notification asking user to report =============
function askUserToReport(url, mlScore) {
    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '🌍 Help Protect Others',
        message: `This URL was detected as phishing (${mlScore}%). Report to protect the community?`,
        priority: 2,
        buttons: [
            { title: '✅ Report' },
            { title: '❌ Ignore' }
        ]
    }, (notificationId) => {
        // Store URL and score for this notification
        chrome.storage.local.set({ 
            [`pending_report_${notificationId}`]: { url: url, score: mlScore }
        });
    });
}

// Handle notification button clicks
chrome.notifications.onButtonClicked.addListener(async (notificationId, buttonIndex) => {
    if (buttonIndex === 0) { // Report button clicked
        const pending = await new Promise((resolve) => {
            chrome.storage.local.get([`pending_report_${notificationId}`], (result) => {
                resolve(result[`pending_report_${notificationId}`]);
            });
        });
        
        if (pending) {
            const result = await reportToGlobalNetwork(pending.url, pending.score);
            if (result && result.status === 'confirmed') {
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'icons/icon128.png',
                    title: '✅ Threat Confirmed!',
                    message: 'Thank you! This URL is now blocked for all users.',
                    priority: 1
                });
            } else if (result) {
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'icons/icon128.png',
                    title: '📢 Report Received',
                    message: result.message || 'Thank you for helping the community!',
                    priority: 1
                });
            }
            // Clean up
            chrome.storage.local.remove(`pending_report_${notificationId}`);
        }
    }
    chrome.notifications.clear(notificationId);
});

// ============= Block access to dangerous pages =============
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    const url = details.url;
    const tabId = details.tabId;

    // Ignore internal browser URLs
    if (
        url.startsWith('chrome://') ||
        url.startsWith('about:') ||
        url.startsWith('edge://') ||
        url.startsWith('moz-extension://')
    ) {
        return;
    }

    // Extract domain
    let domain = '';
    try {
        domain = new URL(url).hostname;
    } catch (e) {
        return;
    }

    // 1. Check blocked list first
    if (blockedDomains.has(domain)) {
        console.log(`🚫 BLOCKED: ${url} (in blocked list)`);
        redirectToWarning(tabId, url, 'This domain is in your blocked list');
        return { cancel: true };
    }

    // 2. Check cache first
    const cached = checkCache.get(url);
    if (cached && (Date.now() - cached.timestamp) < CACHE_DURATION) {
        if (cached.isPhishing) {
            redirectToWarning(tabId, url, `Phishing detected! Score: ${cached.score}%`);
            return { cancel: true };
        }
        return;
    }

    // 3. Check via Global Threat Network first
    try {
        const globalCheck = await checkGlobalThreat(url);
        
        if (globalCheck && globalCheck.is_threat) {
            console.log(`🚫 BLOCKED: ${url} (global threat, score: ${globalCheck.threat_score}%)`);
            
            // Add to blocked list
            addToBlockedList(domain);
            
            // Cache result
            checkCache.set(url, {
                isPhishing: true,
                score: globalCheck.threat_score,
                timestamp: Date.now()
            });
            
            // Block and redirect
            redirectToWarning(tabId, url, `🌍 Global Threat detected!\nReported by ${globalCheck.reports_count} users\nScore: ${globalCheck.threat_score}%`);
            
            // Show notification
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon128.png',
                title: '🌍 Global Threat Blocked!',
                message: `This URL was reported by ${globalCheck.reports_count} users as phishing.`,
                priority: 2
            });
            
            return { cancel: true };
        }
        
        // 4. If not a global threat, check via ML model
        const endpoint = USE_SMART_API ? '/smart-check' : '/check';
        const response = await fetch(`${API_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();
        const isPhishing = data.is_phishing || data.prediction === 'phishing';
        const score = data.score || data.confidence || 0;

        // Cache result
        checkCache.set(url, {
            isPhishing: isPhishing,
            score: score,
            timestamp: Date.now()
        });

        // If URL is dangerous (score > 70)
        if (isPhishing || score > 40) {
            console.log(`🚫 BLOCKED: ${url} (phishing detected, score: ${score}%)`);

            // Automatically add to blocked list
            addToBlockedList(domain);

            // Prepare threat data for warning page
            const threatData = {
                score: score,
                source: data.source || 'ml_model',
                risk_factors: data.risk_factors || []
            };

            // Block access and redirect to warning page with threat data
            redirectToWarning(
                details.tabId,
                url,
                `Phishing detected! Threat score: ${score}%`,
                threatData
            );

            // Show notification
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon128.png',
                title: '🚫 Access Blocked!',
                message: `Phishing URL blocked: ${domain}\nScore: ${score}%`,
                priority: 2
            });

            // Ask user to report to global network (for score > 85)
            if (score > 85) {
                askUserToReport(url, score);
            }

            return { cancel: true };
        }

        // Safe URL - clear badge
        chrome.action.setBadgeText({ text: '', tabId: tabId });

    } catch (error) {
        console.error('Error checking URL:', error);
        // If API is down, don't block (false negative better than false positive)
    }
}, { url: [{ schemes: ['http', 'https'] }] });

// ============= Redirect to warning page =============
function redirectToWarning(tabId, url, reason, threatData = null) {
    // Build URL with all parameters
    let warningUrl = chrome.runtime.getURL('warning.html') +
        `?url=${encodeURIComponent(url)}&reason=${encodeURIComponent(reason)}`;
    
    // Add threat data if available
    if (threatData) {
        warningUrl += `&score=${encodeURIComponent(threatData.score || 0)}`;
        warningUrl += `&source=${encodeURIComponent(threatData.source || 'ml_model')}`;
        if (threatData.risk_factors) {
            warningUrl += `&risks=${encodeURIComponent(JSON.stringify(threatData.risk_factors.slice(0, 3)))}`;
        }
    }
    
    chrome.tabs.update(tabId, { url: warningUrl });
}

// ============= Remove domain from blocked list =============
function removeFromBlockedList(domain) {
    blockedDomains.delete(domain);
    saveBlockedDomains();
    console.log(`✅ Removed from blocked list: ${domain}`);
}

// ============= Get blocked domains list =============
function getBlockedList() {
    return Array.from(blockedDomains);
}

// ============= Clear cache periodically =============
setInterval(() => {
    const now = Date.now();
    for (const [url, data] of checkCache.entries()) {
        if (now - data.timestamp > CACHE_DURATION) {
            checkCache.delete(url);
        }
    }
}, 60000); // Clean cache every minute

// ============= Listen for messages from popup =============
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

    if (request.action === 'getBlockedList') {
        sendResponse({ domains: getBlockedList() });
        return true;
    }

    if (request.action === 'removeBlockedDomain') {
        removeFromBlockedList(request.domain);
        sendResponse({ success: true });
        return true;
    }

    if (request.action === 'addBlockedDomain') {
        addToBlockedList(request.domain);
        sendResponse({ success: true });
        return true;
    }
    
    if (request.action === 'getUserId') {
        getUserId().then(id => sendResponse({ userId: id }));
        return true;
    }
});

console.log('🛡️ CyberGuard background.js loaded - Global Threat Network Active');