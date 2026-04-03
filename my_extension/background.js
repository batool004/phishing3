// background.js - Add automatic blocking feature

let API_URL = 'http://localhost:5002';
let USE_SMART_API = true;

// Blocked domains list (stored locally)
let blockedDomains = new Set();

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

// ============= Block access to dangerous pages =============
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    const url = details.url;

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

    // 2. Check URL via API
    try {
        const endpoint = USE_SMART_API ? '/smart-check' : '/check';

        const response = await fetch(`${API_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();
        const isPhishing = data.is_phishing || data.prediction === 'phishing';
        const score = data.score || data.confidence || 0;

        // If URL is dangerous (score > 70)
        if (isPhishing || score > 70) {
            console.log(`🚫 BLOCKED: ${url} (phishing detected, score: ${score}%)`);

            // Automatically add to blocked list
            addToBlockedList(domain);

            // Block access and redirect to warning page
            redirectToWarning(
                details.tabId,
                url,
                `Phishing detected! Threat score: ${score}%`
            );

            // Show notification
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon128.png',
                title: '🚫 Access Blocked!',
                message: `Phishing URL blocked: ${domain}\nScore: ${score}%`,
                priority: 2
            });

            return { cancel: true };
        }

        // Safe URL - clear badge
        chrome.action.setBadgeText({ text: '', tabId: details.tabId });

    } catch (error) {
        console.error('Error checking URL:', error);
    }

}, { url: [{ schemes: ['http', 'https'] }] });

// ============= Redirect to warning page =============
function redirectToWarning(tabId, url, reason) {
    const warningUrl = chrome.runtime.getURL('warning.html') +
        `?url=${encodeURIComponent(url)}&reason=${encodeURIComponent(reason)}`;

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
});

console.log('🛡️ PhishGuard background.js loaded - Real-time blocking active');