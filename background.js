/**
 * SafeURL Background Service Worker (Manifest V3)
 * Monitors active tabs and updates extension badge status in real-time.
 */

// Import feature extractor scripts inside service worker context
importScripts('feature_extractor.js', 'xai_engine.js');

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    analyzeAndSetBadge(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url && tab.url.startsWith('http')) {
      analyzeAndSetBadge(activeInfo.tabId, tab.url);
    }
  } catch (err) {
    console.log("Tab activate listener error:", err);
  }
});

async function analyzeAndSetBadge(tabId, urlString) {
  try {
    const features = extractURLFeatures(urlString);
    
    // Quick risk computation for badge status
    const [
      urlLength, dotCount, hyphenCount, atSymbol, isHttps,
      isIpAddress, subdomainCount, suspiciousKeywords, digitCount, urlEntropy
    ] = features;

    let risk = 0.05;
    if (isIpAddress === 1.0) risk += 0.55;
    if (isHttps === 0.0) risk += 0.25;
    if (atSymbol === 1.0) risk += 0.40;
    if (subdomainCount >= 2) risk += 0.25;
    if (suspiciousKeywords >= 1) risk += suspiciousKeywords * 0.20;

    if (risk >= 0.70) {
      await chrome.action.setBadgeText({ tabId, text: 'ALERT' });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#EF4444' });
    } else if (risk >= 0.35) {
      await chrome.action.setBadgeText({ tabId, text: 'WARN' });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#F59E0B' });
    } else {
      await chrome.action.setBadgeText({ tabId, text: 'SAFE' });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#10B981' });
    }
  } catch (e) {
    console.error("Badge update error:", e);
  }
}
