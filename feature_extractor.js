/**
 * SafeURL On-Device Feature Extraction Engine
 * Extracts 10 lexical parameters directly from URL strings without network requests.
 */

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verif', 'bank', 'secure', 'account',
  'update', 'confirm', 'paypal', 'apple', 'google', 'microsoft',
  'netflix', 'amazon', 'support', 'service', 'billing', 'security', 'claim'
];

function calculateEntropy(text) {
  if (!text) return 0.0;
  const len = text.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = text[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0.0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(4));
}

function extractURLFeatures(urlString) {
  const urlLower = urlString.toLowerCase();
  
  // Extract hostname safely without throwing
  let hostname = urlLower;
  try {
    if (urlLower.includes("://")) {
      hostname = urlLower.split("://")[1].split("/")[0];
    } else {
      hostname = urlLower.split("/")[0];
    }
  } catch (e) {
    hostname = urlLower;
  }
  const cleanHost = hostname.split(':')[0];

  // 1. Length of URL
  const urlLength = parseFloat(urlString.length);

  // 2. Count of dots
  const dotCount = parseFloat((urlString.match(/\./g) || []).length);

  // 3. Count of hyphens
  const hyphenCount = parseFloat((urlString.match(/-/g) || []).length);

  // 4. Presence of '@'
  const atSymbol = urlString.includes('@') ? 1.0 : 0.0;

  // 5. HTTPS flag
  const isHttps = urlLower.startsWith("https://") ? 1.0 : 0.0;

  // 6. IP in hostname
  const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  const isIpAddress = ipRegex.test(cleanHost) ? 1.0 : 0.0;

  // 7. Subdomain count
  let subdomainCount = 0.0;
  if (!isIpAddress) {
    const parts = cleanHost.split('.');
    subdomainCount = parseFloat(Math.max(0, parts.length - 2));
  }

  // 8. Suspicious keyword count
  let suspiciousKeywords = 0.0;
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (urlLower.includes(kw)) {
      suspiciousKeywords += 1.0;
    }
  }

  // 9. Digit count
  const digitCount = parseFloat((urlString.match(/\d/g) || []).length);

  // 10. Shannon Entropy
  const urlEntropy = calculateEntropy(urlString);

  return [
    urlLength,
    dotCount,
    hyphenCount,
    atSymbol,
    isHttps,
    isIpAddress,
    subdomainCount,
    suspiciousKeywords,
    digitCount,
    urlEntropy
  ];
}

// Export for ES Module or browser script window
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { extractURLFeatures, calculateEntropy };
}
