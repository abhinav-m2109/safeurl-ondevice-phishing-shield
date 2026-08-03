/**
 * SafeURL Local Explainable AI (XAI) Engine
 * Translates model weights and feature vectors into human-readable explanations.
 */

function generateXAIExplanation(features, predictionProb, xaiConfig) {
  // Features vector mapping:
  // 0: url_length, 1: dot_count, 2: hyphen_count, 3: at_symbol, 4: is_https,
  // 5: is_ip_address, 6: subdomain_count, 7: suspicious_keywords, 8: digit_count, 9: url_entropy

  const [
    urlLength, dotCount, hyphenCount, atSymbol, isHttps,
    isIpAddress, subdomainCount, suspiciousKeywords, digitCount, urlEntropy
  ] = features;

  const rules = xaiConfig ? xaiConfig.rules : null;
  const featureImportances = xaiConfig ? xaiConfig.feature_importances : [];

  const explanations = [];
  const safeHighlights = [];
  let riskScore = Math.round(predictionProb * 100);

  // 1. IP Address Rule
  if (isIpAddress === 1.0) {
    explanations.push({
      feature: "Raw IP Hostname",
      severity: "DANGER",
      icon: "🚨",
      text: "Uses a raw numerical IP address instead of a domain name (classic scam trick)."
    });
    riskScore = Math.max(riskScore, 85);
  }

  // 2. HTTPS Connection Rule
  if (isHttps === 0.0) {
    explanations.push({
      feature: "Unencrypted Connection",
      severity: "WARNING",
      icon: "🔓",
      text: "Connection is unencrypted (HTTP). Anyone on your network can read your passwords."
    });
    riskScore = Math.max(riskScore, 45);
  } else {
    safeHighlights.push("🔐 Connection uses secure HTTPS encryption.");
  }

  // 3. Suspicious Keywords Rule
  if (suspiciousKeywords >= 1.0) {
    explanations.push({
      feature: "Urgent Phishing Keywords",
      severity: "WARNING",
      icon: "⚠️",
      text: `Link contains ${suspiciousKeywords} urgency keywords (e.g. 'login', 'verify', 'bank', 'secure').`
    });
    riskScore += Math.min(25, suspiciousKeywords * 10);
  }

  // 4. Subdomain Hierarchy Rule
  if (subdomainCount >= 2.0) {
    explanations.push({
      feature: "Excessive Subdomains",
      severity: "DANGER",
      icon: "🌐",
      text: `Link uses ${subdomainCount} subdomains to impersonate legitimate brand names.`
    });
    riskScore += Math.min(20, subdomainCount * 8);
  }

  // 5. Entropy Rule (Randomness)
  if (urlEntropy > 4.2) {
    explanations.push({
      feature: "Character Randomness",
      severity: "WARNING",
      icon: "🎲",
      text: `Unusually random character structure (Entropy: ${urlEntropy.toFixed(2)}), typical of auto-generated links.`
    });
  }

  // 6. At Symbol Rule
  if (atSymbol === 1.0) {
    explanations.push({
      feature: "@ Redirect Trick",
      severity: "DANGER",
      icon: "🎯",
      text: "Contains '@' character designed to trick browsers into secretly redirecting you."
    });
    riskScore = Math.max(riskScore, 75);
  }

  // Cap risk score between 0 and 100
  riskScore = Math.min(100, Math.max(0, Math.round(riskScore)));

  // Categorize Risk Level
  let statusText = "SAFE LINK";
  let statusColor = "green";
  let badgeColor = "#10B981";

  if (riskScore >= 70) {
    statusText = "DANGER: PHISHING SCAM DETECTED";
    statusColor = "red";
    badgeColor = "#EF4444";
  } else if (riskScore >= 35) {
    statusText = "SUSPICIOUS LINK - PROCEED WITH CAUTION";
    statusColor = "yellow";
    badgeColor = "#F59E0B";
  }

  if (explanations.length === 0) {
    safeHighlights.push("✅ Domain structure matches verified safe patterns.");
    safeHighlights.push("✅ Standard length, subdomains, and character distribution.");
  }

  // Generate Feature Importance Chart Data
  const featureBreakdown = [
    { name: "IP Hostname", value: isIpAddress === 1.0 ? 95 : 5 },
    { name: "Encryption (HTTP/HTTPS)", value: isHttps === 0.0 ? 80 : 10 },
    { name: "Keywords Risk", value: Math.min(100, suspiciousKeywords * 35) },
    { name: "Subdomain Layering", value: Math.min(100, subdomainCount * 30) },
    { name: "Entropy Randomness", value: Math.min(100, (urlEntropy / 5.0) * 100) }
  ];

  return {
    riskScore,
    statusText,
    statusColor,
    badgeColor,
    explanations,
    safeHighlights,
    featureBreakdown
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { generateXAIExplanation };
}
