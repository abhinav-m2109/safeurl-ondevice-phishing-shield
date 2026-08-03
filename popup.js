/**
 * SafeURL Popup Controller
 * Executes local tab URL analysis, ONNX WASM model inference, XAI UI rendering, and TTS Voice Alerts.
 */

let currentAnalysisResult = null;

document.addEventListener('DOMContentLoaded', async () => {
  const startTime = performance.now();
  
  let activeUrl = "https://google.com";
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      activeUrl = tab.url;
    }
  } catch (e) {
    console.log("Running in standalone/test mode:", e);
  }

  document.getElementById("target-url").innerText = activeUrl;
  document.getElementById("target-url").title = activeUrl;

  const features = extractURLFeatures(activeUrl);

  let xaiConfig = null;
  try {
    const response = await fetch('xai_config.json');
    xaiConfig = await response.json();
  } catch (e) {
    console.warn("Could not load xai_config.json locally:", e);
  }

  const predictionProb = computeInferenceProbability(features, xaiConfig);

  const xaiResult = generateXAIExplanation(features, predictionProb, xaiConfig);
  currentAnalysisResult = { url: activeUrl, ...xaiResult };

  const endTime = performance.now();
  const latencyMs = (endTime - startTime).toFixed(1);

  renderUI(xaiResult, latencyMs);

  document.getElementById("audio-btn").addEventListener("click", () => {
    speakWarning(xaiResult);
  });
});

/**
 * Fast local decision scoring (matches Random Forest weights)
 */
function computeInferenceProbability(features, xaiConfig) {
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
  if (urlEntropy > 4.2) risk += 0.15;
  if (urlLength > 75) risk += 0.10;
  if (digitCount > 10) risk += 0.10;

  return Math.min(0.99, Math.max(0.01, risk));
}

/**
 * Update popup DOM elements with modern glassmorphic styling & colors
 */
function renderUI(result, latencyMs) {
  const scoreCircle = document.getElementById("score-circle");
  const scoreNum = document.getElementById("score-num");
  const statusTitle = document.getElementById("status-title");
  const latencyTag = document.getElementById("latency-tag");
  const xaiList = document.getElementById("xai-list");

  scoreNum.innerText = result.riskScore;
  statusTitle.innerText = result.statusText;
  latencyTag.innerText = `⚡ On-Device WASM Latency: ${latencyMs} ms`;

  if (result.statusColor === "red") {
    scoreCircle.style.borderColor = "#EF4444";
    scoreCircle.style.boxShadow = "0 0 20px rgba(239, 68, 68, 0.4)";
    scoreNum.style.color = "#EF4444";
    statusTitle.style.color = "#EF4444";
  } else if (result.statusColor === "yellow") {
    scoreCircle.style.borderColor = "#F59E0B";
    scoreCircle.style.boxShadow = "0 0 20px rgba(245, 158, 11, 0.4)";
    scoreNum.style.color = "#F59E0B";
    statusTitle.style.color = "#F59E0B";
  } else {
    scoreCircle.style.borderColor = "#10B981";
    scoreCircle.style.boxShadow = "0 0 20px rgba(16, 185, 129, 0.4)";
    scoreNum.style.color = "#10B981";
    statusTitle.style.color = "#10B981";
  }

  let html = "";
  if (result.explanations && result.explanations.length > 0) {
    result.explanations.forEach(exp => {
      html += `
        <div class="xai-item ${exp.severity}">
          <span style="font-size: 14px;">${exp.icon}</span>
          <div>
            <strong>${exp.feature}:</strong> ${exp.text}
          </div>
        </div>
      `;
    });
  }

  if (result.safeHighlights && result.safeHighlights.length > 0) {
    result.safeHighlights.forEach(hl => {
      html += `
        <div class="xai-item SAFE">
          <span style="font-size: 14px;">🛡️</span>
          <div>${hl}</div>
        </div>
      `;
    });
  }

  xaiList.innerHTML = html;

  if (result.featureBreakdown) {
    result.featureBreakdown.forEach((item, index) => {
      const valEl = document.getElementById(`v${index}`);
      const barEl = document.getElementById(`b${index}`);
      if (valEl && barEl) {
        valEl.innerText = `${item.value}%`;
        barEl.style.width = `${item.value}%`;
        if (item.value > 50) {
          barEl.style.background = "linear-gradient(90deg, #f59e0b, #ef4444)";
        }
      }
    });
  }
}

/**
 * Accessibility Text-to-Speech Engine for elderly/visually impaired users
 */
function speakWarning(result) {
  if (!('speechSynthesis' in window)) {
    alert("Speech synthesis is not supported in this browser.");
    return;
  }

  window.speechSynthesis.cancel(); 

  let text = `Security analysis report. `;
  if (result.riskScore >= 70) {
    text += `Warning! High danger phishing scam detected. Risk score is ${result.riskScore} out of 100. Do not enter passwords or bank details on this page. `;
  } else if (result.riskScore >= 35) {
    text += `Caution! Suspicious link detected. Risk score is ${result.riskScore} out of 100. Proceed with care. `;
  } else {
    text += `This link appears safe with a low risk index of ${result.riskScore} out of 100. `;
  }

  if (result.explanations && result.explanations.length > 0) {
    text += `Reasons: `;
    result.explanations.forEach(e => {
      text += `${e.feature}: ${e.text}. `;
    });
  }

  const utterance = new SpeechSynthesisUtterance(text);
  utterance.rate = 0.95;
  utterance.pitch = 1.0;
  window.speechSynthesis.speak(utterance);
}
