# Chrome Web Store Metadata & Publishing Disclosure

## Extension Metadata
- **Name**: SafeURL - On-Device AI Phishing Shield
- **Version**: 1.0.0
- **Category**: Developer Tools / Security & Privacy
- **Language**: English

## Short Description (Max 132 Characters)
Privacy-first, on-device AI phishing detector with real-time Explainable AI (XAI) risk metrics and plain-English alerts.

## Detailed Store Description
SafeURL Shield protects everyday internet users and non-technical demographics from phishing scams, credential theft, and malicious link impersonation through 100% on-device Machine Learning and Explainable AI (XAI).

### Key Features:
- 🔒 **100% On-Device Privacy**: No browsing history or URLs are transmitted to any cloud server or third-party API. All feature extraction and model inference run locally in WebAssembly.
- ⚡ **Zero-Latency Defense (< 10ms)**: Instant threat analysis without waiting for cloud API responses.
- 💡 **Plain-English XAI Explanations**: Converts complex model weights into easy-to-understand warning cards (e.g. "Uses raw IP address instead of domain name", "Unencrypted HTTP connection").
- 🔊 **Voice Accessibility Warnings**: Integrated text-to-speech engine alerts elderly or visually impaired users to high-risk threats.
- 🚦 **Real-Time Badge Indicators**: Dynamic extension toolbar badge color updates automatically as you navigate between web pages.

## Permissions Justification

| Permission | Justification |
| :--- | :--- |
| `activeTab` | Required to read the URL of the currently focused browser tab to perform local feature extraction when the user opens the extension popup. |
| `tabs` | Required to monitor tab navigation events (`chrome.tabs.onUpdated`) in order to update the extension action icon badge (SAFE / WARN / DANGER) in real time. |
| `storage` | Required to cache user accessibility preferences (such as audio speech settings) locally on device. |

## Privacy Disclosure
- SafeURL Shield does **NOT** collect, store, or transmit any user browsing data, URLs, IP addresses, or personal information.
- All lexical analysis and machine learning calculations execute strictly in client-side memory using WebAssembly.
